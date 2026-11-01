package web

import (
	"crypto/ed25519"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"sitewatch/internal/probe"
	"sitewatch/internal/report"
	"sitewatch/internal/sign"
	"sitewatch/internal/status"
)

func setupAgents(t *testing.T) (*Server, ed25519.PublicKey) {
	t.Helper()
	srv, _, _ := setup(t)
	priv, err := sign.LoadOrCreateKey(filepath.Join(t.TempDir(), "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	srv.SignKey = priv
	return srv, priv.Public().(ed25519.PublicKey)
}

func do(srv *Server, method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestAgentFlow(t *testing.T) {
	srv, pub := setupAgents(t)
	tok := ""
	// Anlegen über die Oberfläche: Token erscheint einmalig auf der Seite.
	w := do(srv, "POST", "/agents", url.Values{"id": {"server1"}}, nil)
	if w.Code != 200 || !strings.Contains(html.UnescapeString(w.Body.String()), sign.EncodePublicKey(pub)) {
		t.Fatalf("Anlegen: %d", w.Code)
	}
	a, _ := srv.Agents.Get("server1")
	for _, f := range strings.Fields(strings.ReplaceAll(w.Body.String(), `"`, " ")) {
		if len(f) == 64 && a.TokenHash != "" {
			tok = f
		}
	}
	if tok == "" {
		t.Fatal("Token nicht auf der Seite")
	}
	if w := do(srv, "GET", "/agents/server1", nil, nil); !strings.Contains(w.Body.String(), "Konfiguration, die der Agent erhält") {
		t.Error("Vorschau fehlt")
	}
	// Konfiguration speichern.
	form := url.Values{"count": {"2"}, "interval": {"10m"},
		"s0_id": {"kunde"}, "s0_name": {"Kunde"}, "s0_kind": {"contao"}, "s0_path": {"/var/www/kunde"}, "s0_no_nginx": {"1"}, "s0_ignore": {"contao/*:6.*\n"},
		"s1_id": {""}}
	if w := do(srv, "POST", "/agents/server1", form, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("Speichern: %d %s", w.Code, w.Body.String())
	}
	if w := do(srv, "POST", "/agents/server1", url.Values{"count": {"1"}, "s0_id": {"x"}, "s0_kind": {"contao"}}, nil); w.Code != 422 || !strings.Contains(w.Body.String(), "path fehlt") {
		t.Errorf("ungültig: %d", w.Code)
	}
	// Config-API: signiert, nur mit gültigem Token.
	if w := do(srv, "GET", "/api/v1/agent/config", nil, nil); w.Code != 401 {
		t.Errorf("ohne Token: %d", w.Code)
	}
	w = do(srv, "GET", "/api/v1/agent/config", nil, map[string]string{"Authorization": "Bearer " + tok})
	var env sign.Envelope
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &env) != nil {
		t.Fatalf("Config: %d", w.Code)
	}
	p, err := sign.Verify(pub, env, "server1", srv.Now(), srv.Now())
	if err != nil || !strings.Contains(string(p.Config), `"kunde"`) || !strings.Contains(string(p.Config), `contao/*:6.*`) {
		t.Fatalf("Verify: %v %s", err, p.Config)
	}
	if w := do(srv, "GET", "/agents/server1", nil, nil); !strings.Contains(w.Body.String(), "&#34;path&#34;: &#34;/var/www/kunde&#34;") {
		t.Error("Vorschau zeigt die gespeicherte Konfiguration nicht")
	}
	// Melden: nur für Sites der Konfiguration.
	rep := func(id string) report.Report {
		return report.Report{Schema: 1, Agent: report.Agent{Type: "go-host"}, CollectedAt: srv.Now(), Site: report.Site{ID: id, Kind: "contao"}}
	}
	if w := post(srv, tok, rep("kunde")); w.Code != http.StatusNoContent {
		t.Errorf("eigene Site: %d", w.Code)
	}
	if w := post(srv, tok, rep("fremd")); w.Code != http.StatusUnauthorized {
		t.Errorf("fremde Site: %d", w.Code)
	}
	// Übersicht kennt die Site auch ohne Meldung.
	if w := do(srv, "GET", "/", nil, nil); !strings.Contains(w.Body.String(), "kunde") {
		t.Error("Site fehlt in der Übersicht")
	}
	// Token erneuern: das alte ist sofort ungültig.
	rw := do(srv, "POST", "/agents/server1/rotate", url.Values{"docker_php": {"1"}}, nil)
	if b := rw.Body.String(); !strings.Contains(b, `"php": "/usr/share/sitewatch-agent/docker/php-in-docker"`) || strings.Contains(b, "composer-in-docker\"") {
		t.Errorf("Block mit Wrapper nur für php erwartet: %s", b)
	}
	if w := post(srv, tok, rep("kunde")); w.Code != http.StatusUnauthorized {
		t.Errorf("altes Token: %d", w.Code)
	}
	// Löschen braucht die Bestätigung.
	if w := do(srv, "POST", "/agents/server1/delete", url.Values{}, nil); w.Code != 404 {
		t.Errorf("ohne Bestätigung: %d", w.Code)
	}
	if w := do(srv, "POST", "/agents/server1/delete", url.Values{"confirm": {"1"}}, nil); w.Code != http.StatusSeeOther {
		t.Errorf("löschen: %d", w.Code)
	}
}

func TestSameOriginGuardWithLogin(t *testing.T) {
	srv, _ := setupAgents(t)
	srv.Protect = func(next http.Handler) http.Handler { return next } // Login simuliert
	if w := do(srv, "POST", "/agents", url.Values{"id": {"x"}}, map[string]string{"Origin": "https://evil.example"}); w.Code != http.StatusForbidden {
		t.Errorf("mit Login: %d, erwartet 403", w.Code)
	}
}

func TestSaveRejectsBrokenForm(t *testing.T) {
	srv, _ := setupAgents(t)
	do(srv, "POST", "/agents", url.Values{"id": {"server1"}}, nil)
	ok := url.Values{"count": {"1"}, "s0_id": {"a"}, "s0_kind": {"php"}, "s0_path": {"/var/www/a"}}
	if w := do(srv, "POST", "/agents/server1", ok, nil); w.Code != http.StatusSeeOther {
		t.Fatal(w.Code)
	}
	if w := do(srv, "POST", "/agents/server1", url.Values{"interval": {"5m"}}, nil); w.Code != http.StatusBadRequest {
		t.Errorf("ohne count: %d", w.Code)
	}
	if a, _ := srv.Agents.Get("server1"); len(a.Config.Sites) != 1 {
		t.Error("Konfiguration darf nicht geleert werden")
	}
	if w := do(srv, "POST", "/agents/server1", url.Values{"count": {"1"}, "s0_id": {"b"}, "s0_kind": {"php"}, "s0_path": {"/x"}, "s0_url": {"ftp://x"}}, nil); w.Code != 422 {
		t.Errorf("url-Schema: %d", w.Code)
	}
}

func TestSameOriginGuard(t *testing.T) {
	srv, _ := setupAgents(t)
	for name, h := range map[string]map[string]string{
		"anderer Origin":     {"Origin": "https://evil.example"},
		"Sec-Fetch-Site":     {"Sec-Fetch-Site": "cross-site"},
		"gleiche Seite aber": nil,
	} {
		w := do(srv, "POST", "/agents", url.Values{"id": {"x" + strings.ReplaceAll(name, " ", "")[:3]}}, h)
		if h != nil && w.Code != http.StatusForbidden {
			t.Errorf("%s: %d, erwartet 403", name, w.Code)
		}
		if h == nil && w.Code != 200 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := do(srv, "POST", "/agents", url.Values{"id": {"ok"}}, map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"}); w.Code != 200 {
		t.Errorf("gleicher Origin: %d", w.Code)
	}
}

func TestDockerTools(t *testing.T) {
	r := httptest.NewRequest("POST", "/agents", strings.NewReader("docker_php=1&docker_nginx=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got := dockerTools(r)
	if len(got) != 2 || got[0]["Name"] != "php" || got[1]["Path"] != "/usr/share/sitewatch-agent/docker/nginx-in-docker" {
		t.Fatalf("dockerTools = %v", got)
	}
}

func TestBundleFlow(t *testing.T) {
	srv, _ := setupAgents(t)
	snippetToken := func(body string) string {
		for _, l := range strings.Split(html.UnescapeString(body), "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "token: '") {
				return strings.TrimSuffix(strings.TrimPrefix(l, "token: '"), "'")
			}
		}
		return ""
	}
	w := do(srv, "POST", "/agents", url.Values{"type": {"contao-bundle"}, "id": {"kunde-x"}, "name": {"Kunde 'X'"}, "site_url": {"https://x.example"}}, nil)
	body := html.UnescapeString(w.Body.String())
	tok := snippetToken(w.Body.String())
	for _, want := range []string{"cgoit_sitewatch:", "    url: 'https://example.com'", "    site_id: 'kunde-x'", "    site_name: 'Kunde ''X'''", "    site_url: 'https://x.example'"} {
		if w.Code != 200 || !strings.Contains(body, want) {
			t.Fatalf("Snippet ohne %q (%d): %s", want, w.Code, body)
		}
	}
	if len(tok) != 64 || strings.Contains(body, "bootstrap.json") {
		t.Fatalf("Token %q oder Server-Block statt Snippet", tok)
	}
	rep := report.Report{Schema: 1, Agent: report.Agent{Type: report.AgentContaoBundle}, CollectedAt: srv.Now(), Site: report.Site{ID: "kunde-x", Kind: "contao"}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Errorf("Report mit Bundle-Token: %d", w.Code)
	}
	rep.Site.ID = "fremd"
	if w := post(srv, tok, rep); w.Code != http.StatusUnauthorized {
		t.Errorf("fremde Site: %d", w.Code)
	}
	rep.Site.ID, rep.Agent.Type = "kunde-x", "go-host"
	if w := post(srv, tok, rep); w.Code != http.StatusUnauthorized {
		t.Errorf("Bundle-Token mit Typ go-host: %d", w.Code)
	}
	rep.Agent.Type = report.AgentContaoBundle
	if w := do(srv, "POST", "/agents/gibt-es-nicht/rotate", url.Values{}, nil); w.Code != http.StatusNotFound {
		t.Errorf("unbekannter Agent: %d", w.Code)
	}
	if b := do(srv, "GET", "/agents", nil, nil).Body.String(); !strings.Contains(b, "Contao-Bundle") {
		t.Error("Typ fehlt in der Liste")
	}
	if b := do(srv, "GET", "/agents/kunde-x", nil, nil).Body.String(); !strings.Contains(b, "TOKEN-DES-AGENTEN") || strings.Contains(b, tok) {
		t.Error("Seite zeigt Platzhalter statt Token erwartet")
	}
	if w := do(srv, "POST", "/agents/kunde-x", url.Values{"name": {"Neu"}, "site_url": {"ftp://x"}}, nil); w.Code != 422 {
		t.Errorf("ungültige URL: %d", w.Code)
	}
	if w := do(srv, "POST", "/agents/kunde-x", url.Values{"name": {"Neu"}}, nil); w.Code != http.StatusSeeOther {
		t.Errorf("Speichern: %d", w.Code)
	}
	w = do(srv, "POST", "/agents/kunde-x/rotate", url.Values{}, nil)
	if neu := snippetToken(w.Body.String()); len(neu) != 64 || neu == tok {
		t.Errorf("neues Token fehlt")
	}
	rep.Site.ID = "kunde-x"
	if w := post(srv, tok, rep); w.Code != http.StatusUnauthorized {
		t.Errorf("altes Token: %d", w.Code)
	}
}

func TestSettingsPage(t *testing.T) {
	srv, _ := setupAgents(t)
	var savedVals map[string]int
	srv.SaveSettings = func(c status.Config, vals map[string]int) error {
		savedVals = vals
		srv.Settings.Set(c)
		return nil
	}
	if b := do(srv, "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `name="tls_warn_days"`) || !strings.Contains(b, "Standard: 14") || !strings.Contains(b, "Einstellungen</a>") {
		t.Fatal("Formular fehlt")
	}
	// Speichern: nur Abweichungen vom Standard werden weitergereicht, der Wert gilt sofort.
	form := url.Values{"tls_warn_days": {"30"}, "error_warn": {"10"}}
	if w := do(srv, "POST", "/settings", form, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("Speichern: %d %s", w.Code, w.Body.String())
	}
	if len(savedVals) != 1 || savedVals["tls_warn_days"] != 30 || srv.cfg().TLSWarn != 30*24*time.Hour {
		t.Errorf("gespeichert: %v / %v", savedVals, srv.cfg().TLSWarn)
	}
	if b := do(srv, "GET", "/settings?saved=1", nil, nil).Body.String(); !strings.Contains(b, `value="30"`) || !strings.Contains(b, "Gespeichert") {
		t.Error("neuer Wert oder Hinweis fehlt")
	}
	// Ungültige Eingaben ändern nichts und zeigen die Eingabe wieder an.
	for name, bad := range map[string]url.Values{
		"keine Zahl": {"tls_warn_days": {"abc"}},
		"null":       {"tls_warn_days": {"0"}},
		"crit>warn":  {"disk_crit_pct": {"50"}},
	} {
		w := do(srv, "POST", "/settings", bad, nil)
		if w.Code != 422 || srv.cfg().TLSWarn != 30*24*time.Hour || srv.cfg().DiskCrit != 5 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// Zurücksetzen: Standardwerte, nil an den Speicher.
	if w := do(srv, "POST", "/settings/reset", url.Values{}, nil); w.Code != http.StatusSeeOther || savedVals != nil || srv.cfg().TLSWarn != 14*24*time.Hour {
		t.Errorf("zurücksetzen: %d %v %v", w.Code, savedVals, srv.cfg().TLSWarn)
	}
}

// Eine Site ohne Meldung hat keine Detailseite und deshalb keinen Link; mit Meldung gibt es ihn.
func TestUnreportedSiteHasNoLink(t *testing.T) {
	srv, tok, now := setup(t)
	if _, err := srv.Agents.CreateBundle("neu-b", "", "", now); err != nil {
		t.Fatal(err)
	}
	b := do(srv, "GET", "/", nil, nil).Body.String()
	if strings.Contains(b, `href="/sites/neu-b"`) || !strings.Contains(b, "neu-b") {
		t.Error("Site ohne Meldung: Link oder Name falsch")
	}
	if w := do(srv, "GET", "/sites/neu-b", nil, nil); w.Code != 404 {
		t.Errorf("Detail ohne Meldung: %d", w.Code)
	}
	if w := post(srv, tok, report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Kind: "contao"}}); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	if b := do(srv, "GET", "/", nil, nil).Body.String(); !strings.Contains(b, `href="/sites/kunde-c"`) {
		t.Error("Site mit Meldung hat keinen Link")
	}
}

func TestSettingsExport(t *testing.T) {
	srv, _ := setupAgents(t)
	if _, err := srv.Agents.CreateBundle("kunde-b", "", "", srv.Now()); err != nil {
		t.Fatal(err)
	}
	w := do(srv, "POST", "/settings/export", url.Values{}, nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(w.Body.String(), `"id": "kunde-b"`) {
		t.Fatalf("Export: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	if w := do(srv, "GET", "/settings/export", nil, nil); w.Code == 200 {
		t.Error("Export darf nicht per GET erreichbar sein")
	}
}

// Eine Site ohne Agent ist verwaist und lässt sich samt Daten entfernen; Sites eines Agenten nicht.
func TestDeleteOrphanSite(t *testing.T) {
	srv, tok, now := setup(t)
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Kind: "contao"}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Report: %d", w.Code)
	}
	del := func() int { return do(srv, "POST", "/sites/kunde-c/delete", url.Values{"confirm": {"1"}}, nil).Code }
	if c := del(); c != http.StatusConflict {
		t.Errorf("Site eines Agenten: %d", c)
	}
	if b := do(srv, "GET", "/sites/kunde-c", nil, nil).Body.String(); strings.Contains(b, "Verwaiste Site") {
		t.Error("Löschen für Site eines Agenten angeboten")
	}
	if err := srv.Agents.Delete("kunde-c"); err != nil {
		t.Fatal(err)
	}
	if b := do(srv, "GET", "/sites/kunde-c", nil, nil).Body.String(); !strings.Contains(b, "Verwaiste Site") {
		t.Error("Löschen für verwaiste Site nicht angeboten")
	}
	if b := do(srv, "GET", "/", nil, nil).Body.String(); !strings.Contains(b, "verwaist") {
		t.Error("Übersicht kennzeichnet die verwaiste Site nicht")
	}
	if w := do(srv, "POST", "/sites/kunde-c/delete", url.Values{}, nil); w.Code != http.StatusNotFound {
		t.Errorf("ohne Bestätigung: %d", w.Code)
	}
	if c := del(); c != http.StatusSeeOther {
		t.Fatalf("Löschen: %d", c)
	}
	if _, ok, _ := srv.Store.Get("kunde-c"); ok {
		t.Error("Reports sind noch da")
	}
	if h, _ := srv.Store.History("kunde-c", 0); len(h) != 0 {
		t.Error("Verlauf ist noch da")
	}
	if b := do(srv, "GET", "/", nil, nil).Body.String(); strings.Contains(b, "kunde-c") {
		t.Error("Site steht noch in der Übersicht")
	}
}

func TestLessFold(t *testing.T) {
	names := []string{"beta", "Zeta", "alpha", "Alpha", "Beta"}
	sort.SliceStable(names, func(i, j int) bool { return lessFold(names[i], names[j]) })
	if got := strings.Join(names, " "); got != "Alpha alpha Beta beta Zeta" {
		t.Errorf("Reihenfolge: %s", got)
	}
}

type fakeProbe map[string]probe.Info

func (f fakeProbe) Info(id string) (probe.Info, bool) { i, ok := f[id]; return i, ok }

func TestProbeLines(t *testing.T) {
	srv, _ := setupAgents(t)
	if _, err := srv.Agents.CreateBundle("kunde-b", "B", "https://b.example", srv.Now()); err != nil {
		t.Fatal(err)
	}
	page := func() string { return html.UnescapeString(do(srv, "GET", "/agents/kunde-b", nil, nil).Body.String()) }
	if !strings.Contains(page(), "Noch nicht geprüft") {
		t.Error("ohne Prober fehlt der Hinweis")
	}
	now := srv.Now()
	srv.Probe = fakeProbe{"kunde-b": {PingAt: now.Add(-12 * time.Minute), PingCode: 200, CertAt: now.Add(-time.Hour), CertExpires: time.Date(2027, 1, 12, 0, 0, 0, 0, time.UTC)}}
	b := page()
	for _, want := range []string{"Weckruf vor 12", "HTTP 200", "Zertifikat läuft am 12.01.2027 ab"} {
		if !strings.Contains(b, want) {
			t.Errorf("Seite ohne %q: %s", want, b)
		}
	}
	srv.Probe = fakeProbe{"kunde-b": {PingAt: now.Add(-time.Minute), PingErr: "timeout", CertAt: now, CertErr: "kein Zertifikat"}}
	if b := page(); !strings.Contains(b, "fehlgeschlagen: timeout") || !strings.Contains(b, "Zertifikatsprüfung gerade eben fehlgeschlagen") {
		t.Errorf("Fehler nicht angezeigt: %s", b)
	}
}
