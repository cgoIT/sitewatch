package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/report"
	"sitewatch/internal/status"
	"sitewatch/internal/store"
)

func setup(t *testing.T) (*Server, string, time.Time) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "data", "sitewatch.db"), store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 27, 19, 0, 0, 0, time.UTC)
	srv := New(st, status.DefaultConfig())
	srv.Now = func() time.Time { return now }
	if srv.Agents, err = agents.Open(st.DB()); err != nil {
		t.Fatal(err)
	}
	tok, err := srv.Agents.CreateBundle("kunde-c", "", "", now) // ein Token für die Site kunde-c
	if err != nil {
		t.Fatal(err)
	}
	return srv, tok, now
}

func post(srv *Server, token string, rep report.Report) *httptest.ResponseRecorder {
	if rep.Agent.Type == "" { // setup legt einen Bundle-Agenten an, dessen Typ der Report tragen muss
		rep.Agent.Type = report.AgentContaoBundle
	}
	body, _ := json.Marshal(rep)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestIngestAndOverview(t *testing.T) {
	srv, tok, now := setup(t)
	tls, three := now.Add(60*24*time.Hour), 3
	rep := report.Report{
		Schema: 1, CollectedAt: now,
		Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "contao", PHP: "8.3.12", Contao: "5.3.9", TLSExpires: &tls, BackupCount: &three,
			Advisories: []report.Advisory{{Package: "symfony/http-kernel", Title: "Beispiel"}}},
	}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Kunde C") || !strings.Contains(w.Body.String(), "Kritisch") {
		t.Fatalf("Übersicht unerwartet: %d", w.Code)
	}
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Sicherheitshinweis") || !strings.Contains(w.Body.String(), "TLS läuft ab") || !strings.Contains(w.Body.String(), ">3<") ||
		!strings.Contains(w.Body.String(), tls.Local().Format("02.01.2006")) {
		t.Fatalf("Detail unerwartet: %d", w.Code)
	}
}

func TestIngestRejects(t *testing.T) {
	srv, tok, now := setup(t)
	ok := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Kind: "contao"}}

	if w := post(srv, "", ok); w.Code != http.StatusUnauthorized {
		t.Errorf("ohne Token: %d", w.Code)
	}
	if w := post(srv, "falsch", ok); w.Code != http.StatusUnauthorized {
		t.Errorf("falsches Token: %d", w.Code)
	}
	other := ok
	other.Site.ID = "kunde-x" // Token gehört nicht zu dieser Site
	if w := post(srv, tok, other); w.Code != http.StatusUnauthorized {
		t.Errorf("fremde Site: %d", w.Code)
	}
	bad := ok
	bad.Schema = 9
	if w := post(srv, tok, bad); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("ungültiges Schema: %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", strings.NewReader("{kaputt"))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("kaputtes JSON: %d", w.Code)
	}
}

func TestSilentSiteIsCritical(t *testing.T) {
	srv, _, _ := setup(t) // kunde-c ist registriert, hat aber nie gemeldet
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(w.Body.String(), "Noch keine Meldung") {
		t.Errorf("stille Site fehlt in der Übersicht")
	}
}

func TestProtectGuardsUIButNotAgentAPI(t *testing.T) {
	srv, _, _ := setup(t)
	srv.Protect = func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	}
	h := srv.Handler()
	for _, path := range []string{"/", "/sites/kunde-c"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: Code %d, erwartet 403", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz: Code %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/foo", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("/foo: Code %d, erwartet 403", rec.Code)
	}
	// Die Agent-API darf nicht am Login hängen: ohne Token 401 statt 403.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/reports", strings.NewReader("{}")))
	if rec.Code == http.StatusForbidden {
		t.Error("Agent-API läuft hinter Protect")
	}
}

func TestDetailUsesCollectedAtAndIgnoresRuleHits(t *testing.T) {
	srv, tok, now := setup(t)
	rep := report.Report{Schema: 1, CollectedAt: now.Add(-3 * time.Hour), Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "contao",
		Outdated: []report.Package{{Name: "contao/news-bundle", Installed: "5.7.15", Latest: "6.0.4", Status: "update-possible", Ignored: true}}}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c", nil))
	body := w.Body.String()
	if !strings.Contains(body, rep.CollectedAt.Local().Format("02.01. 15:04")) || !strings.Contains(body, "ausgeschlossen") || strings.Contains(body, "Paket(e) mit verfügbarem Update") {
		t.Errorf("Detail unerwartet: %s", body)
	}
}

func TestLogoutButtonOnlyWithLogin(t *testing.T) {
	srv, _, _ := setup(t)
	get := func() (string, string) {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Body.String(), rec.Header().Get("Content-Security-Policy")
	}
	if body, _ := get(); strings.Contains(body, `action="/logout"`) {
		t.Error("Abmelden ohne Login sichtbar")
	}
	srv.Protect = func(next http.Handler) http.Handler { return next }
	body, csp := get()
	if !strings.Contains(body, `action="/logout"`) {
		t.Error("Abmelden fehlt")
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("CSP: %s", csp)
	}
}

func TestDetailShowsCronAndMigrations(t *testing.T) {
	srv, tok, now := setup(t)
	zero, cron := 0, now.Add(-2*time.Minute)
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "contao",
		PendingMigrations: &zero, CronLastRun: &cron}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c", nil))
	body := w.Body.String()
	if !strings.Contains(body, `Offene Migrationen</dt><dd class="mono">0</dd>`) || !strings.Contains(body, cron.Local().Format("02.01. 15:04")) {
		t.Errorf("Cron/Migrationen fehlen: %s", body)
	}
}

func TestDetailDaySnapshot(t *testing.T) {
	srv, tok, now := setup(t)
	if w := post(srv, tok, report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Kind: "contao"}}); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	get := func(q string) (int, string) {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c"+q, nil))
		return w.Code, w.Body.String()
	}
	if c, b := get(""); c != 200 || strings.Contains(b, "Tagesstand vom") || !strings.Contains(b, `value="2026-10-27">27.10.2026`) {
		t.Errorf("aktueller Stand: %d, Liste der Tage fehlt oder Banner zu viel", c)
	}
	if c, b := get("?day=2026-10-27"); c != 200 || !strings.Contains(b, "Tagesstand vom 27.10.2026") {
		t.Errorf("Tagesstand: %d", c)
	}
	for _, q := range []string{"?day=2026-10-01", "?day=quatsch"} {
		if c, _ := get(q); c != 404 {
			t.Errorf("%s: %d, erwartet 404", q, c)
		}
	}
}

func TestMatrixPagesAndHostTable(t *testing.T) {
	srv, tok, now := setup(t)
	free := 42
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "host"}, Host: report.Host{DiskFreePct: &free}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d %s", w.Code, w.Body.String())
	}
	get := func(path string) string {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	if b := get("/"); !strings.Contains(b, "<h2>Hosts</h2>") || !strings.Contains(b, "42 %") || strings.Contains(b, "<h2>Versionen") {
		t.Errorf("Übersicht: Host-Tabelle fehlt oder Matrix noch dabei")
	}
	if b := get("/?kind=contao"); strings.Contains(b, "<h2>Hosts</h2>") || !strings.Contains(b, "Keine Site passt zum Filter") {
		t.Errorf("Filter kind=contao: Hosts-Tabelle sichtbar oder Sites-Hinweis fehlt")
	}
	if b := get("/?kind=host"); strings.Contains(b, "<h2>Sites") || !strings.Contains(b, "<h2>Hosts</h2>") {
		t.Errorf("Filter kind=host: Sites-Tabelle sichtbar oder Hosts fehlen")
	}
	if b := get("/versions"); !strings.Contains(b, "Kunde C") || !strings.Contains(b, "MariaDB") || strings.Contains(b, "Letztes Backup") {
		t.Errorf("/versions unerwartet")
	}
	if b := get("/parameters?q=nichts"); strings.Contains(b, ">Kunde C<") || !strings.Contains(b, "passt zum Filter") {
		t.Errorf("/parameters ignoriert den Filter")
	}
}

func TestOverviewTLSAndBackupColumns(t *testing.T) {
	srv, tok, now := setup(t)
	tls, bk := now.Add(5*24*time.Hour), now.Add(-30*24*time.Hour) // TLS bald abgelaufen, Backup uralt
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "contao", TLSExpires: &tls, LastBackup: &bk}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d", w.Code)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	b := w.Body.String()
	for _, l := range []string{"TLS läuft ab", "Letztes Backup"} {
		if !strings.Contains(b, `data-label="`+l+`"`) {
			t.Errorf("Spalte %q fehlt", l)
		}
	}
	if strings.Contains(b, `data-label="Contao"`) {
		t.Errorf("Contao-Spalte sollte nicht mehr in der Übersicht stehen")
	}
	if !strings.Contains(b, "lvb warn") && !strings.Contains(b, "lvb crit") {
		t.Errorf("TLS/Backup werden nicht eingefärbt")
	}
}

func TestUptimeColumnAndSetting(t *testing.T) {
	srv, tok, now := setup(t)
	st := srv.Store.(*store.SQLite)
	srv.Uptime = st
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "contao"}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d", w.Code)
	}
	for i, state := range []string{store.CheckUp, store.CheckUp, store.CheckDown, store.CheckUp} {
		if err := st.AddCheck("kunde-c", store.Check{At: now.Add(-time.Duration(10-i) * time.Minute), State: state, LatencyMS: 180, Code: 200}); err != nil {
			t.Fatal(err)
		}
	}
	get := func(path string) string {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	b := get("/")
	// 3 von 4 Prüfungen erreichbar = 75 %; Antwortzeit 180 ms
	if !strings.Contains(b, "<th>Erreichbarkeit</th>") || !strings.Contains(b, "75,00 %") || !strings.Contains(b, "180 ms") || !strings.Contains(b, "upl warn") {
		t.Errorf("Spalte Erreichbarkeit unvollständig")
	}
	if d := get("/sites/kunde-c"); !strings.Contains(d, "Ausfälle der letzten 7 Tage") || !strings.Contains(d, `action="/sites/kunde-c/uptime"`) {
		t.Errorf("Detailseite ohne Erreichbarkeit")
	}
	post := func(vals string) int {
		req := httptest.NewRequest(http.MethodPost, "/sites/kunde-c/uptime", strings.NewReader(vals))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://example.com")
		req.Host = "example.com"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if c := post("interval=7"); c != http.StatusNotFound {
		t.Errorf("ungültiges Intervall: %d", c)
	}
	if c := post("interval=300"); c != http.StatusSeeOther { // Haken fehlt = abgeschaltet
		t.Errorf("speichern: %d", c)
	}
	if s, _ := st.UptimeSettings(); s["kunde-c"].Enabled || s["kunde-c"].IntervalS != 300 {
		t.Errorf("gespeichert: %+v", s)
	}
	if b := get("/"); !strings.Contains(b, `<span class="muted">aus</span>`) {
		t.Errorf("abgeschaltete Prüfung nicht gekennzeichnet")
	}
}

type massDownSrc struct{ down bool }

func (massDownSrc) Check(string) (status.UptimeCheck, bool) { return status.UptimeCheck{}, false }
func (m massDownSrc) MassDown() bool                        { return m.down }

func TestMassDownBanner(t *testing.T) {
	srv, _, _ := setup(t)
	get := func() string {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w.Body.String()
	}
	c := srv.cfg()
	c.Uptime = massDownSrc{down: true}
	srv.Settings.Set(c)
	if !strings.Contains(get(), "Möglicherweise liegt das Problem bei Sitewatch") {
		t.Error("Hinweis fehlt")
	}
	c.Uptime = massDownSrc{}
	srv.Settings.Set(c)
	if strings.Contains(get(), "Möglicherweise liegt das Problem bei Sitewatch") {
		t.Error("Hinweis ohne Massenausfall")
	}
}

func TestSiteIcon(t *testing.T) {
	srv, tok, now := setup(t)
	st := srv.Store.(*store.SQLite)
	srv.Favicons = st
	post(srv, tok, report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "Kunde C", Kind: "php"}})
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if w := get("/sites/kunde-c/icon"); w.Code != http.StatusNotFound {
		t.Errorf("ohne Symbol: %d", w.Code)
	}
	if strings.Contains(get("/").Body.String(), `class="fav"`) {
		t.Error("ohne Symbol darf kein Bild erscheinen")
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), 1, 2, 3)
	if err := st.SetFavicon("kunde-c", store.Favicon{Data: png, Type: "image/png", URL: "https://x.example", Fetched: now}); err != nil {
		t.Fatal(err)
	}
	w := get("/sites/kunde-c/icon")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") || !bytes.Equal(w.Body.Bytes(), png) {
		t.Errorf("Symbol: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(get("/").Body.String(), `src="/sites/kunde-c/icon?v=`) {
		t.Error("Übersicht zeigt das Symbol nicht")
	}
	for _, id := range []string{"unbekannt", "GROSS", "a.b"} {
		if w := get("/sites/" + id + "/icon"); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", id, w.Code)
		}
	}
}

func TestHostDetailShowsOSNetworkUpdates(t *testing.T) {
	srv, tok, now := setup(t)
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "Server 1", Kind: "host"}, Host: report.Host{
		OS:      &report.OSInfo{Name: "Debian GNU/Linux 12", Kernel: "6.1.0"},
		Network: &report.Network{Gateway: "10.0.0.1", Interfaces: []report.Iface{{Name: "eth0", Addrs: []string{"10.0.0.2/24"}}}},
		Updates: &report.OSUpdates{Manager: "apt", Total: 2, Security: 1, Packages: []report.OSPackage{{Name: "curl", Installed: "1", New: "2", Security: true}}},
		Systemd: &report.Systemd{Failed: []string{"foo.service"}},
	}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c", nil))
	body := w.Body.String()
	for _, want := range []string{"Debian GNU/Linux 12", "10.0.0.2/24", "10.0.0.1", "foo.service", "Betriebssystem-Updates", ">curl<", "Sicherheit"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q fehlt auf der Host-Detailseite", want)
		}
	}
	if strings.Contains(body, "Pakete mit Updates") || strings.Contains(body, "Letzte Fehler") {
		t.Errorf("Contao-Karten dürfen bei Hosts nicht erscheinen")
	}
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(w.Body.String(), "2 (1 Sicherheit)") {
		t.Errorf("Übersicht zeigt die apt-Updates nicht")
	}
}

func TestDiskAckFlow(t *testing.T) {
	srv, tok, now := setup(t)
	st := srv.Store.(*store.SQLite)
	srv.DiskAcks = st
	cfg := srv.Settings.Get()
	cfg.DiskAcks = st
	srv.Settings.Set(cfg)
	bad, ok := 16, true
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "S", Kind: "host"},
		Host: report.Host{Disks: []report.Disk{{Device: "/dev/sdd", Serial: "S1", Passed: &ok, BadSectors: &bad}}}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("Ingest: %d %s", w.Code, w.Body.String())
	}
	get := func() string {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c", nil))
		return w.Body.String()
	}
	if b := get(); !strings.Contains(b, "Zur Kenntnis nehmen") || !strings.Contains(b, "16 defekte/umgelagerte Sektoren") {
		t.Fatalf("Knopf oder Warnung fehlt: %s", b)
	}
	do := func(form url.Values) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/sites/kunde-c/disks", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		srv.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if c := do(url.Values{"disk": {"sn:S1"}, "action": {"boese"}}); c != http.StatusBadRequest {
		t.Errorf("unbekannte Aktion: %d", c)
	}
	if c := do(url.Values{"disk": {"sn:FREMD"}, "action": {"ack"}}); c != http.StatusNotFound {
		t.Errorf("unbekannte Platte: %d", c)
	}
	if c := do(url.Values{"disk": {"sn:S1"}, "action": {"ack"}}); c != http.StatusSeeOther {
		t.Fatalf("ack: %d", c)
	}
	if b := get(); strings.Contains(b, "16 defekte/umgelagerte Sektoren") || !strings.Contains(b, "bekannt seit") {
		t.Errorf("nach Kenntnisnahme darf es nicht mehr warnen")
	}
	bad = 19
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	if b := get(); !strings.Contains(b, "gestiegen von 16 auf 19") {
		t.Errorf("Anstieg muss warnen")
	}
	if w := httptest.NewRecorder(); true {
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c?day=2026-10-27", nil))
		if strings.Contains(w.Body.String(), "Zurücknehmen") {
			t.Error("Tagesansicht darf keine Knöpfe zeigen")
		}
	}
	if c := do(url.Values{"disk": {"sn:S1"}, "action": {"clear"}}); c != http.StatusSeeOther {
		t.Fatalf("clear: %d", c)
	}
	if _, _, ok := st.DiskAck("kunde-c", "sn:S1"); ok {
		t.Error("Kenntnisnahme besteht noch")
	}
}

func TestHostDetailLayoutOrder(t *testing.T) {
	srv, tok, now := setup(t)
	rep := report.Report{Schema: 1, CollectedAt: now, Site: report.Site{ID: "kunde-c", Name: "S", Kind: "host"}, Host: report.Host{
		OS: &report.OSInfo{Name: "Debian"}, Network: &report.Network{}, Updates: &report.OSUpdates{Manager: "apt"}}}
	if w := post(srv, tok, rep); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sites/kunde-c", nil))
	body, last := w.Body.String(), -1
	for _, h := range []string{"<h2>System</h2>", "<h2>Betriebssystem-Updates", "<h2>Netzwerk</h2>", "<h2>Speicher und Platten</h2>"} {
		i := strings.Index(body, h)
		if i < 0 || i < last {
			t.Fatalf("%q fehlt oder steht an falscher Stelle", h)
		}
		last = i
	}
}
