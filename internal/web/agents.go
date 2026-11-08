package web

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"sitewatch/internal/agentcfg"
	"sitewatch/internal/agents"
	"sitewatch/internal/jobs"
	"sitewatch/internal/report"
	"sitewatch/internal/sign"
	"sitewatch/internal/status"
)

// siteIDs: alle bekannten Sites, auch die ohne Meldung (die Sites der Agenten), sortiert und ohne Doppelte.
func (s *Server) siteIDs() ([]string, error) {
	if s.Agents == nil {
		return nil, nil
	}
	ids, err := s.Agents.SiteIDs()
	sort.Slice(ids, func(i, j int) bool { return lessFold(ids[i], ids[j]) })
	return slices.Compact(ids), err
}

// agentByToken liefert den Agenten zum Token.
func (s *Server) agentByToken(token string) (agents.Agent, bool) {
	if s.Agents == nil {
		return agents.Agent{}, false
	}
	a, ok, err := s.Agents.ByToken(token)
	return a, ok && err == nil
}

// agentMayReport: die Site steht in der Konfiguration des Agenten und der Typ im Report passt zum Typ des Agenten.
// Sonst könnte ein Server-Agent sich als Bundle ausgeben und bekäme dessen großzügigere Schwellwerte.
func agentMayReport(a agents.Agent, rep *report.Report) bool {
	if a.Bundle() != (rep.Agent.Type == report.AgentContaoBundle) {
		return false
	}
	for _, st := range a.Config.Sites {
		if st.ID == rep.Site.ID {
			return true
		}
	}
	return false
}

// agentConfig liefert dem Agenten seine signierte Konfiguration.
func (s *Server) agentConfig(w http.ResponseWriter, r *http.Request) {
	a, ok, err := s.Agents.ByToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil {
		log.Printf("agents: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "nicht autorisiert", http.StatusUnauthorized)
		return
	}
	now := s.Now()
	env, err := sign.Config(s.SignKey, a.ID, now, a.Config)
	if err != nil {
		log.Printf("agents: signieren: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	s.fetchMu.Lock()
	if s.fetched == nil {
		s.fetched = map[string]time.Time{}
	}
	s.fetched[a.ID] = now
	s.fetchMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(env)
}

// sameOrigin lehnt schreibende Anfragen ab, die nicht von der eigenen Seite kommen (zusätzlich zu SameSite=Lax am Cookie).
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
				http.Error(w, "fremde Herkunft", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "fremde Herkunft", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) agentRoutes(ui *http.ServeMux) {
	ui.HandleFunc("GET /agents", s.agentList)
	ui.HandleFunc("POST /agents", s.agentCreate)
	ui.HandleFunc("GET /agents/{id}", s.agentEdit)
	ui.HandleFunc("POST /agents/{id}", s.agentSave)
	ui.HandleFunc("POST /agents/{id}/rotate", s.agentRotate)
	ui.HandleFunc("POST /agents/{id}/delete", s.agentDelete)
}

type agentRow struct {
	ID      string
	Type    string
	Sites   int
	Fetched string
}

// typeLabel: Anzeigename des Agent-Typs.
func typeLabel(a agents.Agent) string {
	if a.Bundle() {
		return "Contao-Bundle"
	}
	return "Server-Agent"
}

func (s *Server) fetchedText(id string) string {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	if t, ok := s.fetched[id]; ok {
		return status.Ago(s.Now().Sub(t))
	}
	return "noch nicht (seit dem Start von Sitewatch)"
}

func (s *Server) agentList(w http.ResponseWriter, r *http.Request) {
	as, err := s.Agents.List()
	if err != nil {
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	rows := make([]agentRow, len(as))
	for i, a := range as {
		rows[i] = agentRow{a.ID, typeLabel(a), len(a.Config.Sites), s.fetchedText(a.ID)}
		if a.Bundle() { // holt keine Konfiguration ab
			rows[i].Fetched = "–"
		}
	}
	s.render(w, "agents.html", map[string]any{"Agents": rows, "Error": r.URL.Query().Get("error")})
}

func (s *Server) agentCreate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("id"))
	var tok string
	var err error
	if r.FormValue("type") == report.AgentContaoBundle {
		tok, err = s.Agents.CreateBundle(id, strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("site_url")), s.Now())
	} else {
		tok, err = s.Agents.Create(id, s.Now())
	}
	if err != nil {
		http.Redirect(w, r, "/agents?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.showToken(w, r, id, tok)
}

// baseURL: unter dieser Adresse erreichen die Agenten Sitewatch. Ohne -public-url zählt der Host der Anfrage;
// X-Forwarded-Proto wird bewusst nicht ausgewertet.
func (s *Server) baseURL(r *http.Request) string {
	base := strings.TrimRight(s.PublicURL, "/")
	if base == "" {
		base = "https://" + r.Host
		if strings.HasPrefix(r.Host, "localhost") && r.TLS == nil {
			base = "http://" + r.Host
		}
	}
	return base
}

// yamlQuote: einfach quotierter YAML-Text (nur ' wird verdoppelt).
func yamlQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

// bundleSnippet ist der Block für config/config.yaml des Contao-Bundles.
func bundleSnippet(base, token string, st agentcfg.Site) string {
	var b strings.Builder
	b.WriteString("cgoit_sitewatch:\n")
	for _, kv := range [][2]string{{"url", base}, {"token", token}, {"site_id", st.ID}, {"site_name", st.Name}, {"site_url", st.URL}} {
		if kv[1] != "" {
			fmt.Fprintf(&b, "    %s: %s\n", kv[0], yamlQuote(kv[1]))
		}
	}
	return b.String()
}

const dockerWrapperDir = "/usr/share/sitewatch-agent/docker/" // Ziel der Pakete sitewatch-agent, siehe packaging/

// dockerTools liefert für die angekreuzten Programme (Formularfelder docker_<name>) den Wrapper aus dem Paket;
// nicht angekreuzte laufen direkt auf dem Host und brauchen keinen Eintrag.
func dockerTools(r *http.Request) []map[string]string {
	var out []map[string]string
	for _, n := range []string{"composer", "php", "nginx", "mariadb"} {
		if r.FormValue("docker_"+n) != "" {
			out = append(out, map[string]string{"Name": n, "Path": dockerWrapperDir + n + "-in-docker"})
		}
	}
	return out
}

// showToken zeigt das neue Token einmalig mit dem Block für die lokale Datei des Agenten.
func (s *Server) showToken(w http.ResponseWriter, r *http.Request, id, tok string) {
	tools := dockerTools(r)
	base := s.baseURL(r)
	w.Header().Set("Cache-Control", "no-store")
	if a, err := s.Agents.Get(id); err == nil && a.Bundle() && len(a.Config.Sites) == 1 {
		s.render(w, "agent_token.html", map[string]any{"ID": id, "Token": tok, "Bundle": true, "Snippet": bundleSnippet(base, tok, a.Config.Sites[0])})
		return
	}
	pub := sign.EncodePublicKey(s.SignKey.Public().(ed25519.PublicKey))
	s.render(w, "agent_token.html", map[string]any{"ID": id, "Jobs": s.jobsUI(), "Token": tok, "Sitewatch": base, "PublicKey": pub, "Tools": tools})
}

type siteForm struct {
	N                                                int
	ID, Name, Kind, URL, Path, BackupDir, BackupGlob string
	SiteDir, Ignore                                  string
	Host, NoNginx, NoMariaDB, NoSMART                bool
	Actions                                          []actionBox // nur bei bestehenden Sites und mit Aufträgen
}

// actionBox: eine Aktion zum Ankreuzen in der Whitelist einer Site; Reported = der Agent hat sie als lokal erlaubt gemeldet.
type actionBox struct {
	Name, Label  string
	On, Reported bool
}

func (s *Server) toForm(i int, st agentcfg.Site, agent string) siteForm {
	f := siteForm{N: i, ID: st.ID, Name: st.Name, Kind: st.Kind, URL: st.URL, Path: st.Path, BackupDir: st.BackupDir,
		BackupGlob: st.BackupGlob, SiteDir: st.Env["SITE_DIR"], Ignore: strings.Join(st.IgnoreUpdates, "\n"), Host: st.Host,
		NoNginx: st.Nginx != nil && !*st.Nginx, NoMariaDB: st.MariaDB != nil && !*st.MariaDB, NoSMART: st.SMART != nil && !*st.SMART}
	if s.jobsUI() && st.Kind != "host" {
		ann, _ := s.announced(agent)
		for _, act := range jobs.Actions {
			if act.AllowsKind(st.Kind) {
				f.Actions = append(f.Actions, actionBox{act.Name, act.Label, slices.Contains(st.Actions, act.Name), slices.Contains(ann.Actions, act.Name)})
			}
		}
	}
	return f
}

func (s *Server) editPage(w http.ResponseWriter, a agents.Agent, cfg agentcfg.Remote, msg string, code int) {
	sites := slices.Clone(cfg.Sites) // alphabetisch nach ID; die gespeicherte Reihenfolge bleibt unberührt
	sort.SliceStable(sites, func(i, j int) bool { return lessFold(sites[i].ID, sites[j].ID) })
	forms := make([]siteForm, 0, len(sites)+1)
	for i, st := range sites {
		forms = append(forms, s.toForm(i, st, a.ID))
	}
	forms = append(forms, siteForm{N: len(forms), Kind: "contao"}) // leere Zeile für eine neue Site
	nonce := newJobID()
	// Nur diese Seite führt ein Skript aus (Nonce): der Knopf „Gemeldete alle wählen“. Ohne JavaScript bleibt er verborgen.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; manifest-src 'self'; script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	preview, _ := json.MarshalIndent(a.Config, "", "  ") // der gespeicherte Stand, nicht die ungespeicherten Eingaben
	s.render(w, "agent.html", map[string]any{"Preview": string(preview), "TTLDays": int(sign.TTL.Hours() / 24), "Now": s.Now(), "Expires": s.Now().Add(sign.TTL), "Agent": a, "Interval": cfg.Interval, "Sites": forms, "Count": len(forms),
		"Error": msg, "Fetched": s.fetchedText(a.ID), "Channel": s.channelText(a.ID), "Nonce": nonce})
}

// bundlePage zeigt ein Contao-Bundle: Name und URL ändern, Snippet für config.yaml (ohne das Token, das es nur einmal gibt).
func (s *Server) bundlePage(w http.ResponseWriter, r *http.Request, a agents.Agent, msg string, code int) {
	st := a.Config.Sites[0]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	s.render(w, "agent_bundle.html", map[string]any{"Agent": a, "Site": st, "Error": msg, "ProbeLines": s.probeLines(st.ID),
		"Snippet": bundleSnippet(s.baseURL(r), "TOKEN-DES-AGENTEN", st)})
}

func (s *Server) agentEdit(w http.ResponseWriter, r *http.Request) {
	a, err := s.Agents.Get(r.PathValue("id"))
	if s.agentErr(w, r, err) {
		return
	}
	if a.Bundle() && len(a.Config.Sites) == 1 {
		s.bundlePage(w, r, a, r.URL.Query().Get("error"), http.StatusOK)
		return
	}
	s.editPage(w, a, a.Config, r.URL.Query().Get("error"), http.StatusOK)
}

const maxSiteRows = 50

// parseSites liest die Zeilen s<n>_… des Formulars; Zeilen mit „löschen“ oder ganz ohne ID fallen weg.
func parseSites(r *http.Request) agentcfg.Remote {
	cfg := agentcfg.Remote{Interval: strings.TrimSpace(r.FormValue("interval"))}
	n, _ := strconv.Atoi(r.FormValue("count"))
	for i := 0; i < min(n, maxSiteRows); i++ {
		f := func(k string) string { return strings.TrimSpace(r.FormValue(fmt.Sprintf("s%d_%s", i, k))) }
		if f("delete") != "" || f("id") == "" {
			continue
		}
		st := agentcfg.Site{ID: f("id"), Name: f("name"), Kind: f("kind"), URL: f("url"), Path: f("path"),
			BackupDir: f("backup_dir"), BackupGlob: f("backup_glob"), Host: f("host") != ""}
		for _, act := range jobs.Actions { // in der Reihenfolge der Liste; Unbekanntes fällt weg
			if slices.Contains(r.Form[fmt.Sprintf("s%d_act", i)], act.Name) {
				st.Actions = append(st.Actions, act.Name)
			}
		}
		if d := f("site_dir"); d != "" {
			st.Env = map[string]string{"SITE_DIR": d}
		}
		no := false
		if f("no_nginx") != "" {
			st.Nginx = &no
		}
		if f("no_mariadb") != "" {
			st.MariaDB = &no
		}
		if f("no_smart") != "" {
			st.SMART = &no
		}
		for _, l := range strings.Split(r.FormValue(fmt.Sprintf("s%d_ignore", i)), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				st.IgnoreUpdates = append(st.IgnoreUpdates, l)
			}
		}
		cfg.Sites = append(cfg.Sites, st)
	}
	return cfg
}

func (s *Server) agentSave(w http.ResponseWriter, r *http.Request) {
	a, err := s.Agents.Get(r.PathValue("id"))
	if s.agentErr(w, r, err) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if a.Bundle() && len(a.Config.Sites) == 1 {
		name, siteURL := strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("site_url"))
		if err := s.Agents.UpdateBundle(a.ID, name, siteURL, s.Now()); err != nil {
			a.Config.Sites[0].Name, a.Config.Sites[0].URL = name, siteURL
			s.bundlePage(w, r, a, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		http.Redirect(w, r, "/agents/"+a.ID, http.StatusSeeOther)
		return
	}
	// Ein unlesbares oder unvollständiges Formular darf die Konfiguration nicht leeren.
	if err := r.ParseForm(); err != nil || r.PostForm.Get("count") == "" {
		http.Error(w, "ungültiges Formular", http.StatusBadRequest)
		return
	}
	cfg := parseSites(r)
	if !s.jobsUI() { // ohne Aufträge zeigt das Formular keine Auswahl: nichts überschreiben
		for i := range cfg.Sites {
			for _, old := range a.Config.Sites {
				if old.ID == cfg.Sites[i].ID {
					cfg.Sites[i].Actions = old.Actions
				}
			}
		}
	}
	if err := s.Agents.Save(a.ID, cfg, s.Now()); err != nil {
		s.editPage(w, a, cfg, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("agents: Konfiguration von %q gespeichert (%d Sites)", a.ID, len(cfg.Sites))
	http.Redirect(w, r, "/agents/"+a.ID, http.StatusSeeOther)
}

func (s *Server) agentRotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok, err := s.Agents.Rotate(id)
	if s.agentErr(w, r, err) {
		return
	}
	log.Printf("agents: Token von %q erneuert", id)
	s.showToken(w, r, id, tok)
}

func (s *Server) agentDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.FormValue("confirm") == "" || !report.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	if s.agentErr(w, r, s.Agents.Delete(id)) {
		return
	}
	log.Printf("agents: %q gelöscht", id)
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

// agentErr beantwortet einen Fehler (404 für unbekannte Agenten, sonst 500) und meldet, ob er einer war.
func (s *Server) agentErr(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, agents.ErrNotFound):
		http.NotFound(w, r)
	default:
		log.Printf("agents: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
	}
	return true
}

// probeLines beschreibt, was Sitewatch zuletzt an der Seite geprüft hat (Weckruf, Zertifikat); leer, wenn nichts geprüft wird.
func (s *Server) probeLines(siteID string) []string {
	if s.Probe == nil {
		return nil
	}
	i, ok := s.Probe.Info(siteID)
	if !ok {
		return nil
	}
	now := s.Now()
	ago := func(t time.Time) string { return status.Ago(now.Sub(t)) } // enthält schon „vor“
	var out []string
	switch {
	case i.PingAt.IsZero():
		out = append(out, "Weckruf: bisher nicht nötig (Report aktuell)")
	case i.PingErr != "":
		out = append(out, "Weckruf "+ago(i.PingAt)+" fehlgeschlagen: "+i.PingErr)
	default:
		out = append(out, fmt.Sprintf("Weckruf %s: HTTP %d", ago(i.PingAt), i.PingCode))
	}
	switch {
	case i.CertAt.IsZero():
		out = append(out, "Zertifikat: noch nicht geprüft")
	case i.CertErr != "":
		out = append(out, "Zertifikatsprüfung "+ago(i.CertAt)+" fehlgeschlagen: "+i.CertErr)
	default:
		out = append(out, fmt.Sprintf("Zertifikat läuft am %s ab (geprüft %s)", i.CertExpires.Format("02.01.2006"), ago(i.CertAt)))
	}
	return out
}
