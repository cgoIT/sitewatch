// Package web enthält die HTTP-Handler von Sitewatch: Empfang der Reports und die Oberfläche.
package web

import (
	"crypto/ed25519"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/report"
	"sitewatch/internal/status"
	"sitewatch/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

// Server bündelt die Abhängigkeiten der Handler.
type Server struct {
	Store store.Store
	// Settings sind die Schwellwerte; SaveSettings speichert eine Änderung aus dem Cockpit (vals = nur die vom Standard abweichenden
	// Werte, nil = zurück auf die Standardwerte) und übernimmt sie in Settings.
	Settings     *status.Settings
	SaveSettings func(cfg status.Config, vals map[string]int) error
	settingsMu   sync.Mutex
	Now          func() time.Time
	// Protect schützt die Oberfläche (Login). nil = offen; die Agent-API ist nie betroffen.
	Protect func(http.Handler) http.Handler
	// Agents und SignKey schalten die Fernkonfiguration der Agenten ein (Config-API und Seiten unter /agents); nil = aus.
	Agents  *agents.Store
	SignKey ed25519.PrivateKey
	// PublicURL ist die Adresse von Sitewatch für den Block der Agenten-Datei; leer = https://<Host der Anfrage>.
	PublicURL string
	// Version erscheint in der Fußzeile (zusammen mit dem Git-Commit aus den Build-Informationen, falls vorhanden).
	Version string
	// TestMail verschickt eine Testmail über die eingestellte Alarmierung; nil = nicht eingerichtet (kein Knopf).
	TestMail func() error
	// Jobs und Who schalten die Aufträge ein (Seiten unter /jobs, Kanal für die Agenten). Who liefert den angemeldeten Benutzer
	// ("" = niemand); ohne Login (Protect == nil) gibt es keine Seiten für Aufträge, weil die Freigabe eine Person braucht.
	Jobs store.Jobs
	Who  func(*http.Request) string
	hub  hub

	annMu sync.Mutex
	ann   map[string]announce
	tpl   *template.Template

	mailMu sync.Mutex
	mailAt time.Time

	fetchMu sync.Mutex
	fetched map[string]time.Time // wann der Agent die Konfiguration zuletzt abgeholt hat (nur im Speicher)
}

// New baut den Server; Agents, SignKey, Protect und weitere Felder setzt der Aufrufer danach, bevor er Handler aufruft.
func New(s store.Store, cfg status.Config) *Server {
	srv := &Server{Store: s, Settings: status.NewSettings(cfg), Now: time.Now}
	srv.SaveSettings = func(c status.Config, _ map[string]int) error { srv.Settings.Set(c); return nil } // ohne Speicher nur im Arbeitsspeicher
	srv.tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"version":     srv.versionText,
		"hasTestMail": func() bool { return srv.TestMail != nil },
		"hasLogin":    func() bool { return srv.Protect != nil }, // Logout-Button nur mit Login
		"hasAgents":   func() bool { return srv.Agents != nil },
		"hasJobs":     func() bool { return srv.jobsUI() },
		"kinds":       func() []string { return []string{"contao", "php", "host"} },
		"fmtDate":     func(t time.Time) string { return t.Local().Format("02.01.2006") },
		"fmtTime":     func(t time.Time) string { return t.Local().Format("02.01. 15:04") },
	}).ParseFS(templateFS, "templates/*.html"))
	return srv
}

// Handler liefert die Routen: Oberfläche (hinter Protect und Same-Origin-Prüfung) und die Agent-API (Bearer-Token).
func (s *Server) Handler() http.Handler {
	ui := http.NewServeMux()
	ui.HandleFunc("GET /{$}", s.overview)
	ui.HandleFunc("GET /sites/{id}", s.detail)
	ui.HandleFunc("POST /sites/{id}/delete", s.siteDelete)
	if s.TestMail != nil {
		ui.HandleFunc("POST /alert-test", s.testMail)
	}
	s.settingsRoutes(ui)
	if s.Agents != nil {
		s.agentRoutes(ui)
	}
	if s.jobsUI() {
		s.jobRoutes(ui)
	}
	var uiHandler http.Handler = sameOrigin(ui)
	if s.Protect != nil {
		uiHandler = s.Protect(sameOrigin(ui))
	}
	// Agent-API (Bearer-Token) und Healthcheck bleiben außerhalb des Logins.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/reports", s.ingest)
	if s.Agents != nil {
		mux.HandleFunc("GET /api/v1/agent/config", s.agentConfig)
		if s.Jobs != nil {
			mux.HandleFunc("GET /api/v1/agent/jobs", s.jobPoll)
			mux.HandleFunc("POST /api/v1/agent/jobs/{id}/events", s.jobEvents)
		}
	}
	// Manifest und Symbol ohne Login: Der Browser holt sie ohne Cookies, sonst ließe sich die Seite nicht installieren.
	mux.HandleFunc("GET /manifest.webmanifest", manifest)
	mux.HandleFunc("GET /icon.svg", icon)
	for _, n := range []string{"icon-192.png", "icon-512.png", "apple-touch-icon.png"} {
		mux.HandleFunc("GET /"+n, png(n))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.Handle("/", uiHandler)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// ingest nimmt einen Report entgegen. Das Token muss zur Site-ID im Report passen.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	a, ok := s.agentByToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !ok { // vor dem Lesen des Bodys
		http.Error(w, "nicht autorisiert", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var rep report.Report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, "ungültiges JSON", http.StatusBadRequest)
		return
	}
	if !agentMayReport(a, &rep) {
		log.Printf("report: Token abgelehnt für site=%q (Agent %q)", rep.Site.ID, a.ID)
		http.Error(w, "nicht autorisiert", http.StatusUnauthorized)
		return
	}
	now := s.Now()
	if err := rep.Validate(now); err != nil {
		log.Printf("report: ungültig von site=%q: %v", rep.Site.ID, err)
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	e := store.Entry{Report: rep, ReceivedAt: now.UTC()}
	if err := s.Store.Save(e, int(status.Evaluate(&rep, now, now, s.cfg()).Level)); err != nil {
		log.Printf("Speichern fehlgeschlagen: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	log.Printf("report: gespeichert site=%q", rep.Site.ID)
	w.WriteHeader(http.StatusNoContent)
}

type row struct {
	ID, Name, URL, Kind, Contao, PHP string
	Updates, Errors, Seen            string
	Level, Label, Icon               string
	Reasons                          []string
	Maintenance                      bool
	Reported                         bool // es gibt einen Report, nur dann gibt es eine Detailseite
	Orphan                           bool // Reports sind da, aber kein Agent ist mehr für die Site eingetragen
	UpdatesTrend                     *arrow
}

type tiles struct{ Total, Contao, PHP, Crit, Warn, Updates int }

// cfg liefert die aktuellen Schwellwerte.
func (s *Server) cfg() status.Config { return s.Settings.Get() }

func (s *Server) rows(base map[string]store.Sample) ([]row, tiles, error) {
	entries, err := s.Store.Latest()
	if err != nil {
		return nil, tiles{}, err
	}
	ids, err := s.siteIDs()
	if err != nil {
		return nil, tiles{}, err
	}
	now := s.Now()
	seen, known := map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	var rows []row
	var t tiles
	for _, e := range entries {
		seen[e.Report.Site.ID] = true
		rep := e.Report
		res := status.Evaluate(&rep, e.ReceivedAt, now, s.cfg())
		rw := row{
			ID: rep.Site.ID, Name: rep.Site.Name, URL: rep.Site.URL, Kind: rep.Site.Kind, Contao: dash(rep.Site.Contao), PHP: dash(rep.Site.PHP),
			Updates: "–", Errors: "–", Seen: status.Ago(now.Sub(e.ReceivedAt)),
			Reasons:     res.Reasons,
			Maintenance: rep.Site.MaintenanceMode != nil && *rep.Site.MaintenanceMode, Reported: true,
			Orphan: s.Agents != nil && !known[rep.Site.ID],
		}
		if rw.Orphan {
			rw.Reasons = append(rw.Reasons, "Gehört zu keinem Agenten mehr (verwaist), auf der Detailseite entfernbar")
		}
		if rep.Site.Kind == "contao" {
			if rep.Agent.Type != report.AgentContaoBundle { // das Bundle prüft keine Updates: "–" statt einer falschen 0
				rw.Updates = fmt.Sprint(rep.Site.OpenUpdates())
				b, ok := base[rep.Site.ID]
				rw.UpdatesTrend = updatesArrow(rep.Site.OpenUpdates(), b, ok, now)
				t.Updates += rep.Site.OpenUpdates()
			}
			n := 0
			for _, le := range rep.Errors {
				n += le.Count
			}
			rw.Errors = fmt.Sprint(n)
			t.Contao++
		} else if rep.Site.Kind == "php" {
			t.PHP++
		}
		setLevel(&rw, res.Level)
		rows = append(rows, rw)
	}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		rw := row{ID: id, Name: id, Contao: "–", PHP: "–", Updates: "–", Errors: "–", Seen: "noch nie",
			Reasons: []string{"Noch keine Meldung eingegangen"}}
		setLevel(&rw, status.Crit)
		rows = append(rows, rw)
	}
	for _, rw := range rows {
		switch rw.Level {
		case "crit":
			t.Crit++
		case "warn":
			t.Warn++
		}
	}
	t.Total = len(rows)
	rank := map[string]int{"crit": 0, "warn": 1, "ok": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if rank[rows[i].Level] != rank[rows[j].Level] {
			return rank[rows[i].Level] < rank[rows[j].Level]
		}
		return lessFold(rows[i].Name, rows[j].Name)
	})
	return rows, t, nil
}

func setLevel(r *row, l status.Level) {
	r.Level = l.String()
	switch l {
	case status.Crit:
		r.Label, r.Icon = "Kritisch", "■"
	case status.Warn:
		r.Label, r.Icon = "Warnung", "▲"
	default:
		r.Label, r.Icon = "OK", "●"
	}
}

func dash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	base := s.baselines()
	rows, t, err := s.rows(base)
	if err != nil {
		log.Printf("overview: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	versions, params, err := s.matrices(base)
	if err != nil {
		log.Printf("overview: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	f := filterFrom(r)
	rows = f.apply(rows)
	keep := map[string]bool{}
	for _, rw := range rows {
		keep[rw.ID] = true
	}
	for _, m := range []*matrix{&versions, &params} {
		kept := m.Rows[:0]
		for _, mr := range m.Rows {
			if keep[mr.ID] {
				kept = append(kept, mr)
			}
		}
		m.Rows = kept
	}
	s.render(w, "overview.html", map[string]any{"Rows": rows, "Tiles": t, "Versions": versions, "Params": params, "Now": s.Now().Local().Format("02.01.2006 15:04"), "Filter": f, "Mail": r.URL.Query().Get("mail")})
}

// filter schränkt die Übersicht ein (GET-Formular, ohne JavaScript). Die Kacheln oben zählen immer alle Sites.
type filter struct{ Q, Status, Kind string }

func filterFrom(r *http.Request) filter {
	q := r.URL.Query()
	f := filter{Q: strings.TrimSpace(q.Get("q")), Status: q.Get("status"), Kind: q.Get("kind")}
	if f.Status != "problems" && f.Status != "crit" {
		f.Status = ""
	}
	if f.Kind != "contao" && f.Kind != "php" && f.Kind != "host" {
		f.Kind = ""
	}
	if len(f.Q) > 100 {
		f.Q = f.Q[:100]
	}
	return f
}

// Active sagt, ob irgendein Filter gesetzt ist.
func (f filter) Active() bool { return f.Q != "" || f.Status != "" || f.Kind != "" }

func (f filter) apply(rows []row) []row {
	if !f.Active() {
		return rows
	}
	q := strings.ToLower(f.Q)
	var out []row
	for _, rw := range rows {
		switch {
		case f.Status == "crit" && rw.Level != "crit", f.Status == "problems" && rw.Level == "ok":
		case f.Kind != "" && rw.Kind != f.Kind: // Sites ohne Meldung haben noch keine Art und fallen hier heraus
		case q != "" && !strings.Contains(strings.ToLower(rw.Name+" "+rw.ID+" "+rw.URL), q):
		default:
			out = append(out, rw)
		}
	}
	return out
}

type detailPackage struct {
	report.Package
	Label, Class string
}

func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !report.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	days, err := s.Store.Days(id)
	if err != nil {
		log.Printf("detail: Tagesstände: %v", err)
	}
	day := r.URL.Query().Get("day")
	var cur store.Entry
	var ok bool
	if day != "" { // Tagesstand: ein früherer Report; ungültige Angaben ergeben 404
		if _, perr := time.Parse("2006-01-02", day); perr != nil {
			http.NotFound(w, r)
			return
		}
		cur, ok, err = s.Store.GetDay(id, day)
	} else {
		cur, ok, err = s.Store.Get(id)
	}
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	hist, err := s.Store.History(id, 0) // alles, neueste zuerst; die Tabelle zeigt die letzten 20
	if err != nil {
		log.Printf("detail: Verlauf: %v", err)
	}
	tr := buildTrend(hist, rangeDays(r), s.Now(), cur.Report.Site.Kind == "contao", s.cfg())
	hist = hist[:min(len(hist), 20)]
	rep := cur.Report
	evalAt := s.Now()
	if day != "" {
		evalAt = cur.ReceivedAt // Bewertung wie damals, sonst wäre jeder alte Stand „keine Meldung"
	}
	res := status.Evaluate(&rep, cur.ReceivedAt, evalAt, s.cfg())
	rw := row{Reasons: res.Reasons}
	setLevel(&rw, res.Level)

	var open, ignored []detailPackage
	for _, p := range rep.Site.Outdated {
		d := detailPackage{p, "innerhalb der Constraints", "warn"}
		switch {
		case p.Ignored:
			d.Label, d.Class = "ausgeschlossen (Regel in der Agent-Konfiguration)", "off"
		case p.Status == "update-possible":
			d.Label, d.Class = "neue Hauptversion, manuell prüfen", "info"
		}
		if p.Ignored {
			ignored = append(ignored, d)
		} else {
			open = append(open, d)
		}
	}
	s.render(w, "detail.html", map[string]any{
		"R": rep, "Status": rw, "Packages": open, "Ignored": ignored, "History": hist, "Trend": tr, "OpenUpdates": len(open),
		"Seen": status.Ago(s.Now().Sub(cur.ReceivedAt)),
		"Day":  day, "DayLabel": dayLabel(day), "Days": dayOptions(days, day),
		"Maintenance": maintenanceLabel(rep.Site.MaintenanceMode, rep.Site.MaintenanceSince),
		"Orphan":      s.orphan(id),
	})
}

// lessFold sortiert ohne Rücksicht auf Groß- und Kleinschreibung; bei Gleichheit entscheidet die genaue Schreibweise, damit die Reihenfolge stabil bleibt.
func lessFold(a, b string) bool {
	if la, lb := strings.ToLower(a), strings.ToLower(b); la != lb {
		return la < lb
	}
	return a < b
}

// orphan: Reports sind gespeichert, aber kein Agent hat die Site (mehr) in seiner Konfiguration.
func (s *Server) orphan(id string) bool {
	if s.Agents == nil {
		return false
	}
	ids, err := s.siteIDs()
	return err == nil && !slices.Contains(ids, id)
}

// siteDelete entfernt eine verwaiste Site mit allen Daten. Sites eines Agenten bleiben geschützt; man löscht den Agenten oder die Site aus seiner Konfiguration.
func (s *Server) siteDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.FormValue("confirm") == "" || !report.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	// shortcut: Prüfen und Löschen sind nicht atomar; legt ein zweiter Admin genau dazwischen einen Agenten für die Site an, gehen deren
	// Verlauf und Aufträge verloren (der nächste Report stellt den Rest wieder her). Bei mehreren Admins mit einem Mutex sperren.
	if !s.orphan(id) {
		http.Error(w, "die Site gehört noch zu einem Agenten", http.StatusConflict)
		return
	}
	if err := s.Store.DeleteSite(id); err != nil {
		log.Printf("sites: %q löschen: %v", id, err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	log.Printf("sites: verwaiste Site %q mit allen Daten entfernt", id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type dayOption struct {
	Value, Label string
	Selected     bool
}

// dayLabel macht aus "2026-10-30" "30.10.2026"; Ungültiges bleibt unverändert.
func dayLabel(d string) string {
	t, err := time.Parse("2006-01-02", d)
	if err != nil {
		return d
	}
	return t.Format("02.01.2006")
}

// dayOptions: Auswahl für die Historie, neueste zuerst (so liefert sie der Store); vorn der aktuelle Stand.
func dayOptions(days []string, sel string) []dayOption {
	if len(days) == 0 {
		return nil
	}
	out := []dayOption{{"", "Aktueller Stand", sel == ""}}
	for _, d := range days {
		out = append(out, dayOption{d, dayLabel(d), d == sel})
	}
	return out
}

func maintenanceLabel(m *bool, since *time.Time) string {
	switch {
	case m == nil:
		return "unbekannt"
	case *m && since != nil:
		return "an seit " + since.Local().Format("02.01. 15:04")
	case *m:
		return "an"
	}
	return "aus"
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// testMail verschickt eine Testmail und kehrt mit einer festen Meldung zur Übersicht zurück (Fehlertext nur im Log).
func (s *Server) testMail(w http.ResponseWriter, r *http.Request) {
	s.mailMu.Lock()
	tooSoon := s.Now().Sub(s.mailAt) < 10*time.Second // gegen Dauerklicken
	if !tooSoon {
		s.mailAt = s.Now()
	}
	s.mailMu.Unlock()
	res := "ok"
	if tooSoon {
		res = "wait"
	} else if err := s.TestMail(); err != nil {
		log.Printf("Testmail fehlgeschlagen: %v", err)
		res = "fail"
	}
	http.Redirect(w, r, "/?mail="+res, http.StatusSeeOther)
}
