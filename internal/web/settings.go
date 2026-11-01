package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sitewatch/internal/backup"
	"strconv"
	"strings"

	"sitewatch/internal/status"
)

func (s *Server) settingsRoutes(ui *http.ServeMux) {
	ui.HandleFunc("GET /settings", s.settingsShow)
	ui.HandleFunc("POST /settings", s.settingsSave)
	ui.HandleFunc("POST /settings/reset", s.settingsReset)
	ui.HandleFunc("POST /settings/export", s.settingsExport)
}

type settingField struct {
	Key, Label, Unit, Value, Default string
}

type settingGroup struct {
	Name   string
	Fields []settingField
}

// settingGroups bereitet die Felder für das Formular auf; entered überschreibt die aktuellen Werte (bei Eingabefehlern).
func settingGroups(cur status.Config, entered map[string]string) []settingGroup {
	def, now := status.DefaultConfig().Values(), cur.Values()
	var groups []settingGroup
	for _, f := range status.Fields {
		if len(groups) == 0 || groups[len(groups)-1].Name != f.Group {
			groups = append(groups, settingGroup{Name: f.Group})
		}
		v := strconv.Itoa(now[f.Key])
		if e, ok := entered[f.Key]; ok {
			v = e
		}
		g := &groups[len(groups)-1]
		g.Fields = append(g.Fields, settingField{f.Key, f.Label, f.Unit, v, strconv.Itoa(def[f.Key])})
	}
	return groups
}

func (s *Server) settingsPage(w http.ResponseWriter, msg string, entered map[string]string, saved bool, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	s.render(w, "settings.html", map[string]any{"Groups": settingGroups(s.cfg(), entered), "Error": msg, "Saved": saved})
}

func (s *Server) settingsShow(w http.ResponseWriter, r *http.Request) {
	s.settingsPage(w, "", nil, r.URL.Query().Get("saved") != "", http.StatusOK)
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "ungültiges Formular", http.StatusBadRequest)
		return
	}
	entered, vals := map[string]string{}, map[string]int{}
	for _, f := range status.Fields {
		raw, ok := r.PostForm[f.Key]
		if !ok { // nicht im Formular: Wert bleibt
			continue
		}
		entered[f.Key] = strings.TrimSpace(raw[0])
		n, err := strconv.Atoi(entered[f.Key])
		if err != nil {
			s.settingsPage(w, fmt.Sprintf("%s: keine ganze Zahl", f.Label), entered, false, http.StatusUnprocessableEntity)
			return
		}
		vals[f.Key] = n
	}
	s.settingsMu.Lock() // lesen, ändern, speichern als Einheit
	defer s.settingsMu.Unlock()
	cfg, err := s.cfg().With(vals)
	if err != nil {
		s.settingsPage(w, err.Error(), entered, false, http.StatusUnprocessableEntity)
		return
	}
	diff := cfg.Diff()
	if err := s.SaveSettings(cfg, diff); err != nil {
		log.Printf("settings: speichern: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	log.Printf("settings: Schwellwerte gespeichert (%d vom Standard abweichend)", len(diff))
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) settingsReset(w http.ResponseWriter, r *http.Request) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg := status.DefaultConfig()
	cfg.EOL = s.cfg().EOL // die Quelle der Support-Enden ist keine Einstellung
	if err := s.SaveSettings(cfg, nil); err != nil {
		log.Printf("settings: zurücksetzen: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	log.Print("settings: Schwellwerte auf die Standardwerte zurückgesetzt")
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// settingsExport liefert die Konfiguration (Agenten mit Token-Hash, Schwellwerte) als Download. POST, damit kein Link und kein
// fremder Seitenaufruf sie auslöst; die Datei ist so schützenswert wie die Datenbank.
func (s *Server) settingsExport(w http.ResponseWriter, r *http.Request) {
	f, err := backup.Export(s.Agents, s.cfg(), s.Now())
	if err != nil {
		log.Printf("settings: Export: %v", err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="sitewatch-`+f.ExportedAt.Format("2006-01-02")+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(f)
	log.Print("settings: Konfiguration exportiert")
}
