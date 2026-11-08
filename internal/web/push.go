package web

import (
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"sitewatch/internal/push"
	"sitewatch/internal/store"
)

// jsFS: Skripte werden als eigene Dateien ausgeliefert, damit die CSP kein 'unsafe-inline' für Skripte braucht.
//
//go:embed static/*.js
var jsFS embed.FS

// PushService ist der Web-Push-Versand (push.Sender); nil = Push ist nicht eingerichtet.
type PushService interface {
	PublicKey() string
	Add(store.PushSub) error
	Remove(endpoint string) error
	Count() (int, error)
	Send(title, body string) error
}

func script(name string) http.HandlerFunc {
	b, err := jsFS.ReadFile("static/" + name)
	if err != nil {
		panic(err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache") // der Browser prüft den Service Worker ohnehin selbst
		_, _ = w.Write(b)
	}
}

func (s *Server) pushRoutes(ui *http.ServeMux) {
	ui.HandleFunc("POST /push/subscribe", s.pushSubscribe)
	ui.HandleFunc("POST /push/unsubscribe", s.pushUnsubscribe)
	ui.HandleFunc("POST /push/test", s.pushTest)
}

func (s *Server) pushSubscribe(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var in struct {
		Endpoint string `json:"endpoint"`
		Keys     struct{ P256dh, Auth string }
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !push.ValidKeys(in.Keys.P256dh, in.Keys.Auth) || !push.ValidEndpoint(in.Endpoint) {
		http.Error(w, "ungültige Anmeldung", http.StatusBadRequest)
		return
	}
	if err := s.Push.Add(store.PushSub{Endpoint: in.Endpoint, P256dh: in.Keys.P256dh, Auth: in.Keys.Auth}); errors.Is(err, push.ErrTooMany) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	} else if err != nil {
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pushUnsubscribe löscht jeden Endpoint ohne Besitzprüfung: Alle Angemeldeten gehören zum selben Admin-Kreis.
func (s *Server) pushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	var in struct{ Endpoint string }
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Endpoint == "" {
		http.Error(w, "ungültige Anfrage", http.StatusBadRequest)
		return
	}
	if err := s.Push.Remove(in.Endpoint); err != nil {
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pushTest(w http.ResponseWriter, _ *http.Request) {
	s.mailMu.Lock() // gemeinsame Sperre mit der Testmail: höchstens eine Testnachricht je 10 s
	if s.Now().Sub(s.pushAt) < 10*time.Second {
		s.mailMu.Unlock()
		http.Error(w, "bitte kurz warten", http.StatusTooManyRequests)
		return
	}
	s.pushAt = s.Now()
	s.mailMu.Unlock()
	if err := s.Push.Send("Sitewatch: Testnachricht", "Push funktioniert."); err != nil {
		http.Error(w, "Senden fehlgeschlagen", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
