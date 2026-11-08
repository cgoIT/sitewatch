package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sitewatch/internal/store"
)

// Manifest und Symbol müssen auch hinter dem Login erreichbar sein; die Fußzeile zeigt die Version.
func TestManifestOhneLoginUndFusszeile(t *testing.T) {
	srv, _ := setupAgents(t)
	srv.Protect = func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "login", http.StatusUnauthorized) })
	}
	srv.Version = "1.2.3"
	h := srv.Handler()
	for _, p := range []string{"/manifest.webmanifest", "/icon.svg", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if !json.Valid([]byte(manifestJSON)) {
		t.Error("Manifest ist kein gültiges JSON")
	}
	srv.Protect = nil
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if b := w.Body.String(); !strings.Contains(b, "Sitewatch 1.2.3") || !strings.Contains(b, `rel="manifest"`) {
		t.Error("Fußzeile oder Manifest-Link fehlt")
	}
	if v := srv.versionText(); !strings.HasPrefix(v, "1.2.3") {
		t.Errorf("versionText = %q", v)
	}
}

func TestTestMail(t *testing.T) {
	srv, _ := setupAgents(t)
	n := 0
	srv.TestMail = func() error { n++; return nil }
	h := srv.Handler()
	get := func(m, p string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(m, p, nil))
		return w
	}
	if b := get("GET", "/").Body.String(); !strings.Contains(b, "Testmail senden") {
		t.Error("Knopf fehlt")
	}
	if w := get("POST", "/alert-test"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/?mail=ok" || n != 1 {
		t.Errorf("erster Versand: %d %s n=%d", w.Code, w.Header().Get("Location"), n)
	}
	if w := get("POST", "/alert-test"); w.Header().Get("Location") != "/?mail=wait" || n != 1 {
		t.Errorf("zweiter Versand sofort: %s n=%d", w.Header().Get("Location"), n)
	}
	if b := get("GET", "/?mail=ok").Body.String(); !strings.Contains(b, "Testmail wurde versendet") {
		t.Error("Meldung fehlt")
	}
}

type fakePush struct{ subs map[string]store.PushSub }

func (f *fakePush) PublicKey() string         { return "KEY" }
func (f *fakePush) Add(s store.PushSub) error { f.subs[s.Endpoint] = s; return nil }
func (f *fakePush) Remove(e string) error     { delete(f.subs, e); return nil }
func (f *fakePush) Count() (int, error)       { return len(f.subs), nil }
func (f *fakePush) Send(_, _ string) error    { return nil }

// Service Worker ohne Login erreichbar, Anmeldung nur mit gültigem Push-Endpoint, Bereich in den Einstellungen nur mit Push.
func TestPushRoutenUndEinstellungen(t *testing.T) {
	srv, _ := setupAgents(t)
	k := base64.RawURLEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...))
	a := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	f := &fakePush{subs: map[string]store.PushSub{}}
	srv.Push = f
	srv.Protect = func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "login", http.StatusUnauthorized) })
	}
	h := srv.Handler()
	for _, p := range []string{"/sw.js", "/push.js"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
			t.Errorf("%s: %d %s", p, w.Code, w.Header().Get("Content-Type"))
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Error("CSP ohne script-src")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/push/subscribe", strings.NewReader("{}")))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Anmeldung ohne Login: %d", w.Code)
	}

	srv.Protect = nil
	h = srv.Handler()
	post := func(path, body string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return w.Code
	}
	if c := post("/push/subscribe", `{"endpoint":"https://evil.example/x","keys":{"p256dh":"`+k+`","auth":"`+a+`"}}`); c != 400 || len(f.subs) != 0 {
		t.Errorf("fremder Endpoint: %d", c)
	}
	if c := post("/push/subscribe", `{"endpoint":"https://fcm.googleapis.com/x","keys":{"p256dh":"a","auth":"b"}}`); c != 400 || len(f.subs) != 0 {
		t.Errorf("kaputte Schlüssel: %d", c)
	}
	ok := `{"endpoint":"https://fcm.googleapis.com/fcm/send/x","keys":{"p256dh":"` + k + `","auth":"` + a + `"}}`
	if c := post("/push/subscribe", ok); c != 204 || len(f.subs) != 1 {
		t.Errorf("gültige Anmeldung: %d", c)
	}
	if c := post("/push/unsubscribe", `{"endpoint":"https://fcm.googleapis.com/fcm/send/x"}`); c != 204 || len(f.subs) != 0 {
		t.Errorf("Abmeldung: %d", c)
	}
	if c := post("/push/test", ""); c != 204 {
		t.Errorf("Testnachricht: %d", c)
	}
	if c := post("/push/test", ""); c != http.StatusTooManyRequests {
		t.Errorf("zweite Testnachricht sofort: %d", c)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/settings", nil))
	if !strings.Contains(w.Body.String(), `data-key="KEY"`) {
		t.Error("Push-Bereich fehlt in den Einstellungen")
	}
	srv.Push = nil
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/settings", nil))
	if strings.Contains(w.Body.String(), "Push-Nachrichten") {
		t.Error("Push-Bereich ohne Push")
	}
}
