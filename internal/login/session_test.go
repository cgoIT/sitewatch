package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newSessions(t *testing.T) (*Sessions, *time.Time) {
	t.Helper()
	s, err := NewSessions([]byte(strings.Repeat("k", 32)), time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, &now
}

func issue(s *Sessions) *http.Cookie {
	rec := httptest.NewRecorder()
	s.Set(rec, Identity{Subject: "u1", Email: "a@example.org", Groups: []string{"sitewatch"}})
	return rec.Result().Cookies()[0]
}

func reqWith(c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestSessionRoundtripAndAttributes(t *testing.T) {
	s, _ := newSessions(t)
	c := issue(s)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge != 3600 {
		t.Errorf("Cookie-Attribute: %+v", c)
	}
	id, ok := s.Get(reqWith(c))
	if !ok || id.Subject != "u1" || id.Groups[0] != "sitewatch" {
		t.Fatalf("Get: %+v %v", id, ok)
	}
}

func TestSessionRejects(t *testing.T) {
	s, now := newSessions(t)
	c := issue(s)

	p, sig, _ := strings.Cut(c.Value, ".")
	tampered := &http.Cookie{Name: c.Name, Value: p + "x." + sig}
	if _, ok := s.Get(reqWith(tampered)); ok {
		t.Error("manipulierte Nutzdaten akzeptiert")
	}
	if _, ok := s.Get(reqWith(&http.Cookie{Name: c.Name, Value: p})); ok {
		t.Error("ohne Signatur akzeptiert")
	}
	other, _ := NewSessions([]byte(strings.Repeat("z", 32)), time.Hour, true)
	other.Now = s.Now
	if _, ok := other.Get(reqWith(c)); ok {
		t.Error("fremder Schlüssel akzeptiert")
	}
	if _, ok := s.Get(reqWith(nil)); ok {
		t.Error("ohne Cookie akzeptiert")
	}
	*now = now.Add(time.Hour)
	if _, ok := s.Get(reqWith(c)); ok {
		t.Error("abgelaufene Sitzung akzeptiert")
	}
}

func TestNewSessionsValidates(t *testing.T) {
	if _, err := NewSessions([]byte("kurz"), time.Hour, true); err == nil {
		t.Error("kurzer Schlüssel akzeptiert")
	}
	if _, err := NewSessions([]byte(strings.Repeat("k", 32)), 0, true); err == nil {
		t.Error("TTL 0 akzeptiert")
	}
}

func TestRequire(t *testing.T) {
	s, _ := newSessions(t)
	h := s.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWith(nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonym GET: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonym POST: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqWith(issue(s)))
	if rec.Code != http.StatusNoContent {
		t.Errorf("angemeldet: %d", rec.Code)
	}
}

func TestSessionAllowRechecked(t *testing.T) {
	s, _ := newSessions(t)
	c := issue(s)
	s.Allow = func(id Identity) bool { return id.Subject != "u1" }
	if _, ok := s.Get(reqWith(c)); ok {
		t.Error("entzogener Zugriff gilt weiter")
	}
}

func TestLogoutClearsCookieWithoutRedirect(t *testing.T) {
	s, _ := newSessions(t)
	rec := httptest.NewRecorder()
	s.Logout(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("kein Redirect erwartet: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == sessionCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("Cookie nicht gelöscht")
	}
}

// Wer die Seite nutzt, bleibt angemeldet: Require verlängert das Cookie, aber nicht bei jedem Aufruf.
func TestSessionGleitendeLaufzeit(t *testing.T) {
	s, now := newSessions(t)
	s.ttl = 30 * 24 * time.Hour
	c := issue(s)
	h := s.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWith(c))
	if len(rec.Result().Cookies()) != 0 {
		t.Error("direkt nach dem Login darf nicht erneut gesetzt werden")
	}
	*now = now.Add(10 * 24 * time.Hour)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqWith(c))
	cs := rec.Result().Cookies()
	if len(cs) != 1 {
		t.Fatal("Cookie nicht verlängert")
	}
	*now = now.Add(25 * 24 * time.Hour) // alt wäre abgelaufen (35 Tage), das verlängerte gilt noch
	if _, ok := s.Get(reqWith(c)); ok {
		t.Error("altes Cookie sollte abgelaufen sein")
	}
	if _, ok := s.Get(reqWith(cs[0])); !ok {
		t.Error("verlängertes Cookie sollte gelten")
	}
}

// Höchstalter ab dem Login, abgelaufene Cookies werden nicht verlängert, entzogene Rechte wirken auch nach einer Verlängerung.
func TestSessionHoechstalterUndAllow(t *testing.T) {
	s, now := newSessions(t)
	s.ttl = 30 * 24 * time.Hour
	c := issue(s)
	h := s.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for i := 0; i < 7; i++ { // alle 12 Tage genutzt (84 Tage): gleitend verlängert
		*now = now.Add(12 * 24 * time.Hour)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqWith(c))
		if cs := rec.Result().Cookies(); len(cs) == 1 {
			c = cs[0]
		}
	}
	if _, ok := s.Get(reqWith(c)); !ok {
		t.Fatal("nach 84 Tagen mit Nutzung muss die Sitzung gelten")
	}
	*now = now.Add(12 * 24 * time.Hour) // 96 Tage seit dem Login
	if _, ok := s.Get(reqWith(c)); ok {
		t.Error("Höchstalter überschritten, Sitzung gilt trotzdem")
	}

	s2, now2 := newSessions(t)
	s2.ttl = 30 * 24 * time.Hour
	old := issue(s2)
	*now2 = now2.Add(31 * 24 * time.Hour)
	rec := httptest.NewRecorder()
	s2.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, reqWith(old))
	if rec.Code != http.StatusFound || len(rec.Result().Cookies()) != 0 {
		t.Errorf("abgelaufen: %d, Cookies %d", rec.Code, len(rec.Result().Cookies()))
	}

	s3, now3 := newSessions(t)
	s3.ttl = 30 * 24 * time.Hour
	c3 := issue(s3)
	*now3 = now3.Add(10 * 24 * time.Hour)
	rec = httptest.NewRecorder()
	s3.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, reqWith(c3))
	renewed := rec.Result().Cookies()[0]
	s3.Allow = func(Identity) bool { return false }
	if _, ok := s3.Get(reqWith(renewed)); ok {
		t.Error("entzogene Rechte wirken nach der Verlängerung nicht")
	}
}
