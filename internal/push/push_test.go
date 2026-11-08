package push

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sitewatch/internal/store"
)

func TestValidEndpoint(t *testing.T) {
	for u, want := range map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc":                 true,
		"https://updates.push.services.mozilla.com/wpush/v2/x":    true,
		"https://web.push.apple.com/Qx":                           true,
		"http://fcm.googleapis.com/x":                             false,
		"https://evil.example/x":                                  false,
		"https://fcm.googleapis.com.evil.example/x":               false,
		"https://127.0.0.1/x":                                     false,
		"https://storage.googleapis.com/x":                        false,
		"https://fcm.googleapis.com/" + strings.Repeat("a", 2100): false,
		"https://fcm.googleapis.com:8443/x":                       false,
		"https://u:p@fcm.googleapis.com/x":                        false,
	} {
		if got := ValidEndpoint(u); got != want {
			t.Errorf("%s: %v, erwartet %v", u, got, want)
		}
	}
}

func TestKeyBleibtStabil(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "vapid.key")
	priv, pub, err := LoadOrCreateKey(p)
	if err != nil || priv == "" || pub == "" {
		t.Fatal(priv, pub, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("Rechte %v", fi.Mode())
	}
	priv2, pub2, err := LoadOrCreateKey(p)
	if err != nil || priv != priv2 || pub != pub2 {
		t.Error("Schlüssel ändert sich beim zweiten Laden")
	}
	_ = os.WriteFile(p, []byte("müll"), 0o600)
	if _, _, err := LoadOrCreateKey(p); err == nil {
		t.Error("kaputte Datei akzeptiert")
	}
}

type fakeSubs struct {
	mu   sync.Mutex
	subs []store.PushSub
}

func (f *fakeSubs) PushSubs() ([]store.PushSub, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.PushSub(nil), f.subs...), nil
}
func (f *fakeSubs) AddPushSub(s store.PushSub) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, s)
	return nil
}
func (f *fakeSubs) DeletePushSub(e string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.subs {
		if s.Endpoint == e {
			f.subs = append(f.subs[:i], f.subs[i+1:]...)
			break
		}
	}
	return nil
}

func testKeys(t *testing.T) (p256dh, auth string) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 16)
	_, _ = rand.Read(a)
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(a)
}

func TestValidKeys(t *testing.T) {
	k, a := testKeys(t)
	if !ValidKeys(k, a) {
		t.Error("gültige Schlüssel abgelehnt")
	}
	for _, c := range [][2]string{{"", ""}, {"a", "b"}, {k, "b"}, {a, a}, {k + "!", a}} {
		if ValidKeys(c[0], c[1]) {
			t.Errorf("%q akzeptiert", c)
		}
	}
}

// 201 bleibt, 404 und 410 löschen die Anmeldung, 500 wird nur geloggt, ein nicht erlaubter Endpoint wird übersprungen.
func TestSendBehandeltAntworten(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(201)
		case "/gone":
			w.WriteHeader(410)
		case "/missing":
			w.WriteHeader(404)
		default:
			http.Error(w, "kaputt", 500)
		}
	}))
	defer srv.Close()
	k, a := testKeys(t)
	subs := &fakeSubs{}
	for _, p := range []string{"/ok", "/gone", "/missing", "/boom", "/skip"} {
		subs.subs = append(subs.subs, store.PushSub{Endpoint: srv.URL + p, P256dh: k, Auth: a})
	}
	priv, pub, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "v.key"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Sender{Subs: subs, Private: priv, Public: pub, Subscriber: "https://sitewatch.example", Client: srv.Client(),
		Allow: func(e string) bool { return !strings.HasSuffix(e, "/skip") }}
	if err := s.Send("t", "b"); err != nil {
		t.Fatal(err)
	}
	left, _ := subs.PushSubs()
	mu.Lock()
	defer mu.Unlock()
	if len(left) != 3 { // ok, boom und skip bleiben
		t.Errorf("übrig: %+v", left)
	}
	if hits["/skip"] != 0 || hits["/ok"] != 1 || hits["/gone"] != 1 || hits["/boom"] != 1 {
		t.Errorf("Aufrufe: %v", hits)
	}
}

func TestAddBegrenzt(t *testing.T) {
	subs := &fakeSubs{}
	s := &Sender{Subs: subs}
	for i := range MaxSubs {
		if err := s.Add(store.PushSub{Endpoint: "https://fcm.googleapis.com/" + strings.Repeat("x", i+1)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Add(store.PushSub{Endpoint: "https://fcm.googleapis.com/neu"}); err != ErrTooMany {
		t.Errorf("Grenze nicht erreicht: %v", err)
	}
	if err := s.Add(store.PushSub{Endpoint: "https://fcm.googleapis.com/x"}); err != nil { // bekannter Endpoint wird ersetzt
		t.Errorf("bekannter Endpoint: %v", err)
	}
}
