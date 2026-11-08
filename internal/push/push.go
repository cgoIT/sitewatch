// Package push verschickt Web-Push-Nachrichten (VAPID, RFC 8030/8292) an die Geräte, die sich im Cockpit angemeldet haben.
// Der Versand geht nur ausgehend von Sitewatch an den Push-Dienst des jeweiligen Browsers.
package push

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"sitewatch/internal/store"
)

// Subs ist der Speicher der Anmeldungen (store.SQLite).
type Subs interface {
	PushSubs() ([]store.PushSub, error)
	AddPushSub(store.PushSub) error
	DeletePushSub(endpoint string) error
}

// Sender verschickt an alle angemeldeten Geräte. Private und Public sind Base64 (URL-Variante ohne Auffüllung).
type Sender struct {
	Subs            Subs
	Private, Public string
	Subscriber      string                     // Kontaktadresse für den Push-Dienst: https-URL oder mailto:
	Client          *http.Client               // nil = Standard mit 10 s Timeout, ohne Weiterleitungen
	Allow           func(endpoint string) bool // nil = ValidEndpoint; nur für Tests ersetzbar
}

// allowed sind die Push-Dienste der gängigen Browser (Host selbst oder Unterdomäne); Sitewatch ruft nie einen anderen Endpoint auf
// (sonst ließe sich über eine angemeldete Sitzung ein beliebiger Server anstoßen).
var allowed = []string{"fcm.googleapis.com", "push.services.mozilla.com", "push.apple.com", "notify.windows.com"}

// MaxSubs begrenzt die Zahl der Geräte, damit der Versand überschaubar bleibt.
const MaxSubs = 20

// ErrTooMany meldet, dass MaxSubs erreicht ist.
var ErrTooMany = errors.New("zu viele angemeldete Geräte")

// ValidEndpoint prüft, dass der Endpoint https ist, höchstens 2 KB lang und zu einem bekannten Push-Dienst gehört.
func ValidEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, s := range allowed {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// ValidKeys prüft Länge und Format der Schlüssel des Browsers (p256dh: 65 Byte, auth: 16 Byte, Base64 URL-Variante).
func ValidKeys(p256dh, auth string) bool {
	k, e1 := base64.RawURLEncoding.DecodeString(strings.TrimRight(p256dh, "="))
	a, e2 := base64.RawURLEncoding.DecodeString(strings.TrimRight(auth, "="))
	return e1 == nil && e2 == nil && len(k) == 65 && len(a) == 16
}

// LoadOrCreateKey liest den privaten VAPID-Schlüssel (Base64 der 32 Byte, chmod 600) oder legt ihn neu an.
// Ein Wechsel des Schlüssels macht alle Anmeldungen ungültig; die Geräte müssen sich neu anmelden.
func LoadOrCreateKey(path string) (priv, pub string, err error) {
	b, err := os.ReadFile(path)
	var k *ecdh.PrivateKey
	switch {
	case errors.Is(err, os.ErrNotExist):
		if k, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
			return "", "", err
		}
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", "", err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) { // ein gleichzeitiger Start war schneller
			return LoadOrCreateKey(path)
		}
		if err != nil {
			return "", "", err
		}
		_, werr := f.WriteString(base64.RawURLEncoding.EncodeToString(k.Bytes()) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil { // keine halbe Datei zurücklassen, sonst bricht der nächste Start ab
			_ = os.Remove(path)
			return "", "", werr
		}
	case err != nil:
		return "", "", err
	default:
		raw, derr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil {
			return "", "", errors.New("VAPID-Schlüssel ist kein Base64")
		}
		if k, err = ecdh.P256().NewPrivateKey(raw); err != nil {
			return "", "", err
		}
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Send schickt an alle Geräte (höchstens 5 gleichzeitig). Versand ist Best-Effort: Fehler einzelner Geräte stehen im Log und führen nie
// zu einem Wiederholen des Alarms (sonst bekämen die übrigen Geräte ihn doppelt). Abgemeldete Geräte (404/410) werden gelöscht.
func (p *Sender) Send(title, body string) error {
	subs, err := p.Subs.PushSubs()
	if err != nil {
		log.Printf("push: Anmeldungen lesen: %v", err)
		return err
	}
	payload, _ := json.Marshal(map[string]string{"title": title, "body": body, "url": "/"})
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	allow := p.Allow
	if allow == nil {
		allow = ValidEndpoint
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, s := range subs {
		if !allow(s.Endpoint) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			p.one(c, s, append([]byte(nil), payload...)) // webpush-go verändert den Puffer beim Verschlüsseln
		}()
	}
	wg.Wait()
	return nil
}

func (p *Sender) one(c *http.Client, s store.PushSub, payload []byte) {
	resp, err := webpush.SendNotification(payload, &webpush.Subscription{Endpoint: s.Endpoint, Keys: webpush.Keys{P256dh: s.P256dh, Auth: s.Auth}},
		&webpush.Options{Subscriber: p.Subscriber, VAPIDPublicKey: p.Public, VAPIDPrivateKey: p.Private, TTL: 3600, Urgency: webpush.UrgencyHigh, HTTPClient: c})
	if err != nil {
		log.Printf("push: Senden fehlgeschlagen: %v", err)
		return
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		if err := p.Subs.DeletePushSub(s.Endpoint); err != nil {
			log.Printf("push: abgemeldetes Gerät löschen: %v", err)
		}
	case resp.StatusCode >= 300:
		why, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("push: Push-Dienst antwortet %d: %s", resp.StatusCode, strings.TrimSpace(string(why)))
	}
}

func (p *Sender) PublicKey() string { return p.Public }

// Add meldet ein Gerät an (ein bekannter Endpoint wird ersetzt); ab MaxSubs Geräten gibt es ErrTooMany.
func (p *Sender) Add(s store.PushSub) error {
	subs, err := p.Subs.PushSubs()
	if err != nil {
		return err
	}
	for _, o := range subs {
		if o.Endpoint == s.Endpoint {
			return p.Subs.AddPushSub(s)
		}
	}
	if len(subs) >= MaxSubs {
		return ErrTooMany
	}
	return p.Subs.AddPushSub(s)
}

func (p *Sender) Remove(endpoint string) error { return p.Subs.DeletePushSub(endpoint) }
func (p *Sender) Count() (int, error)          { s, err := p.Subs.PushSubs(); return len(s), err }
