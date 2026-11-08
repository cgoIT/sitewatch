package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sitewatch/internal/store"
)

var (
	pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 30)...)
	icoBytes = append([]byte("\x00\x00\x01\x00"), make([]byte, 30)...)
)

func TestFaviconFromLinkAndFallback(t *testing.T) {
	p, _, srv, _ := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// apple-touch-icon zählt nicht; das erste echte Icon ist relativ angegeben, mit Entity im Pfad
			w.Write([]byte(`<html><head><link rel="apple-touch-icon" href="/a.png"><LINK HREF='/img/x.png?a=1&amp;b=2' REL="shortcut icon"></head>`))
		case "/img/x.png":
			if r.URL.RawQuery != "a=1&b=2" {
				http.NotFound(w, r)
				return
			}
			w.Write(pngBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	data, ct, err := p.Favicon(context.Background(), srv.URL)
	if err != nil || ct != "image/png" || len(data) != len(pngBytes) {
		t.Fatalf("link: %q %v", ct, err)
	}

	p, _, srv, _ = setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write(icoBytes)
			return
		}
		w.Write([]byte("<html>ohne Icon-Angabe"))
	}))
	if _, ct, err := p.Favicon(context.Background(), srv.URL); err != nil || ct != "image/x-icon" {
		t.Errorf("favicon.ico: %q %v", ct, err)
	}
}

func TestFaviconRejects(t *testing.T) {
	big := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, faviconMax)...)
	for name, h := range map[string]http.HandlerFunc{
		"HTML statt Bild": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>kein Bild")) },
		"SVG": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
		},
		"zu groß":     func(w http.ResponseWriter, r *http.Request) { w.Write(big) },
		"Fehlerseite": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "weg", 500) },
	} {
		p, _, srv, _ := setup(t, h)
		if _, _, err := p.Favicon(context.Background(), srv.URL); err == nil {
			t.Errorf("%s: erwartet Fehler", name)
		}
	}
	p, _, _, _ := setup(t, http.NotFoundHandler())
	if _, _, err := p.Favicon(context.Background(), "http://example.org"); err == nil {
		t.Error("http-Adresse ohne Fehler")
	}
}

func TestFaviconRedirects(t *testing.T) {
	var other atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1); w.Write(pngBytes) }))
	defer foreign.Close()
	var hops atomic.Int32
	p, _, srv, _ := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico": // gleiche Site: erlaubt
			http.Redirect(w, r, "/real.ico", http.StatusMovedPermanently)
		case "/real.ico":
			w.Write(icoBytes)
		case "/", "/fremd":
			w.Write([]byte(`<link rel="icon" href="/fremd.ico">`))
		case "/fremd.ico": // andere Site (anderer Host): nicht folgen
			http.Redirect(w, r, foreign.URL+"/x.png", http.StatusFound)
		case "/loop":
			hops.Add(1)
			http.Redirect(w, r, "/loop", http.StatusFound)
		}
	}))
	// Das Link-Icon leitet fremd weiter und scheitert, danach greift /favicon.ico, das innerhalb der Site weiterleitet.
	if _, ct, err := p.Favicon(context.Background(), srv.URL); err != nil || ct != "image/x-icon" {
		t.Fatalf("Weiterleitung innerhalb der Site: %q %v", ct, err)
	}
	if other.Load() != 0 {
		t.Error("Weiterleitung auf einen fremden Host wurde befolgt")
	}
	// Endlosschleife bricht ab (höchstens maxRedirects Sprünge)
	u, _ := url.Parse(srv.URL)
	if _, _, err := fetch(context.Background(), p.iconClient(u), srv.URL+"/loop", 100, false); err == nil || hops.Load() > maxRedirects+2 {
		t.Errorf("Schleife: err=%v, %d Aufrufe", err, hops.Load())
	}
}

func TestSameSite(t *testing.T) {
	u := func(s string) *url.URL { x, _ := url.Parse(s); return x }
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://example.org", "https://www.example.org/x", true},
		{"https://www.example.org", "https://EXAMPLE.org:443/", true},
		{"https://example.org", "https://cdn.example.org", false},
		{"https://example.org", "https://example.org:8443", false},
		{"https://example.org", "https://example.org.evil.test", false},
	} {
		if got := sameSite(u(c.a), u(c.b)); got != c.want {
			t.Errorf("%s ~ %s: %v", c.a, c.b, got)
		}
	}
}

func TestFaviconsOnce(t *testing.T) {
	var hits atomic.Int32
	p, st, srv, now := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			hits.Add(1)
			w.Write(icoBytes)
			return
		}
		w.Write([]byte("<html>"))
	}))
	p.Favicons = st
	cur := now
	p.Now = func() time.Time { return cur }
	p.faviconsOnce(context.Background())
	f, ok, err := st.GetFavicon("kunde-b")
	if err != nil || !ok || f.Type != "image/x-icon" || f.URL != srv.URL || !f.Fetched.Equal(now) {
		t.Fatalf("gespeichert: %+v %v %v", f, ok, err)
	}
	cur = now.Add(time.Hour)
	p.faviconsOnce(context.Background())
	if hits.Load() != 1 {
		t.Errorf("innerhalb von 24 Stunden darf nichts neu geholt werden (%d Abrufe)", hits.Load())
	}
	cur = now.Add(25 * time.Hour)
	p.faviconsOnce(context.Background())
	if hits.Load() != 2 {
		t.Errorf("nach 24 Stunden wird neu geholt (%d Abrufe)", hits.Load())
	}
	if m, _ := st.FaviconMeta(); len(m) != 1 || len(m["kunde-b"].Data) != 0 {
		t.Errorf("FaviconMeta liefert keine Daten: %+v", m)
	}
	if err := st.DeleteSite("kunde-b"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetFavicon("kunde-b"); ok {
		t.Error("DeleteSite muss das Symbol entfernen")
	}
}

func TestFaviconForeignAndDowngrade(t *testing.T) {
	var other atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1); w.Write(pngBytes) }))
	defer foreign.Close()
	p, _, srv, _ := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/": // Symbole auf fremden Hosts, per Protokoll-relativer Adresse und mit Userinfo, werden nicht geholt
			w.Write([]byte(`<link rel=icon href="` + foreign.URL + `/a.png"><link rel="icon" href="//` + strings.TrimPrefix(foreign.URL, "https://") + `/b.png">` +
				`<link rel="icon" href="https://example.org@` + strings.TrimPrefix(foreign.URL, "https://") + `/c.png"><link rel="icon" href="   ">`))
		case "/favicon.ico":
			http.Redirect(w, r, "http://"+r.Host+"/real.ico", http.StatusFound) // Downgrade auf http
		}
	}))
	if _, _, err := p.Favicon(context.Background(), srv.URL); err == nil {
		t.Error("erwartet Fehler")
	}
	if other.Load() != 0 {
		t.Errorf("fremder Host wurde %d-mal aufgerufen", other.Load())
	}
}

func TestFaviconsOnceStaleAndOrphan(t *testing.T) {
	icon := true
	p, st, srv, now := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" && icon {
			w.Write(icoBytes)
			return
		}
		http.NotFound(w, r)
	}))
	p.Favicons = st
	// Symbol einer früheren Adresse und das einer Site, die es nicht mehr gibt
	st.SetFavicon("kunde-b", store.Favicon{Data: icoBytes, Type: "image/x-icon", URL: "https://alt.example", Fetched: now})
	st.SetFavicon("verwaist", store.Favicon{Data: icoBytes, Type: "image/x-icon", URL: srv.URL, Fetched: now})
	icon = false
	p.faviconsOnce(context.Background())
	if m, _ := st.FaviconMeta(); len(m) != 0 {
		t.Errorf("veraltetes und verwaistes Symbol müssen weg sein: %v", m)
	}
	icon = true
	p.Now = func() time.Time { return now.Add(7 * time.Hour) } // Wiederholung nach dem Fehlschlag (6 Stunden)
	p.faviconsOnce(context.Background())
	if f, ok, _ := st.GetFavicon("kunde-b"); !ok || f.URL != srv.URL {
		t.Errorf("Symbol wurde nicht neu geholt: %+v %v", f, ok)
	}
}
