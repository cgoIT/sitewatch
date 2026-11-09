package probe

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sitewatch/internal/idn"
	"strings"
	"time"

	"sitewatch/internal/store"
)

// Favicon: Sitewatch holt das Symbol jeder Site selbst (die Oberfläche darf keine fremden Bilder laden: CSP, und der Browser
// würde die IP des Betrachters an die Kundenseite senden). Schranken wie beim Ping (https, 10 s, keine internen Ziele), nur mit einer
// Ausnahme: Weiterleitungen sind erlaubt, höchstens 3, nur nach https und nur innerhalb derselben Site (gleicher Host, "www." egal).
const (
	faviconMax   = 128 << 10 // Größe des Bildes
	pageMax      = 64 << 10  // so viel der Startseite wird nach <link rel="icon"> durchsucht
	faviconTTL   = 24 * time.Hour
	faviconRetry = 6 * time.Hour // nach einem Fehlschlag, solange kein Symbol da ist
	maxRedirects = 3
	maxCands     = 4
)

var (
	linkRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	attrRe = regexp.MustCompile(`(?is)([a-z][a-z0-9-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s>"']+)`)
)

// sameSite: gleicher Host (ein "www." davor zählt nicht) und gleicher Port.
func sameSite(a, b *url.URL) bool {
	host := func(u *url.URL) string {
		return strings.TrimPrefix(strings.ToLower(idn.ASCIIHost(u.Hostname())), "www.")
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		return "443"
	}
	return host(a) == host(b) && port(a) == port(b)
}

func (p *Prober) iconClient(origin *url.URL) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: p.dialer().DialContext, TLSClientConfig: p.tlsConfig, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects || req.URL.Scheme != "https" || !sameSite(origin, req.URL) {
				return http.ErrUseLastResponse // die 3xx-Antwort gilt als Fehlschlag
			}
			return nil
		},
	}
}

// fetch lädt eine Adresse (nur Status 200) und liest höchstens limit Bytes; mit trunc wird zu langer Inhalt gekürzt, sonst ist er ein Fehler.
func fetch(ctx context.Context, c *http.Client, raw string, limit int, trunc bool) ([]byte, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Sitewatch-Favicon")
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("HTTP " + resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > limit {
		if !trunc {
			return nil, nil, errors.New("zu groß")
		}
		data = data[:limit]
	}
	return data, resp.Request.URL, nil
}

// shortcut: Regex statt HTML-Parser; ein ">" im Attributwert, doppelte Attribute, <base> und Kommentare werden nicht beachtet. Bei falschen
// Treffern golang.org/x/net/html ergänzen.
// iconLinks liefert die Adressen aus <link rel="icon"> und <link rel="shortcut icon"> (nicht apple-touch-icon), in der Reihenfolge der Seite.
func iconLinks(page []byte, base *url.URL) []string {
	var out []string
	for _, tag := range linkRe.FindAll(page, -1) {
		var rel, href string
		for _, m := range attrRe.FindAllSubmatch(tag, -1) {
			v := html.UnescapeString(strings.Trim(string(m[2]), `"'`))
			switch strings.ToLower(string(m[1])) {
			case "rel":
				rel = v
			case "href":
				href = v
			}
		}
		isIcon := false
		for _, tok := range strings.Fields(strings.ToLower(rel)) {
			isIcon = isIcon || tok == "icon"
		}
		href = strings.TrimSpace(href)
		if ref, err := url.Parse(href); isIcon && err == nil && href != "" {
			out = append(out, base.ResolveReference(ref).String())
		}
	}
	return out
}

// sniffImage erkennt das Format am Inhalt (nie am Header der Fremdseite). SVG fehlt mit Absicht: es kann Skripte enthalten.
func sniffImage(b []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png", true
	case bytes.HasPrefix(b, []byte("\x00\x00\x01\x00")) && len(b) >= 22:
		return "image/x-icon", true
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "image/gif", true
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return "image/jpeg", true
	}
	return "", false
}

// Favicon holt das Symbol der Site unter raw (https): erst die <link>-Angaben der Startseite, dann /favicon.ico.
// shortcut: Symbole auf einem anderen Host (CDN) werden nicht geholt; bei Bedarf eine Allowlist ergänzen.
func (p *Prober) Favicon(ctx context.Context, raw string) (data []byte, ctype string, err error) {
	u, _, err := target(raw)
	if err != nil {
		return nil, "", err
	}
	c := p.iconClient(u)
	base := u
	var cands []string
	if page, final, err := fetch(ctx, c, raw, pageMax, true); err == nil {
		base = final
		cands = iconLinks(page, final)
	}
	cands = append(cands[:min(len(cands), maxCands-1)], base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String())
	for _, cand := range cands {
		cu, _, err := target(cand)
		if err != nil || !sameSite(u, cu) {
			continue
		}
		b, _, err := fetch(ctx, c, cand, faviconMax, false)
		if err != nil {
			continue
		}
		if ct, ok := sniffImage(b); ok {
			return b, ct, nil
		}
	}
	return nil, "", errors.New("kein Favicon gefunden")
}

// RunFavicons prüft alle 10 Minuten, bei welchen Sites das Symbol fällig ist. Ohne p.Favicons tut es nichts.
// shortcut: seriell; bei vielen Sites mit hängenden Servern dauert ein Durchlauf länger, dann je Site nebenläufig.
func (p *Prober) RunFavicons(ctx context.Context) {
	if p.Favicons == nil {
		return
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		p.faviconsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Prober) faviconsOnce(ctx context.Context) {
	as, err := p.Agents.List()
	if err != nil {
		log.Printf("favicon: %v", err)
		return
	}
	meta, err := p.Favicons.FaviconMeta()
	if err != nil {
		log.Printf("favicon: %v", err)
		return
	}
	now := p.Now()
	active := map[string]bool{}
	for _, a := range as {
		for _, st := range a.Config.Sites {
			if _, _, err := target(st.URL); err != nil || active[st.ID] {
				continue
			}
			active[st.ID] = true
			m, has := meta[st.ID]
			stale := has && m.URL != st.URL // Symbol gehört zu einer früheren Adresse
			wait, last := faviconRetry, time.Time{}
			if has && !stale {
				wait, last = faviconTTL, m.Fetched
			}
			p.mu.Lock()
			if t := p.favTry[st.ID]; t.After(last) {
				last = t
			}
			due := now.Sub(last) >= wait
			if due {
				if p.favTry == nil {
					p.favTry = map[string]time.Time{}
				}
				p.favTry[st.ID] = now
			}
			p.mu.Unlock()
			if !due {
				continue
			}
			fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			data, ct, err := p.Favicon(fctx, st.URL)
			cancel()
			if err != nil {
				log.Printf("favicon: %q: %v", st.ID, err)
			}
			switch {
			case err == nil:
				if err := p.Favicons.SetFavicon(st.ID, store.Favicon{Data: data, Type: ct, URL: st.URL, Fetched: now}); err != nil {
					log.Printf("favicon: %q speichern: %v", st.ID, err)
				}
			case stale: // lieber kein Symbol als das einer anderen Adresse
				if err := p.Favicons.DeleteFavicon(st.ID); err != nil {
					log.Printf("favicon: %q löschen: %v", st.ID, err)
				}
			}
		}
	}
	p.mu.Lock()
	for id := range p.favTry {
		if !active[id] {
			delete(p.favTry, id)
		}
	}
	p.mu.Unlock()
	// Gelöschte Sites. Nur bei nicht leerer Agentenliste, damit ein leerer Zwischenstand nicht alle Symbole löscht.
	// (Wird währenddessen eine Site gelöscht, kann ihr Symbol noch einmal geschrieben werden; der nächste Durchlauf räumt es auf.)
	for id := range meta {
		if !active[id] && len(as) > 0 {
			if err := p.Favicons.DeleteFavicon(id); err != nil {
				log.Printf("favicon: %q löschen: %v", id, err)
			}
		}
	}
}
