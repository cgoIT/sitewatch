// Package probe prüft von Sitewatch aus die öffentlichen Seiten der Contao-Bundles: Es liest das Ablaufdatum des TLS-Zertifikats
// und ruft die Seite auf ("Weckruf"), wenn der Report überfällig ist, damit der Contao-Cron auch bei wenig Besuchern läuft.
//
// Der Aufruf trägt keine Daten und keine Aufträge; der Report geht weiterhin vom Bundle zu Sitewatch. Adressen kommen nur aus der
// Konfiguration des Agenten (nie aus Reports), müssen https sein und dürfen nicht auf interne Adressen zeigen.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/report"
	"sitewatch/internal/status"
	"sitewatch/internal/store"
)

const (
	timeout      = 10 * time.Second
	tlsEvery     = 6 * time.Hour
	pingMinSpace = 15 * time.Minute // so selten höchstens, auch wenn der Report überfällig bleibt
)

// Prober führt die Prüfungen aus und merkt sich das Ablaufdatum der Zertifikate (im Arbeitsspeicher; nach einem Neustart
// wird es mit dem ersten Durchlauf neu ermittelt).
type Prober struct {
	Agents   *agents.Store
	Store    store.Store
	Settings *status.Settings
	Now      func() time.Time
	// AllowInternal erlaubt Ziele in privaten und lokalen Netzen; nur für Tests.
	AllowInternal bool
	tlsConfig     *tls.Config // nur für Tests (selbstsigniertes Zertifikat des Testservers)

	mu       sync.Mutex
	expires  map[string]time.Time // Site-ID → Ablauf des Zertifikats
	checked  map[string]time.Time // Site-ID → letzte Zertifikatsprüfung
	lastPing map[string]time.Time
}

// refuseInternal ist die Control-Funktion des Dialers: Sie sieht die aufgelöste Adresse und verhindert so, dass ein
// Hostname (auch nach einem DNS-Wechsel) auf interne Ziele führt.
func refuseInternal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("Ziel %s ist keine öffentliche Adresse", host)
	}
	return nil
}

func (p *Prober) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if !p.AllowInternal {
		d.Control = refuseInternal
	}
	return d
}

// target liefert Host:Port einer https-Adresse, sonst einen Fehler.
func target(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, "", errors.New("nur https-Adressen")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u, net.JoinHostPort(u.Hostname(), port), nil
}

// CertExpiry liest den Ablauf des Zertifikats per TLS-Handshake; es wird nichts gesendet.
// shortcut: das Zertifikat wird nicht geprüft (ein abgelaufenes soll ja gemeldet werden), auch der Hostname nicht; bei Bedarf
// zusätzlich mit Prüfung verbinden.
func (p *Prober) CertExpiry(ctx context.Context, raw string) (time.Time, error) {
	u, addr, err := target(raw)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	td := tls.Dialer{NetDialer: p.dialer(), Config: &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true}} //nolint:gosec // siehe shortcut
	conn, err := td.DialContext(ctx, "tcp", addr)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, errors.New("kein Zertifikat")
	}
	return certs[0].NotAfter, nil
}

// Ping ruft die Seite einmal auf (GET, keine Weiterleitung, Antwort wird nicht gelesen) und liefert den Statuscode.
func (p *Prober) Ping(ctx context.Context, raw string) (int, error) {
	if _, _, err := target(raw); err != nil {
		return 0, err
	}
	c := &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{DialContext: p.dialer().DialContext, TLSClientConfig: p.tlsConfig, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Sitewatch-Weckruf")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// Overlay trägt das ermittelte Zertifikat-Ablaufdatum in einen Report ein, der keins enthält (das Bundle kennt es nicht).
func (p *Prober) Overlay(r *report.Report) {
	if r.Site.TLSExpires != nil {
		return
	}
	p.mu.Lock()
	t, ok := p.expires[r.Site.ID]
	p.mu.Unlock()
	if ok {
		r.Site.TLSExpires = &t
	}
}

// Once macht einen Durchlauf über alle Contao-Bundles mit Adresse.
func (p *Prober) Once(ctx context.Context) {
	as, err := p.Agents.List()
	if err != nil {
		log.Printf("probe: %v", err)
		return
	}
	now := p.Now()
	for _, a := range as {
		if !a.Bundle() || len(a.Config.Sites) != 1 || a.Config.Sites[0].URL == "" {
			continue
		}
		id, raw := a.Config.Sites[0].ID, a.Config.Sites[0].URL
		if _, _, err := target(raw); err != nil {
			continue // http-Adressen werden weder geprüft noch aufgerufen
		}
		p.checkCert(ctx, id, raw, now)
		p.wake(ctx, id, raw, a.Updated, now)
	}
}

func (p *Prober) checkCert(ctx context.Context, id, raw string, now time.Time) {
	p.mu.Lock()
	due := now.Sub(p.checked[id]) >= tlsEvery
	if due {
		if p.checked == nil {
			p.checked = map[string]time.Time{}
		}
		p.checked[id] = now
	}
	p.mu.Unlock()
	if !due {
		return
	}
	t, err := p.CertExpiry(ctx, raw)
	if err != nil {
		log.Printf("probe: Zertifikat von %q: %v", id, err)
		return
	}
	p.mu.Lock()
	if p.expires == nil {
		p.expires = map[string]time.Time{}
	}
	p.expires[id] = t
	p.mu.Unlock()
}

// wake ruft die Seite auf, wenn der letzte Report älter ist als BundlePingAfter (ohne Report: seit dem Anlegen des Agenten).
func (p *Prober) wake(ctx context.Context, id, raw string, created, now time.Time) {
	last := created
	if e, ok, err := p.Store.Get(id); err != nil {
		log.Printf("probe: %q: %v", id, err)
		return
	} else if ok {
		last = e.ReceivedAt
	}
	p.mu.Lock()
	due := now.Sub(last) > p.Settings.Get().BundlePingAfter && now.Sub(p.lastPing[id]) >= pingMinSpace
	if due {
		if p.lastPing == nil {
			p.lastPing = map[string]time.Time{}
		}
		p.lastPing[id] = now
	}
	p.mu.Unlock()
	if !due {
		return
	}
	code, err := p.Ping(ctx, raw)
	if err != nil {
		log.Printf("probe: Weckruf an %q: %v", id, err)
		return
	}
	log.Printf("probe: Weckruf an %q (Report seit %s überfällig): HTTP %d", id, status.Duration(now.Sub(last)), code)
}

// Run macht beim Start und danach alle every einen Durchlauf, bis ctx endet.
func (p *Prober) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		p.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Store legt Overlay über Latest und Get, damit Oberfläche und Alarme das ermittelte Zertifikat sehen.
type Store struct {
	store.Store
	P *Prober
}

func (s Store) Latest() ([]store.Entry, error) {
	es, err := s.Store.Latest()
	for i := range es {
		s.P.Overlay(&es[i].Report)
	}
	return es, err
}

func (s Store) Get(id string) (store.Entry, bool, error) {
	e, ok, err := s.Store.Get(id)
	if ok {
		s.P.Overlay(&e.Report)
	}
	return e, ok, err
}
