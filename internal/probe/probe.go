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
	"net/netip"
	"net/url"
	"sitewatch/internal/idn"
	"strings"
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

// Info ist das Ergebnis der jüngsten Prüfungen einer Site, für die Anzeige. Zeitstempel null = noch nicht vorgekommen.
type Info struct {
	PingAt      time.Time
	PingCode    int    // HTTP-Status des Weckrufs
	PingErr     string // leer = Antwort erhalten
	CertAt      time.Time
	CertErr     string    // leer = Zertifikat gelesen
	CertExpires time.Time // null bei CertErr
}

// Prober führt die Prüfungen aus und merkt sich das Ablaufdatum der Zertifikate (im Arbeitsspeicher; nach einem Neustart
// wird es mit dem ersten Durchlauf neu ermittelt).
type Prober struct {
	Agents   *agents.Store
	Store    store.Store
	Settings *status.Settings
	Now      func() time.Time
	// Uptime (optional) nimmt die Ergebnisse der Erreichbarkeitsprüfung auf (siehe RunUptime); nil = keine Prüfung.
	Uptime store.Uptime
	// Favicons (optional) nimmt die Symbole der Sites auf (siehe RunFavicons); nil = keine.
	Favicons store.Favicons
	// AllowInternal erlaubt Ziele in privaten und lokalen Netzen; nur für Tests.
	AllowInternal bool
	tlsConfig     *tls.Config // nur für Tests (selbstsigniertes Zertifikat des Testservers)

	mu       sync.Mutex
	expires  map[string]time.Time // Site-ID → Ablauf des Zertifikats
	checked  map[string]time.Time // Site-ID → letzte Zertifikatsprüfung
	lastPing map[string]time.Time
	favTry   map[string]time.Time // Site-ID → letzter Versuch, ein Symbol zu holen
	urls     map[string]string    // Site-ID → Adresse, für die expires gilt
	info     map[string]Info
	up       map[string]*upState // Erreichbarkeitsprüfung, nur für aktivierte Sites
}

var errInternal = errors.New("Ziel ist keine öffentliche Adresse")

// shortErr macht aus einem Netzwerkfehler eine kurze Kategorie für die Oberfläche. Die ausführliche Meldung (mit aufgelösten Adressen
// und Texten des Zielservers) bleibt im Log: Sie würde sonst interne Adressen verraten.
func shortErr(err error) string {
	var (
		dns *net.DNSError
		ne  net.Error
		op  *net.OpError
	)
	switch {
	case errors.Is(err, errInternal):
		return "Ziel ist keine öffentliche Adresse"
	case errors.As(err, &dns):
		return "Name nicht auflösbar"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "Zeitüberschreitung"
	case strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:"):
		return "TLS-Fehler"
	case errors.As(err, &op):
		return "Verbindung fehlgeschlagen"
	}
	return "Abruf fehlgeschlagen"
}

// blocked sind Bereiche, die IsPrivate, IsLoopback und Co. nicht abdecken, aber nicht öffentlich erreichbar sind oder interne
// IPv4-Adressen einbetten (NAT64, 6to4, Teredo).
var blocked = func() (out []netip.Prefix) {
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96", "2002::/16", "2001::/32"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// refuseInternal ist die Control-Funktion des Dialers: Sie sieht die aufgelöste Adresse und verhindert so, dass ein
// Hostname (auch nach einem DNS-Wechsel) auf interne Ziele führt.
func refuseInternal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap() // ::ffff:10.0.0.1 wie 10.0.0.1 behandeln
	bad := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
	for _, p := range blocked {
		bad = bad || p.Contains(ip)
	}
	if bad {
		return fmt.Errorf("%w: %s", errInternal, host)
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
	return u, net.JoinHostPort(idn.ASCIIHost(u.Hostname()), port), nil
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
	td := tls.Dialer{NetDialer: p.dialer(), Config: &tls.Config{ServerName: idn.ASCIIHost(u.Hostname()), InsecureSkipVerify: true}} //nolint:gosec // siehe shortcut
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
	code, _, err := p.request(ctx, raw, "Sitewatch-Weckruf")
	return code, err
}

// request ruft die Seite auf und liefert Statuscode und die Zeit bis zu den Antwort-Headern (inklusive DNS und TLS).
func (p *Prober) request(ctx context.Context, raw, userAgent string) (int, time.Duration, error) {
	if _, _, err := target(raw); err != nil {
		return 0, 0, err
	}
	c := &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{DialContext: p.dialer().DialContext, TLSClientConfig: p.tlsConfig, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cache-Control", "no-cache")
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, err
	}
	took := time.Since(start)
	_ = resp.Body.Close()
	return resp.StatusCode, took, nil
}

// Info liefert die jüngsten Prüfergebnisse; ok ist false, wenn die Site nicht (mehr) geprüft wird.
func (p *Prober) Info(id string) (Info, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i, ok := p.info[id]
	return i, ok
}

// update ändert die Prüfergebnisse einer Site.
func (p *Prober) update(id string, f func(*Info)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.info == nil {
		p.info = map[string]Info{}
	}
	i := p.info[id]
	f(&i)
	p.info[id] = i
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
// shortcut: seriell, bei vielen Seiten mit hängenden Servern (bis 20 s je Seite) dauert ein Durchlauf länger als der Takt; dann je Seite nebenläufig.
func (p *Prober) Once(ctx context.Context) {
	as, err := p.Agents.List()
	if err != nil {
		log.Printf("probe: %v", err)
		return
	}
	now := p.Now()
	active := map[string]bool{}
	defer func() { p.forgetExcept(active) }()
	for _, a := range as {
		if !a.Bundle() || len(a.Config.Sites) != 1 || a.Config.Sites[0].URL == "" {
			continue
		}
		id, raw := a.Config.Sites[0].ID, a.Config.Sites[0].URL
		if _, _, err := target(raw); err != nil {
			continue // http-Adressen werden weder geprüft noch aufgerufen
		}
		active[id] = true
		p.update(id, func(*Info) {}) // wird geprüft, auch wenn noch nichts vorliegt
		p.checkCert(ctx, id, raw, now)
		p.wake(ctx, id, raw, a.Updated, now)
	}
}

// forgetExcept verwirft alle Merkwerte von Sites, die nicht mehr geprüft werden (gelöscht, ohne https-Adresse).
func (p *Prober) forgetExcept(active map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range []map[string]time.Time{p.expires, p.checked, p.lastPing} {
		for id := range m {
			if !active[id] {
				delete(m, id)
			}
		}
	}
	for id := range p.urls {
		if !active[id] {
			delete(p.urls, id)
		}
	}
	for id := range p.info {
		if !active[id] {
			delete(p.info, id)
		}
	}
}

func (p *Prober) checkCert(ctx context.Context, id, raw string, now time.Time) {
	p.mu.Lock()
	if p.urls[id] != raw { // andere Adresse: bisherige Werte gelten nicht mehr
		if p.urls == nil {
			p.urls = map[string]string{}
		}
		p.urls[id] = raw
		delete(p.expires, id)
		delete(p.checked, id)
		delete(p.lastPing, id)
		delete(p.info, id)
	}
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
		p.mu.Lock()
		delete(p.expires, id) // lieber unbekannt als ein veralteter Wert
		p.mu.Unlock()
		p.update(id, func(i *Info) { i.CertAt, i.CertErr, i.CertExpires = now, shortErr(err), time.Time{} })
		return
	}
	p.update(id, func(i *Info) { i.CertAt, i.CertErr, i.CertExpires = now, "", t })
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
		p.update(id, func(i *Info) { i.PingAt, i.PingCode, i.PingErr = now, 0, shortErr(err) })
		return
	}
	p.update(id, func(i *Info) { i.PingAt, i.PingCode, i.PingErr = now, code, "" })
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

// Latest wie store.Store.Latest, mit ergänztem Zertifikat-Ablauf.
func (s Store) Latest() ([]store.Entry, error) {
	es, err := s.Store.Latest()
	for i := range es {
		s.P.Overlay(&es[i].Report)
	}
	return es, err
}

// Get wie store.Store.Get, mit ergänztem Zertifikat-Ablauf.
func (s Store) Get(id string) (store.Entry, bool, error) {
	e, ok, err := s.Store.Get(id)
	if ok {
		s.P.Overlay(&e.Report)
	}
	return e, ok, err
}
