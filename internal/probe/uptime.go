package probe

import (
	"context"
	"log"
	"slices"
	"sync"
	"time"

	"sitewatch/internal/status"
	"sitewatch/internal/store"
)

// Erreichbarkeitsprüfung: Sitewatch ruft die https-Adresse jeder Site (Agent-Konfiguration, nie der Report) im eingestellten Abstand
// auf und speichert Zustand und Antwortzeit. Gleiche Schranken wie der Weckruf (https, 10 s, keine Weiterleitung, keine internen Ziele).
const (
	uptimeTick     = 15 * time.Second // so fein wird geprüft, ob eine Site an der Reihe ist
	maintGrace     = 15 * time.Minute // 503 ohne Wartungsmodus im Report gilt so lange als Wartung (der Report kann hinterherhinken)
	uptimeParallel = 8
	latWindow      = 5 // Prüfungen für den Median der Antwortzeit
	seedChecks     = 10
)

// upState ist der Stand einer Site, aus den letzten Prüfungen abgeleitet (nach einem Neustart aus der Datenbank wiederhergestellt).
type upState struct {
	state     string // "", "up", "maint", "down" (down erst nach UptimeFails Fehlschlägen in Folge)
	since     time.Time
	fails     int
	failSince time.Time
	first503  time.Time // Beginn der aktuellen Folge von 503-Antworten
	last      time.Time
	lat       []int
}

func (s *upState) apply(c store.Check, failN int) {
	s.last = c.At
	if c.Code != 503 {
		s.first503 = time.Time{}
	} else if s.first503.IsZero() {
		s.first503 = c.At
	}
	set := func(st string, at time.Time) {
		if s.state != st {
			s.state, s.since = st, at
		}
	}
	switch c.State {
	case store.CheckUp:
		s.fails = 0
		set("up", c.At)
		s.lat = append(s.lat, c.LatencyMS)
		if len(s.lat) > latWindow {
			s.lat = s.lat[1:]
		}
	case store.CheckMaint:
		s.fails = 0
		set("maint", c.At)
	default:
		if s.fails == 0 {
			s.failSince = c.At
		}
		if s.fails++; s.fails >= failN {
			set("down", s.failSince)
		}
	}
}

func (s *upState) median() int {
	if len(s.lat) < 3 {
		return 0
	}
	l := slices.Clone(s.lat)
	slices.Sort(l)
	return l[len(l)/2]
}

// classify ordnet eine Antwort ein. 503 ist Wartung, wenn der Report den Wartungsmodus meldet oder die 503er jünger als maintGrace sind.
func classify(code int, err error, reportMaint bool, first503, now time.Time) string {
	switch {
	case err != nil:
		return store.CheckDown
	case code >= 200 && code < 400, code == 401, code == 403:
		return store.CheckUp
	case code == 503 && (reportMaint || first503.IsZero() || now.Sub(first503) < maintGrace):
		return store.CheckMaint
	}
	return store.CheckDown
}

// Check liefert den Stand der Erreichbarkeitsprüfung (status.UptimeSource).
func (p *Prober) Check(siteID string) (status.UptimeCheck, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.up[siteID]
	if s == nil || s.state == "" {
		return status.UptimeCheck{}, false
	}
	return status.UptimeCheck{State: s.state, Since: s.since, LatencyMS: s.median()}, true
}

// MassDown sagt, ob so viele Sites zugleich "down" sind (mindestens 3 und 80 % der geprüften), dass die Ursache eher bei Sitewatch
// (Netz, DNS) als bei den Sites liegt. Nur ein Hinweis in der Oberfläche; Status und Alarme bleiben unverändert.
func (p *Prober) MassDown() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	down, total := 0, 0
	for _, s := range p.up {
		if s.state == "" {
			continue
		}
		total++
		if s.state == "down" {
			down++
		}
	}
	return down >= 3 && down*100 >= total*80
}

func (p *Prober) failN() int {
	if p.Settings == nil {
		return status.DefaultConfig().UptimeFails
	}
	return p.Settings.Get().UptimeFails
}

// RunUptime prüft im Takt uptimeTick, welche Sites an der Reihe sind, bis ctx endet. Ohne p.Uptime tut es nichts.
func (p *Prober) RunUptime(ctx context.Context) {
	if p.Uptime == nil {
		return
	}
	t := time.NewTicker(uptimeTick)
	defer t.Stop()
	for {
		p.uptimeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Prober) uptimeOnce(ctx context.Context) {
	as, err := p.Agents.List()
	if err != nil {
		log.Printf("uptime: %v", err)
		return
	}
	sets, err := p.Uptime.UptimeSettings()
	if err != nil {
		log.Printf("uptime: %v", err)
		return
	}
	type job struct{ id, url string }
	var due []job
	active := map[string]bool{}
	now := p.Now()
	for _, a := range as {
		for _, st := range a.Config.Sites {
			if _, _, err := target(st.URL); err != nil { // leer oder kein https: keine Prüfung
				continue
			}
			set, ok := sets[st.ID]
			if !ok {
				set = store.DefaultUptime()
			}
			if !set.Enabled || active[st.ID] {
				continue
			}
			active[st.ID] = true
			p.mu.Lock()
			s := p.up[st.ID]
			if s == nil {
				if p.up == nil {
					p.up = map[string]*upState{}
				}
				s = &upState{}
				p.up[st.ID] = s
				p.mu.Unlock()
				recent, err := p.Uptime.RecentChecks(st.ID, seedChecks)
				if err != nil {
					log.Printf("uptime: %q: %v", st.ID, err)
				}
				p.mu.Lock()
				for _, c := range slices.Backward(recent) { // älteste zuerst
					s.apply(c, p.failN())
				}
			}
			last := s.last
			p.mu.Unlock()
			if now.Sub(last) >= time.Duration(set.IntervalS)*time.Second-uptimeTick/2 {
				due = append(due, job{st.ID, st.URL})
			}
		}
	}
	p.mu.Lock()
	for id := range p.up { // abgeschaltete oder gelöschte Sites vergessen
		if !active[id] {
			delete(p.up, id)
		}
	}
	p.mu.Unlock()
	var wg sync.WaitGroup
	sem := make(chan struct{}, uptimeParallel)
	for _, j := range due {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			p.measure(ctx, j.id, j.url)
		}()
	}
	wg.Wait()
}

func (p *Prober) measure(ctx context.Context, id, raw string) {
	code, took, err := p.request(ctx, raw, "Sitewatch-Uptime")
	if err != nil {
		log.Printf("uptime: %q: %v", id, err)
	}
	reportMaint := false
	if e, ok, err := p.Store.Get(id); err == nil && ok {
		reportMaint = e.Report.Site.MaintenanceMode != nil && *e.Report.Site.MaintenanceMode
	}
	now := p.Now()
	p.mu.Lock()
	s := p.up[id]
	if s == nil { // inzwischen abgeschaltet
		p.mu.Unlock()
		return
	}
	c := store.Check{At: now, Code: code, State: classify(code, err, reportMaint, s.first503, now)}
	if c.State == store.CheckUp {
		c.LatencyMS = max(1, int(took.Milliseconds()))
	}
	s.apply(c, p.failN())
	p.mu.Unlock()
	if err := p.Uptime.AddCheck(id, c); err != nil {
		log.Printf("uptime: %q speichern: %v", id, err)
	}
}
