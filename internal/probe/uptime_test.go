package probe

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"sitewatch/internal/store"
)

func TestClassify(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name     string
		code     int
		err      error
		maint    bool
		first503 time.Time
		want     string
	}{
		{"200", 200, nil, false, time.Time{}, store.CheckUp},
		{"302", 302, nil, false, time.Time{}, store.CheckUp},
		{"401", 401, nil, false, time.Time{}, store.CheckUp},
		{"403", 403, nil, false, time.Time{}, store.CheckUp},
		{"404", 404, nil, false, time.Time{}, store.CheckDown},
		{"500", 500, nil, true, time.Time{}, store.CheckDown},
		{"Fehler", 0, errors.New("x"), false, time.Time{}, store.CheckDown},
		{"503 neu", 503, nil, false, time.Time{}, store.CheckMaint},
		{"503 jung", 503, nil, false, now.Add(-10 * time.Minute), store.CheckMaint},
		{"503 alt", 503, nil, false, now.Add(-20 * time.Minute), store.CheckDown},
		{"503 alt, Report meldet Wartung", 503, nil, true, now.Add(-2 * time.Hour), store.CheckMaint},
	} {
		if got := classify(c.code, c.err, c.maint, c.first503, now); got != c.want {
			t.Errorf("%s: %s, erwartet %s", c.name, got, c.want)
		}
	}
}

func TestUptimeFlow(t *testing.T) {
	var code atomic.Int32
	code.Store(200)
	p, st, _, now := setup(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(code.Load())) }))
	p.Uptime = st
	cur := now
	p.Now = func() time.Time { return cur }
	ctx := context.Background()
	step := func(c int, d time.Duration) string {
		code.Store(int32(c))
		cur = cur.Add(d)
		p.uptimeOnce(ctx)
		u, ok := p.Check("kunde-b")
		if !ok {
			return ""
		}
		return u.State
	}
	if got := step(200, 0); got != "up" {
		t.Fatalf("erste Prüfung: %q", got)
	}
	if recent, _ := st.RecentChecks("kunde-b", 10); len(recent) != 1 || recent[0].LatencyMS < 1 {
		t.Fatalf("gespeichert: %+v", recent)
	}
	step(500, 15*time.Second) // noch nicht an der Reihe
	if recent, _ := st.RecentChecks("kunde-b", 10); len(recent) != 1 {
		t.Errorf("zu früh geprüft: %d", len(recent))
	}
	if got := step(500, 3*time.Minute); got != "up" { // 1. Fehlschlag: noch nicht kritisch
		t.Errorf("nach 1 Fehlschlag: %q", got)
	}
	step(500, 3*time.Minute)
	if got := step(500, 3*time.Minute); got != "down" {
		t.Errorf("nach 3 Fehlschlägen: %q", got)
	}
	if got := step(503, 3*time.Minute); got != "maint" {
		t.Errorf("503: %q", got)
	}
	step(503, 20*time.Minute) // Frist abgelaufen: zählt als Fehlschlag
	for range 2 {
		step(503, 3*time.Minute)
	}
	if got := step(503, 3*time.Minute); got != "down" {
		t.Errorf("503 nach Ablauf der Frist: %q", got)
	}
	if got := step(200, 3*time.Minute); got != "up" {
		t.Errorf("Erholung: %q", got)
	}
	// Neustart: Zustand kommt aus der Datenbank zurück.
	p.up = nil
	p.uptimeOnce(ctx)
	if got := mustState(t, p); got != "up" {
		t.Errorf("nach Neustart: %q", got)
	}
	// Abgeschaltet: keine Prüfung, kein Zustand.
	if err := st.SetUptimeSetting("kunde-b", store.UptimeSetting{Enabled: false, IntervalS: 180}); err != nil {
		t.Fatal(err)
	}
	p.uptimeOnce(ctx)
	if _, ok := p.Check("kunde-b"); ok {
		t.Error("abgeschaltete Site wird geprüft")
	}
}

func mustState(t *testing.T, p *Prober) string {
	t.Helper()
	u, ok := p.Check("kunde-b")
	if !ok {
		t.Fatal("kein Zustand")
	}
	return u.State
}

func TestMassDown(t *testing.T) {
	p := &Prober{up: map[string]*upState{}}
	add := func(id, state string) { p.up[id] = &upState{state: state} }
	add("a", "down")
	add("b", "down")
	add("c", "up")
	if p.MassDown() {
		t.Error("2 von 3 ausgefallen sind noch kein Massenausfall")
	}
	add("c", "down")
	add("d", "up")
	if p.MassDown() { // 3 von 4 = 75 %
		t.Error("75 % reichen nicht")
	}
	add("d", "down")
	if !p.MassDown() {
		t.Error("4 von 4 ausgefallen nicht erkannt")
	}
	add("e", "")
	if !p.MassDown() {
		t.Error("Sites ohne Zustand zählen nicht")
	}
}
