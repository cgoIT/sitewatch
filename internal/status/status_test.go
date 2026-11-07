package status

import (
	"testing"
	"time"

	"sitewatch/internal/report"
)

var now = time.Date(2026, 10, 27, 19, 0, 0, 0, time.UTC)

func base() *report.Report {
	return &report.Report{Site: report.Site{ID: "x", Kind: "contao", PHP: "8.3.12"}}
}

func TestEvaluate(t *testing.T) {
	cfg := DefaultConfig()
	cases := []struct {
		name string
		mod  func(*report.Report)
		age  time.Duration
		want Level
	}{
		{"ok", func(r *report.Report) {}, time.Minute, OK},
		{"veraltet", func(r *report.Report) {}, time.Hour, Crit},
		{"advisory", func(r *report.Report) { r.Site.Advisories = []report.Advisory{{Package: "a"}} }, time.Minute, Crit},
		{"update", func(r *report.Report) { r.Site.Outdated = []report.Package{{Name: "a"}} }, time.Minute, Warn},
		{"php eol", func(r *report.Report) { r.Site.PHP = "8.1.30" }, time.Minute, Warn},
		{"php bald eol", func(r *report.Report) { r.Site.PHP = "8.2.24" }, time.Minute, Warn},
		{"viele fehler", func(r *report.Report) { r.Errors = []report.LogError{{Count: 12}} }, time.Minute, Warn},
		{"wenige fehler", func(r *report.Report) { r.Errors = []report.LogError{{Count: 2}} }, time.Minute, OK},
		{"tls abgelaufen", func(r *report.Report) { r.Site.TLSExpires = ptr(now.Add(-time.Hour)) }, time.Minute, Crit},
		{"tls bald", func(r *report.Report) { r.Site.TLSExpires = ptr(now.Add(5 * 24 * time.Hour)) }, time.Minute, Warn},
		{"tls ok", func(r *report.Report) { r.Site.TLSExpires = ptr(now.Add(60 * 24 * time.Hour)) }, time.Minute, OK},
		{"backup alt", func(r *report.Report) { r.Site.LastBackup = ptr(now.Add(-3 * 24 * time.Hour)) }, time.Minute, Warn},
		{"backup frisch", func(r *report.Report) { r.Site.LastBackup = ptr(now.Add(-2 * time.Hour)) }, time.Minute, OK},
		{"tls genau an der Schwelle", func(r *report.Report) { r.Site.TLSExpires = ptr(now.Add(cfg.TLSWarn)) }, time.Minute, OK},
		{"backup genau an der Schwelle", func(r *report.Report) { r.Site.LastBackup = ptr(now.Add(-cfg.BackupMax)) }, time.Minute, OK},
		{"nur ausgeschlossene Updates", func(r *report.Report) { r.Site.Outdated = []report.Package{{Name: "a", Ignored: true}} }, time.Minute, OK},
		{"gemischte Updates", func(r *report.Report) {
			r.Site.Outdated = []report.Package{{Name: "a", Ignored: true}, {Name: "b"}}
		}, time.Minute, Warn},
		{"probleme", func(r *report.Report) { r.Site.Problems = []string{"x"} }, time.Minute, Warn},
	}
	for _, c := range cases {
		r := base()
		c.mod(r)
		got := Evaluate(r, now.Add(-c.age), now, cfg)
		if got.Level != c.want {
			t.Errorf("%s: Level %v, erwartet %v (%v)", c.name, got.Level, c.want, got.Reasons)
		}
	}
}

func ptr(t time.Time) *time.Time { return &t }

// Das Contao-Bundle meldet nur stündlich: 2 Stunden ohne Meldung sind für ein Bundle noch in Ordnung, für einen Server-Agenten nicht.
func TestBundleProfile(t *testing.T) {
	cfg := DefaultConfig()
	r := base()
	r.Agent.Type = report.AgentContaoBundle
	if got := Evaluate(r, now.Add(-2*time.Hour), now, cfg).Level; got != OK {
		t.Errorf("Bundle nach 2 h: %v", got)
	}
	if got := Evaluate(r, now.Add(-4*time.Hour), now, cfg).Level; got != Crit {
		t.Errorf("Bundle nach 4 h: %v", got)
	}
	r.Agent.Type = "go-host"
	if got := Evaluate(r, now.Add(-2*time.Hour), now, cfg).Level; got != Crit {
		t.Errorf("Server-Agent nach 2 h: %v", got)
	}
}

type fakeUptime map[string]UptimeCheck

func (f fakeUptime) Check(id string) (UptimeCheck, bool) { u, ok := f[id]; return u, ok }

func TestEvaluateUptime(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		u    UptimeCheck
		want Level
	}{
		{"erreichbar", UptimeCheck{State: "up", Since: now.Add(-time.Hour), LatencyMS: 200}, OK},
		{"langsam", UptimeCheck{State: "up", Since: now.Add(-time.Hour), LatencyMS: 2500}, Warn},
		{"Wartung", UptimeCheck{State: "maint", Since: now.Add(-time.Hour)}, OK},
		{"nicht erreichbar", UptimeCheck{State: "down", Since: now.Add(-time.Hour)}, Crit},
		{"Tagesstand aus der Vergangenheit", UptimeCheck{State: "down", Since: now.Add(time.Hour)}, OK},
	}
	for _, c := range cases {
		cfg := DefaultConfig()
		cfg.Uptime = fakeUptime{"s": c.u}
		r := &report.Report{Site: report.Site{ID: "s"}}
		if got := Evaluate(r, now, now, cfg).Level; got != c.want {
			t.Errorf("%s: %v, erwartet %v", c.name, got, c.want)
		}
	}
}
