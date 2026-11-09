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

func TestEvaluateSMART(t *testing.T) {
	now := time.Now()
	f, tr, n := false, true, 3
	r := &report.Report{Site: report.Site{ID: "a", Kind: "host"}, Host: report.Host{Disks: []report.Disk{{Device: "/dev/sda", Passed: &tr, BadSectors: &n}}}}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Warn {
		t.Errorf("defekte Sektoren: %v, erwartet Warn", got)
	}
	r.Host.Disks[0].Passed = &f
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Crit {
		t.Errorf("SMART failed: %v, erwartet Crit", got)
	}
}

func TestEvaluateRAID(t *testing.T) {
	r := base()
	r.Host.Raids = []report.Raid{{Name: "md0", Level: "raid1", Total: 2, Active: 2}}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != OK {
		t.Errorf("gesund: %v", got)
	}
	r.Host.Raids[0].Failed = 1 // Ersatzplatte ist eingesprungen
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Warn {
		t.Errorf("defektes Mitglied: %v, erwartet Warn", got)
	}
	r.Host.Raids[0].Active = 1
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Crit {
		t.Errorf("degradiert: %v, erwartet Crit", got)
	}
}

func TestEvaluateDiskRaidEdgeCases(t *testing.T) {
	r := base()
	r.Host.Disks = []report.Disk{{Device: "/dev/sda"}}                                              // keine Daten: kein Befund
	r.Host.Raids = []report.Raid{{Name: "md0", Level: "raid1", Total: 2, Active: 2, Syncing: true}} // Prüfung läuft: ok
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != OK {
		t.Errorf("keine Daten bzw. Prüfung: %v, erwartet OK", got)
	}
	r.Host.Raids[0] = report.Raid{Name: "md0", Inactive: true}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Crit {
		t.Errorf("inaktiv: %v, erwartet Crit", got)
	}
}

func TestEvaluateHostOS(t *testing.T) {
	r := &report.Report{Site: report.Site{ID: "a", Kind: "host"}}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != OK {
		t.Fatalf("nichts erfasst: %v", got)
	}
	r.Host.Updates = &report.OSUpdates{Manager: "apt", Total: 5}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != OK {
		t.Errorf("normale Updates dürfen nicht warnen: %v", got)
	}
	r.Host.Updates.Security = 1
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Warn {
		t.Errorf("Sicherheitsupdate: %v", got)
	}
	r.Host.Updates = nil
	since := now.Add(-3 * 24 * time.Hour)
	r.Host.OS = &report.OSInfo{RebootRequired: true, RebootSince: &since}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != OK {
		t.Errorf("Neustart seit 3 Tagen: %v", got)
	}
	since = now.Add(-8 * 24 * time.Hour)
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != Warn {
		t.Errorf("Neustart seit 8 Tagen: %v", got)
	}
	r.Host.OS = nil
	r.Host.Systemd = &report.Systemd{Failed: []string{}}
	if got := Evaluate(r, now, now, DefaultConfig()).Level; got != OK {
		t.Errorf("keine fehlgeschlagenen Units: %v", got)
	}
	r.Host.Systemd.Failed = []string{"mariadb.service"}
	if res := Evaluate(r, now, now, DefaultConfig()); res.Level != Warn || len(res.Reasons) != 1 {
		t.Errorf("failed unit: %+v", res)
	}
}

type fakeAcks map[string]int

func (f fakeAcks) DiskAck(site, disk string) (int, time.Time, bool) {
	v, ok := f[site+"|"+disk]
	return v, now, ok
}

func TestEvaluateDiskAck(t *testing.T) {
	tr, n := true, 16
	r := &report.Report{Site: report.Site{ID: "a", Kind: "host"}, Host: report.Host{Disks: []report.Disk{{Device: "/dev/sdd", Serial: "S1", Passed: &tr, BadSectors: &n}}}}
	cfg := DefaultConfig()
	if got := Evaluate(r, now, now, cfg).Level; got != Warn {
		t.Fatalf("ohne Kenntnisnahme: %v", got)
	}
	cfg.DiskAcks = fakeAcks{"a|sn:S1": 16}
	if res := Evaluate(r, now, now, cfg); res.Level != OK || len(res.Reasons) != 0 {
		t.Errorf("bekannt und unverändert muss OK sein: %+v", res)
	}
	n = 17
	if res := Evaluate(r, now, now, cfg); res.Level != Warn || len(res.Reasons) != 1 {
		t.Errorf("gestiegen muss warnen: %+v", res)
	}
	n = 10
	if got := Evaluate(r, now, now, cfg).Level; got != OK {
		t.Errorf("gesunken: %v", got)
	}
	n = 16
	f := false
	r.Host.Disks[0].Passed = &f
	if got := Evaluate(r, now, now, cfg).Level; got != Crit {
		t.Errorf("SMART failed bleibt auch bei Kenntnisnahme kritisch: %v", got)
	}
}

func TestEvaluateNVMeWear(t *testing.T) {
	tr := true
	lv := func(wear, spare *int) Level {
		r := &report.Report{Site: report.Site{ID: "a", Kind: "host"}, Host: report.Host{Disks: []report.Disk{{Device: "/dev/nvme0n1", Passed: &tr, WearPct: wear, SpareLeftPct: spare}}}}
		return Evaluate(r, now, now, DefaultConfig()).Level
	}
	p := func(n int) *int { return &n }
	for _, c := range []struct {
		wear, spare *int
		want        Level
	}{{p(79), nil, OK}, {p(80), nil, Warn}, {p(100), nil, Crit}, {p(247), nil, Crit}, {nil, nil, OK}, {nil, p(49), Warn}, {nil, p(50), OK}} {
		if got := lv(c.wear, c.spare); got != c.want {
			t.Errorf("wear=%v spare=%v: %v, erwartet %v", c.wear, c.spare, got, c.want)
		}
	}
}
