package status

import (
	"testing"
	"time"

	"sitewatch/internal/report"
)

func TestDiskLevel(t *testing.T) {
	cfg := DefaultConfig() // 15 / 5
	for pct, want := range map[int]Level{50: OK, 15: OK, 14: Warn, 5: Warn, 4: Crit, 0: Crit} {
		if got := DiskLevel(pct, cfg); got != want {
			t.Errorf("%d %%: %v, erwartet %v", pct, got, want)
		}
	}
}

func TestCronAndMigrationsEvaluate(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	old, fresh, n := now.Add(-3*time.Hour), now.Add(-time.Minute), 2
	r := &report.Report{Site: report.Site{CronLastRun: &old, PendingMigrations: &n}}
	res := Evaluate(r, now, now, cfg)
	if res.Level != Crit || len(res.Reasons) != 2 { // offene Migrationen sind immer kritisch
		t.Fatalf("%+v", res)
	}
	veryOld := now.Add(-5 * time.Hour)
	r = &report.Report{Site: report.Site{CronLastRun: &veryOld}}
	if res := Evaluate(r, now, now, cfg); res.Level != Crit {
		t.Fatalf("5 Std.: %+v", res)
	}
	zero := 0
	r = &report.Report{Site: report.Site{CronLastRun: &fresh, PendingMigrations: &zero}}
	if res := Evaluate(r, now, now, cfg); res.Level != OK {
		t.Fatalf("%+v", res)
	}
}

func TestMaintenanceEvaluate(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cfg := DefaultConfig() // 2 Std. Warnung, 8 Std. kritisch
	on := true
	for since, want := range map[time.Duration]Level{time.Hour: OK, 3 * time.Hour: Warn, 9 * time.Hour: Crit} {
		s := now.Add(-since)
		r := &report.Report{Site: report.Site{MaintenanceMode: &on, MaintenanceSince: &s}}
		if got := Evaluate(r, now, now, cfg).Level; got != want {
			t.Errorf("seit %v: %v, erwartet %v", since, got, want)
		}
	}
	off, s := false, now.Add(-10*time.Hour) // ausgeschaltet: kein Urteil, auch bei altem Zeitpunkt
	if got := Evaluate(&report.Report{Site: report.Site{MaintenanceMode: &off, MaintenanceSince: &s}}, now, now, cfg).Level; got != OK {
		t.Errorf("aus: %v", got)
	}
}

func TestWith(t *testing.T) {
	def := DefaultConfig()
	if c, err := def.With(nil); err != nil || c != def {
		t.Fatalf("ohne Werte: %+v %v", c, err)
	}
	c, err := def.With(map[string]int{"tls_warn_days": 30, "disk_warn_pct": 20})
	if err != nil || c.TLSWarn != 30*24*time.Hour || c.DiskWarn != 20 || c.DiskCrit != def.DiskCrit || c.BackupMax != def.BackupMax {
		t.Fatalf("%+v %v", c, err)
	}
	for name, vals := range map[string]map[string]int{
		"unbekannt": {"tls_warn": 30},
		"null":      {"tls_warn_days": 0},
		"crit>warn": {"disk_crit_pct": 30},
		"cron":      {"cron_warn_minutes": 300},
		"wartung":   {"maintenance_warn_minutes": 600},
		"history":   {"history_full_days": 100},
		">100":      {"disk_warn_pct": 101},
	} {
		if got, err := def.With(vals); err == nil || got != def {
			t.Errorf("%s: kein Fehler oder Config verändert", name)
		}
	}
}

// Jeder Schlüssel aus Fields lässt sich schreiben und liest denselben Wert zurück; Standardwerte sind gültig.
func TestFieldsRoundTrip(t *testing.T) {
	def := DefaultConfig()
	if _, err := def.With(def.Values()); err != nil {
		t.Fatalf("Standardwerte ungültig: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range Fields {
		if seen[f.Key] || f.Group == "" || f.Label == "" || f.Unit == "" {
			t.Errorf("Feld unvollständig oder doppelt: %+v", f.Key)
		}
		seen[f.Key] = true
		c := def
		f.Set(&c, 7)
		if got := f.Get(c); got != 7 {
			t.Errorf("%s: %d", f.Key, got)
		}
	}
}

func TestSettingsHolder(t *testing.T) {
	s := NewSettings(DefaultConfig())
	c := s.Get()
	c.ErrorWarn = 99
	s.Set(c)
	if s.Get().ErrorWarn != 99 {
		t.Error("Set wirkt nicht")
	}
}

type fakeEOL map[string]time.Time

func (f fakeEOL) EOL(product, version string) (time.Time, bool) {
	t, ok := f[product+" "+minor(version)]
	return t, ok
}

func TestEOLLevel(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	if l, _ := EOLLevel("php", "8.1.9", now, cfg); l != Warn { // ohne Quelle: eingebaute Tabelle
		t.Errorf("Tabelle: %v", l)
	}
	if l, _ := EOLLevel("contao", "5.6.1", now, cfg); l != OK { // ohne Daten kein Urteil
		t.Errorf("ohne Quelle: %v", l)
	}
	cfg.EOL = fakeEOL{"contao 5.6": now.Add(-time.Hour), "contao 5.7": now.Add(400 * 24 * time.Hour), "php 8.1": now.Add(400 * 24 * time.Hour)}
	if l, _ := EOLLevel("contao", "5.6.1", now, cfg); l != Warn {
		t.Errorf("abgelaufen: %v", l)
	}
	if l, _ := EOLLevel("contao", "5.7.15", now, cfg); l != OK {
		t.Errorf("weit entfernt: %v", l)
	}
	if l, _ := EOLLevel("php", "8.1.9", now, cfg); l != OK { // die Quelle hat Vorrang vor der Tabelle
		t.Errorf("Quelle vor Tabelle: %v", l)
	}
}

func TestWithJSON(t *testing.T) {
	def := DefaultConfig()
	if c, err := def.WithJSON(`{"tls_warn_days": 30}`); err != nil || c.TLSWarn != 30*24*time.Hour {
		t.Fatalf("gültig: %+v %v", c, err)
	}
	for name, raw := range map[string]string{
		"kein json": `{`,
		"ungültig":  `{"disk_crit_pct": 30}`,
		"zu groß":   `{"tls_warn_days": 99999999999}`,
		"unbekannt": `{"x": 1}`,
	} {
		if got, err := def.WithJSON(raw); err == nil || got != def {
			t.Errorf("%s: kein Fehler oder Config verändert", name)
		}
	}
}
