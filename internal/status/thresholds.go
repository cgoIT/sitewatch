package status

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Field ist ein Schwellwert, der im Cockpit gepflegt wird. Die Einheit steht im Schlüssel und in Unit, damit es keine
// Parsing-Fallen gibt (time.ParseDuration kennt keine Tage). Reihenfolge und Group bestimmen die Anzeige.
type Field struct {
	Key, Group, Label, Unit string
	Get                     func(Config) int
	Set                     func(*Config, int)
}

func durField(key, group, label, unit string, unitDur time.Duration, p func(*Config) *time.Duration) Field {
	return Field{key, group, label, unit,
		func(c Config) int { return int(*p(&c) / unitDur) },
		func(c *Config, n int) { *p(c) = time.Duration(n) * unitDur }}
}

func intField(key, group, label, unit string, p func(*Config) *int) Field {
	return Field{key, group, label, unit, func(c Config) int { return *p(&c) }, func(c *Config, n int) { *p(c) = n }}
}

const (
	gReports = "Meldungen"
	gVersion = "Versionen und Zertifikate"
	gBackup  = "Backups"
	gDisk    = "Speicherplatz"
	gCron    = "Contao-Cron"
	gMaint   = "Wartungsmodus"
	gHistory = "Aufbewahrung des Verlaufs"
)

// Fields sind alle pflegbaren Schwellwerte. Fehlende Werte behalten den Standard aus DefaultConfig.
var Fields = []Field{
	durField("stale_after_minutes", gReports, "Keine Meldung seit (Server-Agent): kritisch", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.StaleAfter }),
	durField("bundle_stale_after_minutes", gReports, "Keine Meldung seit (Contao-Bundle): kritisch", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.BundleStaleAfter }),
	durField("bundle_ping_after_minutes", gReports, "Weckruf an die Seite (Contao-Bundle), wenn der Report älter ist als", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.BundlePingAfter }),
	intField("error_warn", gReports, "Fehler in 24 Stunden: Warnung ab", "Fehler", func(c *Config) *int { return &c.ErrorWarn }),
	durField("eol_warn_days", gVersion, "Support-Ende: Warnung, wenn näher als", "Tage", 24*time.Hour, func(c *Config) *time.Duration { return &c.EOLWarn }),
	durField("tls_warn_days", gVersion, "TLS-Zertifikat: Warnung, wenn es früher abläuft als", "Tage", 24*time.Hour, func(c *Config) *time.Duration { return &c.TLSWarn }),
	durField("backup_max_hours", gBackup, "Letztes Backup: Warnung, wenn älter als", "Stunden", time.Hour, func(c *Config) *time.Duration { return &c.BackupMax }),
	intField("disk_warn_pct", gDisk, "Freier Speicher: Warnung unter", "%", func(c *Config) *int { return &c.DiskWarn }),
	intField("disk_crit_pct", gDisk, "Freier Speicher: kritisch unter", "%", func(c *Config) *int { return &c.DiskCrit }),
	durField("cron_warn_minutes", gCron, "Letzter Cron-Lauf: Warnung, wenn älter als", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.CronWarn }),
	durField("cron_crit_minutes", gCron, "Letzter Cron-Lauf: kritisch, wenn älter als", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.CronCrit }),
	durField("maintenance_warn_minutes", gMaint, "Wartungsmodus an: Warnung nach", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.MaintWarn }),
	durField("maintenance_crit_minutes", gMaint, "Wartungsmodus an: kritisch nach", "Minuten", time.Minute, func(c *Config) *time.Duration { return &c.MaintCrit }),
	intField("history_full_days", gHistory, "Jeder Messpunkt bis", "Tage", func(c *Config) *int { return &c.Retention.FullDays }),
	intField("history_6h_days", gHistory, "Ein Punkt je 6 Stunden bis", "Tage", func(c *Config) *int { return &c.Retention.SixHourDays }),
	intField("history_max_days", gHistory, "Ein Punkt je Tag bis (danach gelöscht)", "Tage", func(c *Config) *int { return &c.Retention.MaxDays }),
	intField("history_reports_days", gHistory, "Vollständige Tagesstände bis", "Tage", func(c *Config) *int { return &c.Retention.ReportDays }),
}

// maxValue begrenzt jeden Wert, damit keine Zeitspanne beim Umrechnen überläuft.
const maxValue = 1_000_000

// Values liefert die aktuellen Werte nach Schlüssel.
func (c Config) Values() map[string]int {
	m := make(map[string]int, len(Fields))
	for _, f := range Fields {
		m[f.Key] = f.Get(c)
	}
	return m
}

// With übernimmt die Werte (Schlüssel aus Fields) und prüft die Abhängigkeiten. Unbekannte Schlüssel und Werte unter 1 sind Fehler,
// c bleibt dann unverändert. Fehlende Schlüssel behalten ihren Wert.
func (c Config) With(vals map[string]int) (Config, error) {
	next, err := c.with(vals)
	if err != nil {
		return c, err
	}
	return next, nil
}

// Diff liefert die Werte, die vom Standard abweichen. Nur sie werden gespeichert, so wirken spätere neue Standardwerte weiter.
func (c Config) Diff() map[string]int {
	def, diff := DefaultConfig().Values(), map[string]int{}
	for k, v := range c.Values() {
		if v != def[k] {
			diff[k] = v
		}
	}
	return diff
}

// WithJSON übernimmt gespeicherte Werte (JSON-Objekt Schlüssel → Zahl); bei Fehlern bleibt c unverändert.
func (c Config) WithJSON(raw string) (Config, error) {
	var vals map[string]int
	if err := json.Unmarshal([]byte(raw), &vals); err != nil {
		return c, fmt.Errorf("kein gültiges JSON: %w", err)
	}
	return c.With(vals)
}

func (c Config) with(vals map[string]int) (Config, error) {
	byKey := make(map[string]Field, len(Fields))
	for _, f := range Fields {
		byKey[f.Key] = f
	}
	for k, n := range vals {
		f, ok := byKey[k]
		switch {
		case !ok:
			return c, fmt.Errorf("unbekannter Schwellwert %q", k)
		case n < 1 || n > maxValue:
			return c, fmt.Errorf("%s: muss zwischen 1 und %d liegen", f.Label, maxValue)
		}
	}
	for _, f := range Fields { // in der Reihenfolge der Liste, damit Fehler reproduzierbar bleiben
		if n, ok := vals[f.Key]; ok {
			f.Set(&c, n)
		}
	}
	switch r := c.Retention; {
	case c.DiskWarn > 100 || c.DiskCrit > c.DiskWarn:
		return c, fmt.Errorf("Freier Speicher: kritisch darf nicht über der Warnung liegen, die Warnung höchstens 100 %%")
	case c.BundlePingAfter >= c.BundleStaleAfter:
		return c, fmt.Errorf("Weckruf: muss früher kommen als die kritische Meldung „Keine Meldung seit“ des Contao-Bundles")
	case c.MaintWarn > c.MaintCrit:
		return c, fmt.Errorf("Wartungsmodus: die Warnung darf nicht später kommen als der kritische Wert")
	case c.CronWarn > c.CronCrit:
		return c, fmt.Errorf("Contao-Cron: die Warnung darf nicht später kommen als der kritische Wert")
	case r.FullDays > r.SixHourDays || r.SixHourDays > r.MaxDays:
		return c, fmt.Errorf("Aufbewahrung: es muss gelten jeder Punkt ≤ 6 Stunden ≤ je Tag")
	}
	return c, nil
}

// Settings hält die Schwellwerte, die zur Laufzeit im Cockpit geändert werden. Evaluate bekommt jeweils eine Kopie.
type Settings struct {
	mu  sync.RWMutex
	cfg Config
}

// NewSettings legt die Schwellwerte mit dem Startwert c an.
func NewSettings(c Config) *Settings { return &Settings{cfg: c} }

// Get liefert eine Kopie der aktuellen Schwellwerte; sie ist ohne Sperre weiterverwendbar.
func (s *Settings) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Set ersetzt die Schwellwerte; der Aufrufer hat sie vorher mit Config.With geprüft.
func (s *Settings) Set(c Config) {
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
}
