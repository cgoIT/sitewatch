// Package status bewertet einen Report: OK, Warnung oder Kritisch, jeweils mit Gründen.
package status

import (
	"fmt"
	"strings"
	"time"

	"sitewatch/internal/report"
	"sitewatch/internal/store"
)

// Level ist die Schwere eines Befunds; höhere Werte sind schlimmer, damit das Maximum der Gesamtstatus ist.
type Level int

const (
	OK Level = iota
	Warn
	Crit
)

// String liefert den Namen für Oberfläche und CSS: "ok", "warn" oder "crit".
func (l Level) String() string {
	switch l {
	case Warn:
		return "warn"
	case Crit:
		return "crit"
	}
	return "ok"
}

// Config enthält die Schwellwerte.
type Config struct {
	StaleAfter time.Duration // keine Meldung seit dieser Zeit = kritisch
	// BundleStaleAfter ersetzt StaleAfter für Reports des Contao-Bundles: Es meldet nur stündlich und über den Contao-Cron,
	// der bei wenig Besuchern verzögert läuft.
	BundleStaleAfter time.Duration
	// BundlePingAfter: ist der Report eines Contao-Bundles so alt, ruft Sitewatch die Seite einmal auf (Weckruf für den Contao-Cron).
	BundlePingAfter time.Duration
	ErrorWarn       int             // ab so vielen Fehlern im Fenster = Warnung
	EOLWarn         time.Duration   // Warnung, wenn das PHP-Support-Ende näher als das ist
	TLSWarn         time.Duration   // Warnung, wenn das Zertifikat in weniger als dieser Zeit abläuft
	BackupMax       time.Duration   // Warnung, wenn das letzte Backup älter ist
	DiskWarn        int             // Warnung, wenn weniger als so viel Prozent Speicher frei sind
	DiskCrit        int             // kritisch, wenn weniger als so viel Prozent frei sind
	CronWarn        time.Duration   // Warnung, wenn der letzte Contao-Cron-Lauf länger her ist
	CronCrit        time.Duration   // kritisch, wenn er noch länger her ist
	RebootWarn      time.Duration   // Warnung, wenn ein Neustart des Servers (reboot-required) so lange aussteht
	MaintWarn       time.Duration   // Warnung, wenn der Wartungsmodus so lange an ist
	MaintCrit       time.Duration   // kritisch, wenn er noch länger an ist (vergessen)
	Retention       store.Retention // Aufbewahrung des Verlaufs und der Tagesstände (siehe store)
	UptimeFails     int             // so viele Fehlschläge in Folge: Seite gilt als nicht erreichbar (kritisch)
	LatencyWarn     time.Duration   // Warnung, wenn die Antwortzeit (Median der letzten Prüfungen) darüber liegt
	UptimeWarnPct   int             // Anzeige: Erreichbarkeit der letzten 30 Tage darunter wird markiert (wirkt nicht auf den Status)
	Uptime          UptimeSource    // optional: Erreichbarkeitsprüfung von Sitewatch aus; nil = keine
	EOL             EOLSource       // optional: aktuelle Support-Enden (z. B. endoflife.date); nil = nur die eingebaute PHP-Tabelle
}

// DefaultConfig liefert die Standardwerte aller Schwellwerte. Im Betrieb kommen Abweichungen aus der Datenbank (Seite „Einstellungen“).
func DefaultConfig() Config {
	return Config{StaleAfter: 15 * time.Minute, BundleStaleAfter: 3 * time.Hour, BundlePingAfter: 90 * time.Minute, ErrorWarn: 10, EOLWarn: 90 * 24 * time.Hour,
		TLSWarn: 14 * 24 * time.Hour, BackupMax: 36 * time.Hour, DiskWarn: 15, DiskCrit: 5, CronWarn: 2 * time.Hour, CronCrit: 4 * time.Hour, MaintWarn: 2 * time.Hour, RebootWarn: 7 * 24 * time.Hour, MaintCrit: 8 * time.Hour,
		UptimeFails: 3, LatencyWarn: 2 * time.Second, UptimeWarnPct: 99, Retention: store.DefaultRetention()}
}

// phpEOL: Ende der Sicherheitsunterstützung je PHP-Minor-Version.
// Stand Oktober 2026, bitte bei neuen PHP-Versionen pflegen.
var phpEOL = map[string]time.Time{
	"8.0": date(2023, 11, 26),
	"8.1": date(2025, 12, 31),
	"8.2": date(2026, 12, 31),
	"8.3": date(2027, 12, 31),
	"8.4": date(2028, 12, 31),
	"8.5": date(2029, 12, 31),
}

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 23, 59, 59, 0, time.UTC) }

// Result ist das Ergebnis der Bewertung.
type Result struct {
	Level   Level
	Reasons []string
}

// Evaluate bewertet den letzten Report einer Site. receivedAt ist der Eingangszeitpunkt in Sitewatch.
func Evaluate(r *report.Report, receivedAt, now time.Time, cfg Config) Result {
	if r.Agent.Type == report.AgentContaoBundle {
		cfg.StaleAfter = cfg.BundleStaleAfter
	}
	var res Result
	raise := func(l Level, format string, a ...any) {
		if l > res.Level {
			res.Level = l
		}
		res.Reasons = append(res.Reasons, fmt.Sprintf(format, a...))
	}
	if age := now.Sub(receivedAt); age > cfg.StaleAfter {
		raise(Crit, "Keine Meldung seit %s", Duration(age))
	}
	if n := len(r.Site.Advisories); n > 0 {
		raise(Crit, "%d Sicherheitshinweis(e) von composer audit", n)
	}
	for _, p := range []struct{ product, label, version string }{
		{"php", "PHP", r.Site.PHP}, {"contao", "Contao", r.Site.Contao},
		{"mariadb", "MariaDB", r.Host.MariaDB}, {"nginx", "nginx", r.Host.Nginx},
	} {
		if l, eol := EOLLevel(p.product, p.version, now, cfg); l > OK {
			if eol.Before(now) {
				raise(l, "%s %s hat kein Support mehr (seit %s)", p.label, minor(p.version), eol.Format("02.01.2006"))
			} else {
				raise(l, "%s %s: Support endet am %s", p.label, minor(p.version), eol.Format("02.01.2006"))
			}
		}
	}
	if t := r.Site.TLSExpires; t != nil {
		switch l := TLSLevel(*t, now, cfg); {
		case l == Crit:
			raise(Crit, "TLS-Zertifikat ist abgelaufen (seit %s)", t.Format("02.01.2006"))
		case l == Warn:
			raise(Warn, "TLS-Zertifikat läuft am %s ab", t.Format("02.01.2006"))
		}
	}
	if t := r.Site.LastBackup; t != nil && BackupLevel(*t, now, cfg) > OK {
		raise(Warn, "Letztes Backup vor %s", Duration(now.Sub(*t)))
	}
	if p := r.Host.DiskFreePct; p != nil {
		switch DiskLevel(*p, cfg) {
		case Crit:
			raise(Crit, "Nur noch %d %% Speicherplatz frei", *p)
		case Warn:
			raise(Warn, "Nur noch %d %% Speicherplatz frei", *p)
		}
	}
	for _, d := range r.Host.Disks {
		switch {
		case d.Passed != nil && !*d.Passed:
			raise(Crit, "Platte %s: SMART meldet Fehler, Ausfall droht", d.Device)
		case d.BadSectors != nil && *d.BadSectors > 0:
			raise(Warn, "Platte %s: %d defekte/umgelagerte Sektoren", d.Device, *d.BadSectors)
		}
	}
	for _, a := range r.Host.Raids {
		switch {
		case a.Inactive:
			raise(Crit, "RAID %s ist inaktiv", a.Name)
		case a.Missing() > 0:
			s := ""
			if a.Syncing {
				s = ", Wiederherstellung läuft"
			}
			raise(Crit, "RAID %s (%s) ist degradiert: %d von %d Platten aktiv%s", a.Name, a.Level, a.Active, a.Total, s)
		case a.Failed > 0:
			raise(Warn, "RAID %s: %d Platte(n) als defekt markiert", a.Name, a.Failed)
		}
	}
	if u := r.Host.Updates; u != nil && u.Security > 0 {
		raise(Warn, "%d Sicherheitsupdate(s) des Betriebssystems offen", u.Security)
	}
	if o := r.Host.OS; o != nil && o.RebootRequired && o.RebootSince != nil && now.Sub(*o.RebootSince) > cfg.RebootWarn {
		raise(Warn, "Neustart des Servers seit %s ausstehend", Duration(now.Sub(*o.RebootSince)))
	}
	if sd := r.Host.Systemd; sd != nil && len(sd.Failed) > 0 {
		names := sd.Failed
		if len(names) > 3 {
			names = names[:3]
		}
		raise(Warn, "%d systemd-Unit(s) fehlgeschlagen: %s", len(sd.Failed), strings.Join(names, ", "))
	}
	if t := r.Site.CronLastRun; t != nil {
		if l := CronLevel(*t, now, cfg); l > OK {
			raise(l, "Contao-Cron zuletzt vor %s gelaufen", Duration(now.Sub(*t)))
		}
	}
	if m, t := r.Site.MaintenanceMode, r.Site.MaintenanceSince; m != nil && *m && t != nil {
		if l := MaintenanceLevel(*t, now, cfg); l > OK {
			raise(l, "Wartungsmodus seit %s an", Duration(now.Sub(*t)))
		}
	}
	if n := r.Site.PendingMigrations; n != nil && *n > 0 {
		raise(Crit, "%d offene Migration(en) bzw. Schema-Änderung(en)", *n)
	}
	if n := r.Site.OpenUpdates(); n > 0 {
		raise(Warn, "%d Paket(e) mit verfügbarem Update", n)
	}
	total := 0
	for _, e := range r.Errors {
		total += e.Count
	}
	if total >= cfg.ErrorWarn {
		raise(Warn, "%d Fehler in den letzten 24 Stunden", total)
	}
	if cfg.Uptime != nil {
		// u.Since nach now: Tagesstand aus der Vergangenheit, die heutige Prüfung gilt dafür nicht.
		if u, ok := cfg.Uptime.Check(r.Site.ID); ok && !u.Since.After(now) {
			switch {
			case u.State == "down":
				raise(Crit, "Seite nicht erreichbar seit %s", Duration(now.Sub(u.Since)))
			case u.LatencyMS > 0 && time.Duration(u.LatencyMS)*time.Millisecond > cfg.LatencyWarn:
				raise(Warn, "Antwortzeit %d ms", u.LatencyMS)
			}
		}
	}
	if len(r.Site.Problems) > 0 {
		raise(Warn, "Teilweise keine Daten (%d Problem(e) beim Sammeln)", len(r.Site.Problems))
	}
	return res
}

// UptimeCheck ist der aktuelle Stand der Erreichbarkeitsprüfung einer Site. State: "up", "maint" oder "down" (erst nach
// UptimeFails Fehlschlägen in Folge); Since: seit wann. LatencyMS = Median der letzten Prüfungen, 0 = unbekannt.
type UptimeCheck struct {
	State     string
	Since     time.Time
	LatencyMS int
}

// UptimeSource liefert den Stand der Prüfung; ok=false: die Site wird nicht geprüft oder es liegt noch nichts vor.
type UptimeSource interface {
	Check(siteID string) (UptimeCheck, bool)
}

// EOLSource liefert das Ende der Sicherheitsunterstützung je Produkt ("php", "contao", "mariadb", "nginx") und Version.
// ok=false: unbekannt. Beispiel: eol.Provider (endoflife.date).
type EOLSource interface {
	EOL(product, version string) (time.Time, bool)
}

// EOLLevel, TLSLevel, BackupLevel und DiskLevel sind die Schwellen für Evaluate und für die Matrix-Ansicht.
// Für PHP gilt ohne Treffer in cfg.EOL die eingebaute Tabelle phpEOL; für die anderen Produkte ist ohne Daten alles OK.
func EOLLevel(product, version string, now time.Time, cfg Config) (Level, time.Time) {
	var eol time.Time
	var ok bool
	if cfg.EOL != nil {
		eol, ok = cfg.EOL.EOL(product, version)
	}
	if !ok && product == "php" {
		eol, ok = phpEOL[minor(version)]
	}
	if ok && eol.Sub(now) < cfg.EOLWarn {
		return Warn, eol
	}
	return OK, eol
}

// TLSLevel bewertet das Ablaufdatum eines Zertifikats: Crit, wenn es abgelaufen ist, Warn unter cfg.TLSWarn Restlaufzeit.
func TLSLevel(expires, now time.Time, cfg Config) Level {
	switch {
	case expires.Before(now):
		return Crit
	case expires.Sub(now) < cfg.TLSWarn:
		return Warn
	}
	return OK
}

// BackupLevel gibt Warn, wenn das letzte Backup länger her ist als cfg.BackupMax.
func BackupLevel(last, now time.Time, cfg Config) Level {
	if now.Sub(last) > cfg.BackupMax {
		return Warn
	}
	return OK
}

// MaintenanceLevel bewertet, wie lange der Wartungsmodus schon an ist (Warn ab cfg.MaintWarn, Crit ab cfg.MaintCrit).
func MaintenanceLevel(since, now time.Time, cfg Config) Level {
	switch age := now.Sub(since); {
	case age > cfg.MaintCrit:
		return Crit
	case age > cfg.MaintWarn:
		return Warn
	}
	return OK
}

// CronLevel bewertet das Alter des letzten Contao-Cron-Laufs (Warn ab cfg.CronWarn, Crit ab cfg.CronCrit).
func CronLevel(last, now time.Time, cfg Config) Level {
	switch age := now.Sub(last); {
	case age > cfg.CronCrit:
		return Crit
	case age > cfg.CronWarn:
		return Warn
	}
	return OK
}

// shortcut: keine Hysterese, pendelt der Wert um die Schwelle, wechseln Status und Alarm; bei Bedarf eine Toleranz ergänzen.
func DiskLevel(freePct int, cfg Config) Level {
	switch {
	case freePct < cfg.DiskCrit:
		return Crit
	case freePct < cfg.DiskWarn:
		return Warn
	}
	return OK
}

func minor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// Duration formatiert eine Dauer knapp auf Deutsch.
func Duration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "weniger als 1 Min."
	case d < time.Hour:
		return fmt.Sprintf("%d Min.", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d Std.", int(d.Hours()))
	}
	return fmt.Sprintf("%d Tagen", int(d.Hours()/24))
}

// Ago formuliert "vor 5 Min." bzw. "gerade eben".
func Ago(d time.Duration) string {
	if d < time.Minute {
		return "gerade eben"
	}
	return "vor " + Duration(d)
}
