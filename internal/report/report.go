// Package report definiert das Report-Format, das Agenten an Sitewatch senden.
// Agent und Sitewatch nutzen dieselben Typen, damit das Schema nur einmal existiert.
package report

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// SchemaVersion ist die aktuelle Version des Report-Formats.
const SchemaVersion = 1

// Report ist ein vollständiger Zustandsbericht für genau eine Site.
type Report struct {
	Schema      int        `json:"schema"`
	Agent       Agent      `json:"agent"`
	Host        Host       `json:"host"`
	Site        Site       `json:"site"`
	Errors      []LogError `json:"errors"`
	CollectedAt time.Time  `json:"collected_at"`
}

// AgentContaoBundle ist der Agent-Typ des Contao-Bundles (cgoit/contao-sitewatch-bundle) für Hosting ohne eigene Programme.
const AgentContaoBundle = "contao-bundle"

// Agent beschreibt, wer den Report erzeugt hat (Go-Host-Agent "go-host" oder Contao-Bundle).
type Agent struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// Host enthält Server-Informationen. Alle Felder sind optional.
type Host struct {
	Name        string `json:"name"`
	Nginx       string `json:"nginx,omitempty"`
	MariaDB     string `json:"mariadb,omitempty"`
	DiskFreePct *int   `json:"disk_free_pct,omitempty"`
	Disks       []Disk `json:"disks,omitempty"` // SMART je Platte; leer = nicht erfasst
	Raids       []Raid `json:"raids,omitempty"` // Linux-Software-RAID (mdadm); leer = keins oder nicht erfasst

	// Nur Host-Einträge; nil = nicht erfasst (nie geraten).
	OS      *OSInfo    `json:"os,omitempty"`
	Network *Network   `json:"network,omitempty"`
	Updates *OSUpdates `json:"os_updates,omitempty"`
	Systemd *Systemd   `json:"systemd,omitempty"`
}

// OSInfo beschreibt Betriebssystem und Auslastung des Servers.
type OSInfo struct {
	Name           string     `json:"name,omitempty"`   // z. B. "Debian GNU/Linux 12 (bookworm)"
	Kernel         string     `json:"kernel,omitempty"` // laufender Kernel
	UptimeS        *int64     `json:"uptime_s,omitempty"`
	RebootRequired bool       `json:"reboot_required,omitempty"`
	RebootSince    *time.Time `json:"reboot_since,omitempty"` // seit wann ein Neustart aussteht
	Load1          *float64   `json:"load1,omitempty"`
	CPUs           int        `json:"cpus,omitempty"`
	MemAvailPct    *int       `json:"mem_avail_pct,omitempty"`
	SwapUsedPct    *int       `json:"swap_used_pct,omitempty"`
}

// Network sind die Netzwerkangaben des Servers.
type Network struct {
	Interfaces []Iface  `json:"interfaces,omitempty"`
	Gateway    string   `json:"gateway,omitempty"` // Standardroute IPv4
	DNS        []string `json:"dns,omitempty"`
}

// Iface ist eine aktive Netzwerkschnittstelle mit ihren Adressen (CIDR).
type Iface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac,omitempty"`
}

// OSUpdates sind offene Paket-Updates des Betriebssystems (apt).
type OSUpdates struct {
	Manager  string      `json:"manager"` // "apt"
	Total    int         `json:"total"`   // alle offenen Updates (Packages ist ggf. gekürzt)
	Security int         `json:"security"`
	Packages []OSPackage `json:"packages,omitempty"`
}

// OSPackage ist ein Paket mit verfügbarem Update.
type OSPackage struct {
	Name      string `json:"name"`
	Installed string `json:"installed,omitempty"`
	New       string `json:"new"`
	Security  bool   `json:"security,omitempty"`
}

// Systemd meldet fehlgeschlagene Units (systemctl --failed).
type Systemd struct {
	Failed []string `json:"failed"`
}

// OpenOSUpdates liefert die Zahl offener Betriebssystem-Updates (0 = keine oder nicht erfasst).
func (h Host) OpenOSUpdates() int {
	if h.Updates == nil {
		return 0
	}
	return h.Updates.Total
}

// Raid ist ein Software-RAID-Verbund aus /proc/mdstat.
type Raid struct {
	Name     string `json:"name"`   // z. B. md0
	Level    string `json:"level"`  // z. B. raid1; bei inaktivem Verbund leer
	Total    int    `json:"total"`  // Sollzahl der Platten
	Active   int    `json:"active"` // davon aktiv
	Failed   int    `json:"failed"` // als defekt markierte Mitglieder (F)
	Inactive bool   `json:"inactive,omitempty"`
	Syncing  bool   `json:"syncing,omitempty"` // Wiederherstellung, Resync, Reshape oder Prüfung läuft
}

// Missing liefert die fehlenden Platten (Soll minus aktiv); ein inaktiver Verbund zählt mindestens eine.
func (r Raid) Missing() int {
	n := max(r.Total-r.Active, 0)
	if r.Inactive {
		n = max(n, 1)
	}
	return n
}

// Disk ist der SMART-Zustand einer Platte (smartctl).
type Disk struct {
	Device     string `json:"device"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`      // Seriennummer; bleibt beim Umbenennen des Geräts (sdd → sde) gleich
	Passed     *bool  `json:"passed"`                // Gesamturteil des Geräts (SMART overall-health); false = Ausfall droht
	TempC      *int   `json:"temp_c,omitempty"`      // nil = unbekannt
	BadSectors *int   `json:"bad_sectors,omitempty"` // ATA: Reallocated + Pending + Offline Uncorrectable; NVMe: Media Errors; nil = unbekannt
	// Nur NVMe, nil = unbekannt.
	WearPct      *int   `json:"wear_pct,omitempty"`      // percentage_used; über 100 möglich, bis 255
	SpareLeftPct *int   `json:"spare_pct,omitempty"`     // available_spare
	WrittenBytes *int64 `json:"written_bytes,omitempty"` // data_units_written × 512000
}

// Site beschreibt die überwachte Webseite.
type Site struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Kind            string `json:"kind"` // "contao", "php" oder "host"
	URL             string `json:"url,omitempty"`
	PHP             string `json:"php,omitempty"`
	Contao          string `json:"contao,omitempty"`
	MaintenanceMode *bool  `json:"maintenance_mode,omitempty"` // nil = unbekannt
	// MaintenanceSince ist der Zeitpunkt, seit dem der Wartungsmodus an ist (Änderungsdatum der Wartungsdatei).
	MaintenanceSince  *time.Time `json:"maintenance_since,omitempty"`
	TLSExpires        *time.Time `json:"tls_expires,omitempty"`        // nil = unbekannt
	LastBackup        *time.Time `json:"last_backup,omitempty"`        // nil = unbekannt
	BackupCount       *int       `json:"backup_count,omitempty"`       // Dateien, die der Backup-Maske entsprechen; nil = nicht geprüft
	CronLastRun       *time.Time `json:"cron_last_run,omitempty"`      // letzter Lauf eines Contao-Cron-Jobs; nil = unbekannt
	PendingMigrations *int       `json:"pending_migrations,omitempty"` // offene Migrationen und Schema-Befehle; nil = unbekannt
	PackagesTotal     int        `json:"packages_total"`
	Outdated          []Package  `json:"outdated"`
	Advisories        []Advisory `json:"advisories"`
	// Problems listet Dinge, die der Agent nicht ermitteln konnte.
	Problems []string `json:"problems,omitempty"`
}

// Package ist ein Composer-Paket mit verfügbarem Update.
type Package struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Latest    string `json:"latest"`
	// Status stammt von "composer outdated": "semver-safe-update" (innerhalb der
	// Constraints) oder "update-possible" (neue Hauptversion außerhalb).
	Status    string `json:"status"`
	Abandoned bool   `json:"abandoned,omitempty"`
	// Ignored: per Regel in der Agent-Konfiguration ausgeschlossen (z. B. keine neue Hauptversion); zählt nicht als offenes Update.
	Ignored bool `json:"ignored,omitempty"`
}

// Failed meldet, ob SMART der Platte einen Fehler bescheinigt; Bad liefert die defekten Sektoren (0 = keine oder unbekannt).
func (d Disk) Failed() bool { return d.Passed != nil && !*d.Passed }

// Key identifiziert die Platte über Neustarts hinweg: Seriennummer, sonst der Gerätename.
func (d Disk) Key() string {
	if d.Serial != "" {
		return "sn:" + d.Serial
	}
	return "dev:" + d.Device
}

// Temp liefert die Temperatur in °C; 0 = unbekannt (auch ein 0 °C aus älteren Reports gilt so).
func (d Disk) Temp() int {
	if d.TempC == nil || *d.TempC < 0 {
		return 0
	}
	return *d.TempC
}

func (d Disk) Bad() int {
	if d.BadSectors == nil {
		return 0
	}
	return *d.BadSectors
}

// OpenUpdates zählt die Pakete mit verfügbarem Update, die nicht ausgeschlossen sind.
func (s Site) OpenUpdates() int {
	n := 0
	for _, p := range s.Outdated {
		if !p.Ignored {
			n++
		}
	}
	return n
}

// Advisory ist ein von "composer audit" gemeldeter Sicherheitshinweis.
type Advisory struct {
	Package string `json:"package"`
	Title   string `json:"title"`
	CVE     string `json:"cve,omitempty"`
	Link    string `json:"link,omitempty"`
}

// LogError ist eine gruppierte Fehlermeldung aus dem Log.
type LogError struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Count   int       `json:"count"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidID prüft eine Site-ID. Sie wird auch als Dateiname verwendet.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Validate prüft einen empfangenen Report auf Plausibilität und Größenlimits.
func (r *Report) Validate(now time.Time) error {
	if r.Schema != SchemaVersion {
		return fmt.Errorf("unbekannte Schema-Version %d", r.Schema)
	}
	if !ValidID(r.Site.ID) {
		return errors.New("ungültige site.id (erlaubt: a-z, 0-9, -)")
	}
	if k := r.Site.Kind; k != "contao" && k != "php" && k != "host" {
		return errors.New(`site.kind muss "contao", "php" oder "host" sein`)
	}
	if r.CollectedAt.IsZero() {
		return errors.New("collected_at fehlt")
	}
	if r.CollectedAt.After(now.Add(5*time.Minute)) || r.CollectedAt.Before(now.Add(-7*24*time.Hour)) {
		return errors.New("collected_at liegt außerhalb des erlaubten Zeitfensters")
	}
	if n := r.Site.BackupCount; n != nil && *n < 0 {
		return errors.New("backup_count darf nicht negativ sein")
	}
	if n := r.Site.PendingMigrations; n != nil && *n < 0 {
		return errors.New("pending_migrations darf nicht negativ sein")
	}
	if t := r.Site.MaintenanceSince; t != nil && t.After(now.Add(5*time.Minute)) {
		return errors.New("maintenance_since liegt in der Zukunft")
	}
	if t := r.Site.CronLastRun; t != nil && t.After(now.Add(5*time.Minute)) {
		return errors.New("cron_last_run liegt in der Zukunft")
	}
	if t := r.Site.LastBackup; t != nil && t.After(now.Add(5*time.Minute)) {
		return errors.New("last_backup liegt in der Zukunft")
	}
	for _, d := range r.Host.Disks {
		if len(d.Device) > 128 || len(d.Model) > 128 || len(d.Serial) > 128 || badInt(d.BadSectors) || badInt(d.TempC) || badPct(d.WearPct) || badPct(d.SpareLeftPct) || (d.WrittenBytes != nil && *d.WrittenBytes < 0) {
			return errors.New("ungültige Plattenangabe")
		}
	}
	for _, a := range r.Host.Raids {
		if len(a.Name) > 128 || len(a.Level) > 128 || a.Total < 0 || a.Active < 0 || a.Failed < 0 || a.Total > 1<<20 || a.Active > 1<<20 || a.Failed > 1<<20 {
			return errors.New("ungültige RAID-Angabe")
		}
	}
	if err := r.Host.validateDetails(); err != nil {
		return err
	}
	if len(r.Host.Disks) > 64 || len(r.Host.Raids) > 64 {
		return errors.New("zu viele Platten oder RAID-Verbünde im Report")
	}
	if len(r.Errors) > 100 || len(r.Site.Outdated) > 1000 || len(r.Site.Advisories) > 200 || len(r.Site.Problems) > 50 {
		return errors.New("zu viele Einträge im Report")
	}
	for _, e := range r.Errors {
		if len(e.Message) > 2000 {
			return errors.New("Fehlermeldung zu lang")
		}
	}
	return nil
}

// badInt: negativ oder absurd groß (die Werte landen summiert im Verlauf).
func badPct(p *int) bool { return p != nil && (*p < 0 || *p > 255) }

func badInt(p *int) bool { return p != nil && (*p < 0 || *p > 1<<30) }

func (h Host) validateDetails() error {
	long := func(ss ...string) bool {
		for _, s := range ss {
			if len(s) > 256 {
				return true
			}
		}
		return false
	}
	if o := h.OS; o != nil {
		if (o.RebootSince != nil && o.RebootSince.After(time.Now().Add(5*time.Minute))) || long(o.Name, o.Kernel) || o.CPUs < 0 || o.CPUs > 1<<16 || (o.UptimeS != nil && *o.UptimeS < 0) ||
			badInt(o.MemAvailPct) || badInt(o.SwapUsedPct) || (o.Load1 != nil && (*o.Load1 < 0 || *o.Load1 > 1e6)) {
			return errors.New("ungültige OS-Angabe")
		}
	}
	if n := h.Network; n != nil {
		if len(n.Interfaces) > 64 || len(n.DNS) > 16 || long(n.Gateway) || long(n.DNS...) {
			return errors.New("ungültige Netzwerkangabe")
		}
		for _, i := range n.Interfaces {
			if len(i.Addrs) > 32 || long(i.Name, i.MAC) || long(i.Addrs...) {
				return errors.New("ungültige Netzwerkangabe")
			}
		}
	}
	if u := h.Updates; u != nil {
		if len(u.Packages) > 1000 || u.Total < 0 || u.Security < 0 || u.Total > 1<<20 || u.Security > u.Total || u.Security > 1<<20 || long(u.Manager) {
			return errors.New("ungültige Update-Angabe")
		}
		for _, p := range u.Packages {
			if long(p.Name, p.Installed, p.New) {
				return errors.New("ungültige Update-Angabe")
			}
		}
	}
	if s := h.Systemd; s != nil {
		if len(s.Failed) > 64 || long(s.Failed...) {
			return errors.New("ungültige systemd-Angabe")
		}
	}
	return nil
}
