package collect

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"time"

	"sitewatch/internal/report"
)

// collectSMART liest den SMART-Zustand aller Platten über smartctl (smartmontools, braucht Root-Rechte bzw. Gruppe disk).
// Fehlt smartctl, ist das ein Problem (Warnung), damit eine unüberwachte Platte nicht unbemerkt bleibt; VMs schalten die Abfrage je Site ab.
// Findet smartctl keine Platten, bleibt die Liste leer.
func collectSMART(ctx context.Context, cfg Config, r *report.Report, problem func(string, ...any)) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second) // Gesamtbudget, damit hängende Platten den Report-Zyklus nicht blockieren
	defer cancel()
	bin := or(cfg.Smartctl, "smartctl")
	out, _, _, err := runEnv(ctx, cfg.Env, cfg.Path, bin, "-j", "--scan")
	if err != nil {
		problem("smartctl nicht ausführbar (smartmontools installieren oder SMART für diese Site abschalten): %v", err)
		return
	}
	var scan struct {
		Devices []struct{ Name, Type string } `json:"devices"`
	}
	if json.Unmarshal([]byte(out), &scan) != nil {
		problem("smartctl --scan lieferte kein gültiges JSON")
		return
	}
	var unreadable []string
	for _, dev := range scan.Devices {
		if dev.Name == "" || dev.Name[0] == '-' { // kein Gerät, sondern eine Option
			continue
		}
		out, _, _, err := runEnv(ctx, cfg.Env, cfg.Path, bin, smartArgs(dev.Type, dev.Name)...)
		d, ok := ParseSMART(out)
		if err != nil || !ok {
			unreadable = append(unreadable, dev.Name)
			continue
		}
		d.Device = dev.Name
		r.Host.Disks = append(r.Host.Disks, d)
	}
	switch {
	case len(unreadable) > 3: // eine Sammelzeile, damit viele Platten nicht das Problem-Limit des Reports sprengen
		problem("SMART bei %d Platten nicht lesbar (Rechte? smartctl braucht Root)", len(unreadable))
	case len(unreadable) > 0:
		problem("SMART nicht lesbar: %s (Rechte? smartctl braucht Root)", strings.Join(unreadable, ", "))
	}
}

// smartArgs baut die Argumente für eine Platte. Der Typ aus --scan wird nur für Controller-Typen übernommen, die smartctl nicht selbst
// erkennt (megaraid,N, 3ware,N, cciss,N ...). "scsi" (meldet --scan auch für SATA-Platten hinter dem SCSI-Layer) bleibt der
// Autoerkennung überlassen ("sat" wird übernommen, USB-Adapter brauchen es): mit "-d scsi" fehlen bei SATA-Platten die ATA-Attribute, also Temperatur und defekte Sektoren.
func smartArgs(typ, name string) []string {
	args := []string{"-j", "-H", "-A"}
	if typ != "" && typ != "scsi" {
		args = append(args, "-d", typ)
	}
	return append(args, name)
}

// ParseSMART liest die JSON-Ausgabe von "smartctl -j -H -A". ok=false: kein SMART-Urteil enthalten.
// smartctl setzt auch bei gesundem Gerät Exit-Bits, deshalb zählt nur der Inhalt.
func ParseSMART(data string) (report.Disk, bool) {
	d, ok, _ := parseSMART(data)
	return d, ok
}

// parseSMART wie ParseSMART; badPct meldet, dass ein Prozentwert außerhalb 0..255 lag (die NVMe-Spezifikation kennt nur 8 Bit)
// und deshalb unbekannt (nil) bleibt, damit nicht der ganze Report an der Validierung scheitert.
func parseSMART(data string) (d report.Disk, ok, badPct bool) {
	var doc struct {
		Model  string `json:"model_name"`
		Serial string `json:"serial_number"`
		Status *struct {
			Passed *bool `json:"passed"`
		} `json:"smart_status"`
		Temp *struct {
			Current *int `json:"current"`
		} `json:"temperature"`
		ATA struct {
			Table []struct {
				ID  int `json:"id"`
				Raw struct {
					Value int64 `json:"value"`
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
		NVMe *struct {
			MediaErrors  int64  `json:"media_errors"`
			PercentUsed  *int   `json:"percentage_used"`
			AvailSpare   *int   `json:"available_spare"`
			UnitsWritten *int64 `json:"data_units_written"`
		} `json:"nvme_smart_health_information_log"`
	}
	if json.Unmarshal([]byte(data), &doc) != nil || doc.Status == nil || doc.Status.Passed == nil {
		return report.Disk{}, false, false
	}
	d = report.Disk{Model: doc.Model, Serial: strings.TrimSpace(doc.Serial), Passed: doc.Status.Passed}
	if doc.Temp != nil && doc.Temp.Current != nil && *doc.Temp.Current > 0 { // 0 °C heißt: nicht ermittelt
		d.TempC = doc.Temp.Current
	}
	bad, have := int64(0), false
	for _, a := range doc.ATA.Table {
		if a.ID == 5 || a.ID == 197 || a.ID == 198 { // Reallocated, Pending, Offline Uncorrectable
			bad, have = bad+min(max(a.Raw.Value, 0), 1<<30), true
		}
	}
	if doc.NVMe != nil {
		bad, have = doc.NVMe.MediaErrors, true
		inRange := func(p *int) *int {
			if p != nil && (*p < 0 || *p > 255) {
				badPct = true
				return nil
			}
			return p
		}
		d.WearPct, d.SpareLeftPct = inRange(doc.NVMe.PercentUsed), inRange(doc.NVMe.AvailSpare)
		if u := doc.NVMe.UnitsWritten; u != nil && *u >= 0 && *u <= math.MaxInt64/512000 { // eine Einheit = 1000 Sektoren à 512 Byte
			b := *u * 512000
			d.WrittenBytes = &b
		}
	}
	if have {
		n := int(min(bad, 1<<30))
		d.BadSectors = &n
	}
	return d, true, badPct
}
