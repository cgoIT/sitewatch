package collect

import (
	"os"
	"regexp"
	"strings"

	"sitewatch/internal/report"
)

var mdCountRe = regexp.MustCompile(`\[(\d+)/(\d+)\]`)

// collectRAID liest die Linux-Software-RAIDs aus /proc/mdstat. Ohne die Datei (kein Linux, kein md) bleibt die Liste leer.
func collectRAID(r *report.Report) {
	if data, err := os.ReadFile("/proc/mdstat"); err == nil {
		r.Host.Raids = ParseMdstat(string(data))
	}
}

// ParseMdstat liest den Inhalt von /proc/mdstat.
// shortcut: Hardware-RAID (MegaRAID, Adaptec) und ZFS/btrfs-Verbünde fehlen; bei Bedarf eigene Quellen ergänzen.
func ParseMdstat(data string) []report.Raid {
	var out []report.Raid
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && strings.HasPrefix(f[0], "md") && f[1] == ":":
			a := report.Raid{Name: f[0], Inactive: f[2] == "inactive"}
			for _, w := range f[3:] {
				switch {
				case strings.Contains(w, "["): // Mitglied, z. B. sda1[0] oder sdb1[1](F)
					if strings.HasSuffix(w, "(F)") {
						a.Failed++
					}
				case a.Level == "" && !strings.HasPrefix(w, "("): // "(auto-read-only)" überspringen
					a.Level = w
				}
			}
			out = append(out, a)
		case len(out) > 0 && line != "" && (line[0] == ' ' || line[0] == '\t'):
			a := &out[len(out)-1]
			if m := mdCountRe.FindStringSubmatch(line); m != nil {
				a.Total, a.Active = atoi(m[1]), atoi(m[2])
			}
			if strings.Contains(line, "%") && (strings.Contains(line, "recovery") || strings.Contains(line, "resync") ||
				strings.Contains(line, "reshape") || strings.Contains(line, "check")) {
				a.Syncing = true
			}
		}
	}
	return out
}

func atoi(s string) (n int) {
	for _, c := range s {
		n = n*10 + int(c-'0') // s besteht laut mdCountRe nur aus Ziffern
	}
	return n
}
