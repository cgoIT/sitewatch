package collect

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"sitewatch/internal/report"
)

// collectHostInfo erfasst Betriebssystem, Netzwerk, apt-Updates und fehlgeschlagene systemd-Units. Alles lesend.
// Was fehlt (kein Linux, kein apt, kein systemd), bleibt nil und ist kein Problem; nur ein Fehler bei vorhandenem Programm wird gemeldet.
func collectHostInfo(ctx context.Context, cfg Config, r *report.Report, now time.Time, problem func(string, ...any)) {
	if runtime.GOOS != "linux" {
		return
	}
	r.Host.OS = collectOS(now)
	r.Host.Network = collectNetwork()
	if _, err := exec.LookPath("apt"); err == nil {
		out, se, code, err := runEnv(ctx, []string{"LC_ALL=C"}, cfg.Path, "apt", "list", "--upgradable")
		switch {
		case err != nil || code != 0:
			problem("apt list fehlgeschlagen: %s", firstLine(se))
		default:
			// Was apt wegen Phasing zurückstellt, würde ein Upgrade nicht einspielen: nicht als offen zählen. Die Simulation ändert nichts.
			sim, se, code, err := runEnv(ctx, []string{"LC_ALL=C"}, cfg.Path, "apt-get", "-s", "--with-new-pkgs", "upgrade")
			if err != nil || code != 0 {
				problem("apt-get -s upgrade fehlgeschlagen (zurückgestellte Updates zählen mit): %s", firstLine(se))
			}
			r.Host.Updates = ParseAptUpgradable(out, ParseAptDeferred(sim))
			if st, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil && now.Sub(st.ModTime()) > 3*24*time.Hour {
				problem("apt-Paketlisten sind %d Tage alt (apt update läuft nicht regelmäßig); die Update-Zahl kann zu niedrig sein", int(now.Sub(st.ModTime()).Hours()/24))
			}
		}
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil { // systemctl ohne laufendes systemd (Container) ist kein Fehler
		if _, err := exec.LookPath("systemctl"); err != nil {
			return
		}
		out, se, code, err := runEnv(ctx, nil, cfg.Path, "systemctl", "list-units", "--state=failed", "--plain", "--no-legend", "--no-pager")
		if err != nil || code != 0 {
			problem("systemctl fehlgeschlagen: %s", firstLine(se))
		} else {
			r.Host.Systemd = &report.Systemd{Failed: ParseFailedUnits(out)}
		}
		collectJournal(ctx, cfg, r, now, problem)
	}
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func collectOS(now time.Time) *report.OSInfo {
	o := &report.OSInfo{
		Name:    ParseOSRelease(readFile("/etc/os-release")),
		Kernel:  strings.TrimSpace(readFile("/proc/sys/kernel/osrelease")),
		UptimeS: ParseUptime(readFile("/proc/uptime")),
		CPUs:    runtime.NumCPU(),
	}
	if f := strings.Fields(readFile("/proc/loadavg")); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil && v >= 0 {
			o.Load1 = &v
		}
	}
	o.MemAvailPct, o.SwapUsedPct = ParseMeminfo(readFile("/proc/meminfo"))
	if st, err := os.Stat("/run/reboot-required"); err == nil {
		t := st.ModTime().UTC()
		o.RebootRequired, o.RebootSince = true, &t
	}
	return o
}

// ParseOSRelease liefert PRETTY_NAME aus /etc/os-release.
func ParseOSRelease(data string) string {
	for _, l := range strings.Split(data, "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// ParseUptime liest die Betriebszeit in Sekunden aus /proc/uptime.
func ParseUptime(data string) *int64 {
	f := strings.Fields(data)
	if len(f) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return nil
	}
	s := int64(v)
	return &s
}

// ParseMeminfo liefert den verfügbaren Arbeitsspeicher und den belegten Swap in Prozent (nil = unbekannt, kein Swap = nil).
func ParseMeminfo(data string) (memAvail, swapUsed *int) {
	kb := map[string]int64{}
	for _, l := range strings.Split(data, "\n") {
		k, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		if f := strings.Fields(rest); len(f) > 0 {
			if v, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				kb[k] = v
			}
		}
	}
	if t := kb["MemTotal"]; t > 0 {
		if a, ok := kb["MemAvailable"]; ok {
			p := int(a * 100 / t)
			memAvail = &p
		}
	}
	if t := kb["SwapTotal"]; t > 0 {
		p := int((t - kb["SwapFree"]) * 100 / t)
		swapUsed = &p
	}
	return
}

// collectNetwork liefert aktive Schnittstellen mit Adressen, die IPv4-Standardroute und die DNS-Server.
// shortcut: virtuelle Schnittstellen (Docker, veth, Bridges) und link-lokale Adressen werden ausgeblendet; bei Bedarf konfigurierbar machen.
func collectNetwork() *report.Network {
	n := &report.Network{Gateway: ParseDefaultGateway(readFile("/proc/net/route")), DNS: ParseResolv(readFile("/etc/resolv.conf"))}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || virtualIface(i.Name) {
			continue
		}
		addrs, _ := i.Addrs()
		var list []string
		for _, a := range addrs {
			if ip, _, err := net.ParseCIDR(a.String()); err == nil && !ip.IsLinkLocalUnicast() {
				list = append(list, a.String())
			}
		}
		if len(list) == 0 {
			continue
		}
		sort.Strings(list)
		n.Interfaces = append(n.Interfaces, report.Iface{Name: i.Name, Addrs: list[:min(len(list), 32)], MAC: i.HardwareAddr.String()})
	}
	if len(n.Interfaces) > 64 {
		n.Interfaces = n.Interfaces[:64]
	}
	return n
}

func virtualIface(name string) bool {
	for _, p := range []string{"veth", "docker", "br-", "virbr", "cni", "flannel", "cali"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ParseDefaultGateway liest die IPv4-Standardroute aus /proc/net/route (Adresse hexadezimal, little endian).
func ParseDefaultGateway(data string) string {
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
	}
	return ""
}

// ParseResolv liefert die nameserver-Einträge aus resolv.conf (höchstens 16).
func ParseResolv(data string) []string {
	var out []string
	for _, l := range strings.Split(data, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" && len(out) < 16 {
			out = append(out, f[1])
		}
	}
	return out
}

// ParseAptUpgradable liest "apt list --upgradable". Sicherheitsupdates erkennt man an einer Quelle mit "-security" im Namen.
// Pakete in deferred (siehe ParseAptDeferred) fehlen in Liste und Zahl.
// shortcut: keine Unterscheidung nach Priorität oder mit apt-mark zurückgehaltenen Paketen; die Liste ist auf 500 Einträge gekürzt (Total zählt alle).
func ParseAptUpgradable(data string, deferred map[string]bool) *report.OSUpdates {
	u := &report.OSUpdates{Manager: "apt"}
	for _, l := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(l, "/")
		if !ok || strings.ContainsAny(name, " \t") || deferred[name] {
			continue // "Listing...", Warnungen und zurückgestellte Pakete
		}
		f := strings.Fields(rest)
		if len(f) < 3 {
			continue
		}
		p := report.OSPackage{Name: name, New: f[1], Security: strings.Contains(f[0], "-security")}
		if i := strings.Index(l, "[upgradable from: "); i >= 0 {
			p.Installed = strings.TrimSuffix(strings.TrimSpace(l[i+len("[upgradable from: "):]), "]")
		}
		u.Total++
		if p.Security {
			u.Security++
		}
		if len(u.Packages) < 500 {
			u.Packages = append(u.Packages, p)
		}
	}
	// Sicherheitsupdates zuerst
	sort.SliceStable(u.Packages, func(i, j int) bool { return u.Packages[i].Security && !u.Packages[j].Security })
	return u
}

// ParseAptDeferred liest aus "apt-get -s upgrade" die Pakete, die apt wegen Phasing (gestaffelte Auslieferung) zurückstellt:
// der eingerückte Block nach "The following upgrades have been deferred due to phasing:".
func ParseAptDeferred(sim string) map[string]bool {
	out := map[string]bool{}
	_, rest, _ := strings.Cut(sim, "deferred due to phasing:\n")
	for _, l := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(l, " ") {
			break
		}
		for _, name := range strings.Fields(l) {
			out[name] = true
		}
	}
	return out
}

// ParseFailedUnits liest "systemctl list-units --state=failed --plain --no-legend".
func ParseFailedUnits(data string) []string {
	out := []string{}
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(strings.TrimLeft(l, " ●*×"))
		if len(f) > 0 && len(out) < 64 {
			out = append(out, f[0])
		}
	}
	return out
}

// sshMaxLines begrenzt die Ausgabe von journalctl (runEnv puffert sie ganz); mehr Fehlversuche am Tag zählt Sitewatch nicht.
const sshMaxLines = "100000"

// collectJournal liest Kernel-Fehler und zählt fehlgeschlagene SSH-Anmeldungen im Zeitfenster.
func collectJournal(ctx context.Context, cfg Config, r *report.Report, now time.Time, problem func(string, ...any)) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return
	}
	since := fmt.Sprintf("--since=-%ds", int(cfg.Window.Seconds()))
	if out, se, code, err := runEnv(ctx, nil, cfg.Path, "journalctl", "-k", "-p", "err", since, "-o", "short-iso", "--no-pager", "-q"); err != nil || code != 0 {
		problem("Kernel-Meldungen nicht lesbar: %s", firstLine(se))
	} else {
		r.Errors = ParseKernelLog(out, now, cfg.Window, cfg.MaxErrors)
	}
	// -t: Kennung der Meldung, unabhängig vom Namen der Unit (ssh/sshd); seit OpenSSH 9.8 schreibt sshd-session.
	// Ohne Treffer endet journalctl --grep mit Code 1 und leerer Ausgabe: das sind null Fehlversuche.
	out, se, code, err := runEnv(ctx, nil, cfg.Path, "journalctl", "-t", "sshd", "-t", "sshd-session", since, "-g", sshFailRe, "-n", sshMaxLines, "-o", "cat", "--no-pager", "-q")
	if err != nil || code > 1 || (code == 1 && strings.TrimSpace(se) != "") {
		problem("SSH-Anmeldungen nicht lesbar: %s", firstLine(se))
		return
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	r.Host.SSHFailed = &n
}
