package collect

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sitewatch/internal/report"
)

// Monolog-Zeile: [2026-10-27T19:02:11.123456+01:00] request.CRITICAL: Nachricht {...} []
var lineRe = regexp.MustCompile(`^\[([^\]]+)\] [^.\s]+\.([A-Z]+): (.*)$`)

var errorLevels = map[string]bool{"ERROR": true, "CRITICAL": true, "ALERT": true, "EMERGENCY": true}

const tailBytes = 512 * 1024

// logParser erkennt eine Fehlerzeile (ERROR und höher). loc gilt für Zeitangaben ohne Zone.
type logParser func(line string) (ts time.Time, level, msg string, ok bool)

func parseMonolog(line string) (time.Time, string, string, bool) {
	m := lineRe.FindStringSubmatch(line)
	if m == nil || !errorLevels[m[2]] {
		return time.Time{}, "", "", false
	}
	ts, err := time.Parse(time.RFC3339Nano, m[1])
	return ts, m[2], m[3], err == nil
}

// Logs des Website-Stacks unter <SITE_DIR>/logs. Zeiten ohne Zone gelten in der Zone des Servers.
// shortcut: läuft ein Container in einer anderen Zeitzone als der Server, verschiebt sich das Zeitfenster; bei Bedarf Zone je Site konfigurieren.
var (
	// 2026/11/10 05:45:44 [error] 38#38: *37167 Meldung, client: 1.2.3.4, server: _, request: "..."
	nginxErrRe = regexp.MustCompile(`^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(error|crit|alert|emerg)\] \d+#\d+: (?:\*\d+ )?(.*)$`)
	// [10-Nov-2026 00:04:07] ERROR: Meldung
	fpmErrRe = regexp.MustCompile(`^\[(\d\d-\w{3}-\d{4} \d\d:\d\d:\d\d)\] (ERROR|ALERT): (.*)$`)
	// [01-Nov-2026 17:26:16 Europe/Berlin] PHP Fatal error:  Meldung
	phpErrRe = regexp.MustCompile(`^\[(\d\d-\w{3}-\d{4} \d\d:\d\d:\d\d)(?: ([^\]]+))?\] PHP (Fatal error|Parse error|Recoverable fatal error):\s+(.*)$`)
)

func parseNginxError(line string) (time.Time, string, string, bool) {
	m := nginxErrRe.FindStringSubmatch(line)
	// "access forbidden by rule" ist die Sperrregel für Scanner (.git, .env) und kein Fehler der Site; die Treffer zählen als 403 in den Zugriffen.
	if m == nil || strings.HasPrefix(m[3], "access forbidden by rule") {
		return time.Time{}, "", "", false
	}
	ts, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
	msg, _, _ := strings.Cut(m[3], ", client: ") // Adresse und Anfrage weglassen: gleiche Meldungen gruppieren, keine Besucheradressen melden
	return ts, "nginx " + m[2], msg, err == nil
}

func parseFPMError(line string) (time.Time, string, string, bool) {
	m := fpmErrRe.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, "", "", false
	}
	ts, err := time.ParseInLocation("02-Jan-2006 15:04:05", m[1], time.Local)
	return ts, "FPM " + m[2], m[3], err == nil
}

func parsePHPError(line string) (time.Time, string, string, bool) {
	m := phpErrRe.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, "", "", false
	}
	loc := time.Local
	if l, err := time.LoadLocation(m[2]); err == nil && m[2] != "" {
		loc = l
	}
	ts, err := time.ParseInLocation("02-Jan-2006 15:04:05", m[1], loc)
	return ts, "PHP " + m[3], m[4], err == nil
}

// errorSet gruppiert gleiche Meldungen aus mehreren Logs.
type errorSet struct {
	now, since time.Time
	groups     map[[2]string]*report.LogError
}

func newErrorSet(now time.Time, window time.Duration) *errorSet {
	return &errorSet{now: now, since: now.Add(-window), groups: map[[2]string]*report.LogError{}}
}

// add liest die Dateien (jeweils nur das Ende, nur wenn im Zeitfenster geändert). Fehlende Dateien sind kein Fehler;
// eine vorhandene, aber nicht lesbare Datei liefert den ersten solchen Fehler (die übrigen werden trotzdem gelesen).
func (s *errorSet) add(parse logParser, files ...string) (first error) {
	for _, f := range files {
		st, err := os.Stat(f)
		if err == nil && st.ModTime().Before(s.since) {
			continue
		}
		var lines []string
		if err == nil {
			lines, err = tailLines(f, tailBytes)
		}
		if err != nil {
			if first == nil && !errors.Is(err, os.ErrNotExist) {
				first = err
			}
			continue
		}
		for _, line := range lines {
			s.addLine(parse, line)
		}
	}
	return first
}

func (s *errorSet) addLine(parse logParser, line string) {
	ts, level, msg, ok := parse(line)
	if !ok || ts.Before(s.since) || ts.After(s.now.Add(5*time.Minute)) {
		return
	}
	k := [2]string{level, cleanMessage(msg)}
	if g, ok := s.groups[k]; ok {
		g.Count++
		if ts.After(g.Time) {
			g.Time = ts.UTC()
		}
	} else {
		s.groups[k] = &report.LogError{Time: ts.UTC(), Level: k[0], Message: k[1], Count: 1}
	}
}

// list liefert die Gruppen, neueste zuerst, höchstens max.
func (s *errorSet) list(max int) []report.LogError {
	out := make([]report.LogError, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// addContao nimmt die Fehler aus var/logs/*.log (Monolog) auf.
func (s *errorSet) addContao(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
	return errors.Join(err, s.add(parseMonolog, files...))
}

// addStack nimmt die Fehler aus nginx und PHP des Website-Stacks auf (logs = <SITE_DIR>/logs; rotiert wird täglich nach backup/<name>.1).
func (s *errorSet) addStack(logs string) error {
	var errs []error
	for name, parse := range map[string]logParser{"nginx/error.log": parseNginxError, "php/error.log": parsePHPError, "php/fpm-error.log": parseFPMError} {
		dir, file := filepath.Split(name)
		errs = append(errs, s.add(parse, filepath.Join(logs, name), filepath.Join(logs, dir, "backup", file+".1")))
	}
	return errors.Join(errs...)
}

// ReadLogErrors liest Fehler (ERROR und höher) der letzten window aus var/logs/*.log
// und gruppiert gleiche Meldungen. Neueste zuerst.
func ReadLogErrors(dir string, now time.Time, window time.Duration, max int) ([]report.LogError, error) {
	s := newErrorSet(now, window)
	err := s.addContao(dir)
	return s.list(max), err
}

// accessLine: die Felder einer Zeile des nginx-Access-Logs (JSON), die gezählt werden.
type accessLine struct {
	Time       time.Time `json:"time"`
	Status     int       `json:"status"`
	RemoteAddr string    `json:"remote_addr"`
	UserAgent  string    `json:"user_agent"`
}

// ReadTraffic zählt die Zugriffe der letzten window im nginx-Access-Log des Website-Stacks (eine JSON-Zeile je Anfrage). Nur Summen.
// Nicht gezählt: Anfragen vom Server selbst (FPM-Ping, Cron-Aufruf) und die Erreichbarkeitsprüfung von Sitewatch.
// nil ohne Fehler = kein Access-Log vorhanden.
// shortcut: liest die Dateien des Zeitfensters jedes Mal ganz (heute + gestern); bei sehr großen Logs die Startposition per Bisektion suchen.
func ReadTraffic(logs string, now time.Time, window time.Duration) (*report.Traffic, error) {
	since := now.Add(-window)
	var t *report.Traffic
	for _, name := range []string{filepath.Join(logs, "nginx", "access.log"), filepath.Join(logs, "nginx", "backup", "access.log.1")} {
		f, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if t == nil {
			t = &report.Traffic{}
		}
		st, err := f.Stat()
		if err != nil || st.ModTime().Before(since) {
			f.Close()
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		lines, parsed := 0, 0
		for sc.Scan() {
			lines++
			var l accessLine
			if json.Unmarshal(sc.Bytes(), &l) != nil || l.Status == 0 {
				continue
			}
			parsed++
			if l.Time.Before(since) || l.Time.After(now.Add(5*time.Minute)) || l.RemoteAddr == "127.0.0.1" || l.RemoteAddr == "::1" || l.UserAgent == "Sitewatch-Uptime" {
				continue
			}
			t.Requests++
			switch l.Status / 100 {
			case 4:
				t.Status4xx++
			case 5:
				t.Status5xx++
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
		if lines > 0 && parsed == 0 {
			return nil, fmt.Errorf("%s hat kein bekanntes Format (erwartet: eine JSON-Zeile je Anfrage mit time und status)", name)
		}
	}
	return t, nil
}

// journal: 2026-11-10T05:45:44+0100 server kernel: Meldung (journalctl -o short-iso; neuere Versionen schreiben +01:00)
var kernelRe = regexp.MustCompile(`^(\S+) \S+ kernel: (.*)$`)

func parseKernel(line string) (time.Time, string, string, bool) {
	m := kernelRe.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, "", "", false
	}
	ts, err := time.Parse("2006-01-02T15:04:05-0700", m[1])
	if err != nil {
		ts, err = time.Parse(time.RFC3339, m[1])
	}
	return ts, "Kernel", m[2], err == nil
}

// ParseKernelLog gruppiert die Ausgabe von "journalctl -k -p err -o short-iso".
func ParseKernelLog(out string, now time.Time, window time.Duration, max int) []report.LogError {
	s := newErrorSet(now, window)
	for _, line := range strings.Split(out, "\n") {
		s.addLine(parseKernel, line)
	}
	return s.list(max)
}

// sshFailRe: fehlgeschlagene Anmeldungen in den Meldungen von sshd. Grobe Zahl, kein Sicherheitsprotokoll:
// ein Versuch kann zwei Zeilen treffen (Fehlversuch und Verbindungsende), und ein abgebrochener Aufbau eines eigenen Clients zählt mit.
const sshFailRe = `Failed password for|(Connection closed by|Disconnected from) (authenticating|invalid) user`

// cleanMessage schneidet Monolog-Kontext (" {...}" / " []") ab und kürzt.
func cleanMessage(s string) string {
	for _, sep := range []string{" {\"", " []", " {}"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func tailLines(path string, max int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	partial := false
	if st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return nil, err
		}
		partial = true
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if partial && len(lines) > 0 {
		lines = lines[1:] // erste Zeile ist angeschnitten
	}
	return lines, sc.Err()
}
