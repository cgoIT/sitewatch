package store

import (
	"database/sql"
	"sort"
	"time"
)

// Zustände einer Erreichbarkeitsprüfung.
const (
	CheckUp    = "up"    // Antwort erhalten (2xx, 3xx, 401, 403)
	CheckMaint = "maint" // 503 im Wartungsmodus
	CheckDown  = "down"  // sonst, auch Zeitüberschreitung und Verbindungsfehler
)

// Check ist das Ergebnis einer Prüfung. Latenz = Zeit bis zu den Antwort-Headern (0 bei Fehlern).
type Check struct {
	At        time.Time
	State     string
	LatencyMS int
	Code      int
}

// UptimeSetting steuert die Prüfung einer Site. Ohne gespeicherte Zeile gilt DefaultUptime.
type UptimeSetting struct {
	Enabled   bool `json:"enabled"`
	IntervalS int  `json:"interval_s"`
}

// UptimeIntervals sind die wählbaren Abstände in Sekunden.
var UptimeIntervals = []int{60, 180, 300, 900}

func DefaultUptime() UptimeSetting { return UptimeSetting{Enabled: true, IntervalS: 180} }

// DayStat fasst die Prüfungen eines UTC-Tages zusammen. Day = Tage seit 1970 (UTC).
type DayStat struct{ Day, Checks, Ups, Maint int }

// Ratio ist die Erreichbarkeit des Tages; Wartung zählt nicht mit. ok=false: keine auswertbare Messung.
func (d DayStat) Ratio() (r float64, ok bool) {
	if n := d.Checks - d.Maint; n > 0 {
		return float64(d.Ups) / float64(n), true
	}
	return 0, false
}

// Outage ist eine zusammenhängende Folge fehlgeschlagener Prüfungen.
type Outage struct {
	From, To time.Time // erste und letzte fehlgeschlagene Prüfung
	Checks   int
}

// Uptime ist der Speicher der Erreichbarkeitsprüfung (SQLite).
type Uptime interface {
	AddCheck(siteID string, c Check) error
	RecentChecks(siteID string, n int) ([]Check, error) // neueste zuerst
	UptimeSettings() (map[string]UptimeSetting, error)  // nur gespeicherte Abweichungen
	SetUptimeSetting(siteID string, s UptimeSetting) error
	UptimeDays(since time.Time) (map[string][]DayStat, error) // je Site aufsteigend nach Tag
	MedianLatency(since time.Time) (map[string]int, error)    // Median der erfolgreichen Prüfungen, ms
	Outages(siteID string, since time.Time) ([]Outage, error) // aus den Rohwerten, neueste zuerst
}

const rawDays = 7 // so lange bleiben Einzelmessungen; danach nur noch eine Zeile je Tag

const dayNS = int64(24 * time.Hour)

func migrateUptime(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS uptime_raw(site_id TEXT NOT NULL, at INTEGER NOT NULL, state TEXT NOT NULL, latency_ms INTEGER NOT NULL, code INTEGER NOT NULL, PRIMARY KEY(site_id, at));
CREATE TABLE IF NOT EXISTS uptime_day(site_id TEXT NOT NULL, day INTEGER NOT NULL, checks INTEGER NOT NULL, ups INTEGER NOT NULL, maint INTEGER NOT NULL, PRIMARY KEY(site_id, day));
CREATE TABLE IF NOT EXISTS uptime_site(site_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, interval_s INTEGER NOT NULL);`)
	return err
}

func (s *SQLite) AddCheck(siteID string, c Check) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR REPLACE INTO uptime_raw(site_id, at, state, latency_ms, code) VALUES(?,?,?,?,?)`,
		siteID, c.At.UnixNano(), c.State, c.LatencyMS, c.Code)
	return err
}

func (s *SQLite) RecentChecks(siteID string, n int) ([]Check, error) {
	rows, err := s.db.Query(`SELECT at, state, latency_ms, code FROM uptime_raw WHERE site_id=? ORDER BY at DESC LIMIT ?`, siteID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		var c Check
		var at int64
		if err := rows.Scan(&at, &c.State, &c.LatencyMS, &c.Code); err != nil {
			return nil, err
		}
		c.At = time.Unix(0, at).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) UptimeSettings() (map[string]UptimeSetting, error) {
	rows, err := s.db.Query(`SELECT site_id, enabled, interval_s FROM uptime_site`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]UptimeSetting{}
	for rows.Next() {
		var id string
		var u UptimeSetting
		if err := rows.Scan(&id, &u.Enabled, &u.IntervalS); err != nil {
			return nil, err
		}
		out[id] = u
	}
	return out, rows.Err()
}

// SetUptimeSetting speichert die Einstellung; der Standard wird nicht gespeichert, sondern die Zeile gelöscht.
func (s *SQLite) SetUptimeSetting(siteID string, u UptimeSetting) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u == DefaultUptime() {
		_, err := s.db.Exec(`DELETE FROM uptime_site WHERE site_id=?`, siteID)
		return err
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO uptime_site(site_id, enabled, interval_s) VALUES(?,?,?)`, siteID, u.Enabled, u.IntervalS)
	return err
}

// shortcut: kein Index auf uptime_raw(at); die Abfragen über alle Sites lesen die Rohwerte von 7 Tagen vollständig, bei vielen Sites ergänzen.
// UptimeDays liefert je Site die Tageswerte ab dem Tag von since: verdichtete Tage und die Rohwerte der letzten Tage.
// Ein Tag ist nie in beiden Quellen (Maintain verdichtet nur ganze Tage und löscht deren Rohwerte).
func (s *SQLite) UptimeDays(since time.Time) (map[string][]DayStat, error) {
	rows, err := s.db.Query(`
SELECT site_id, day, checks, ups, maint FROM uptime_day WHERE day >= ?1
UNION ALL
SELECT site_id, at/?2, COUNT(*), SUM(state='up'), SUM(state='maint') FROM uptime_raw WHERE at >= ?1*?2 GROUP BY site_id, at/?2
ORDER BY 1, 2`, since.UTC().UnixNano()/dayNS, dayNS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]DayStat{}
	for rows.Next() {
		var id string
		var d DayStat
		if err := rows.Scan(&id, &d.Day, &d.Checks, &d.Ups, &d.Maint); err != nil {
			return nil, err
		}
		out[id] = append(out[id], d)
	}
	return out, rows.Err()
}

func (s *SQLite) MedianLatency(since time.Time) (map[string]int, error) {
	rows, err := s.db.Query(`SELECT site_id, latency_ms FROM uptime_raw WHERE at >= ? AND state='up' ORDER BY site_id, latency_ms`, since.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	vals := map[string][]int{}
	for rows.Next() {
		var id string
		var ms int
		if err := rows.Scan(&id, &ms); err != nil {
			return nil, err
		}
		if _, ok := vals[id]; !ok {
			ids = append(ids, id)
		}
		vals[id] = append(vals[id], ms)
	}
	out := map[string]int{}
	for _, id := range ids {
		out[id] = vals[id][len(vals[id])/2]
	}
	return out, rows.Err()
}

func (s *SQLite) Outages(siteID string, since time.Time) ([]Outage, error) {
	rows, err := s.db.Query(`SELECT at, state FROM uptime_raw WHERE site_id=? AND at >= ? ORDER BY at`, siteID, since.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Outage
	open := false
	for rows.Next() {
		var at int64
		var st string
		if err := rows.Scan(&at, &st); err != nil {
			return nil, err
		}
		t := time.Unix(0, at).UTC()
		switch {
		case st == CheckDown && open:
			out[len(out)-1].To, out[len(out)-1].Checks = t, out[len(out)-1].Checks+1
		case st == CheckDown:
			out, open = append(out, Outage{From: t, To: t, Checks: 1}), true
		case st == CheckUp:
			open = false // Wartung unterbricht eine Folge nicht
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From.After(out[j].From) })
	return out, rows.Err()
}

// compactUptime verdichtet ganze Tage, die älter als rawDays sind, und löscht verdichtete Tage nach MaxDays. Aufruf aus Maintain (hält s.mu).
func (s *SQLite) compactUptime(tx *sql.Tx, now time.Time) error {
	cut := now.UTC().AddDate(0, 0, -rawDays).UnixNano() / dayNS * dayNS // Beginn des Tages vor rawDays Tagen
	if _, err := tx.Exec(`
INSERT OR REPLACE INTO uptime_day(site_id, day, checks, ups, maint)
SELECT site_id, at/?1, COUNT(*), SUM(state='up'), SUM(state='maint') FROM uptime_raw WHERE at < ?2 GROUP BY site_id, at/?1`, dayNS, cut); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM uptime_raw WHERE at < ?`, cut); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM uptime_day WHERE day < ?`, now.UTC().AddDate(0, 0, -s.ret.MaxDays).UnixNano()/dayNS)
	return err
}
