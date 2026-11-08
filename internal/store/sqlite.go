package store

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"sitewatch/internal/report"
)

// SQLite ist der Store auf einer SQLite-Datei.
type SQLite struct {
	db  *sql.DB
	ret Retention
	mu  sync.Mutex // serialisiert Schreibzugriffe (eine Verbindung, WAL)
}

const schema = `
CREATE TABLE IF NOT EXISTS daily_reports(
  site_id TEXT NOT NULL, day TEXT NOT NULL, received_ns INTEGER NOT NULL, collected_ns INTEGER NOT NULL, report TEXT NOT NULL,
  PRIMARY KEY(site_id, day));
CREATE TABLE IF NOT EXISTS samples(
  site_id TEXT NOT NULL, at INTEGER NOT NULL, level INTEGER NOT NULL, disk INTEGER, updates INTEGER NOT NULL, errors INTEGER NOT NULL,
  migrations INTEGER, cron_age INTEGER, backup_age INTEGER, contao TEXT, php TEXT, mariadb TEXT, nginx TEXT,
  PRIMARY KEY(site_id, at));
CREATE TABLE IF NOT EXISTS alert_state(site_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, agent TEXT NOT NULL, site TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
  approved_by TEXT NOT NULL, created_ns INTEGER NOT NULL, expires_ns INTEGER NOT NULL, started_ns INTEGER, finished_ns INTEGER, exit_code INTEGER,
  envelope TEXT NOT NULL, cancel INTEGER NOT NULL DEFAULT 0, out_bytes INTEGER NOT NULL DEFAULT 0, truncated INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS jobs_agent ON jobs(agent, status);
CREATE TABLE IF NOT EXISTS job_chunks(job_id TEXT NOT NULL, seq INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(job_id, seq));
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY, type TEXT NOT NULL DEFAULT '', token_hash TEXT NOT NULL, config TEXT NOT NULL, updated TEXT NOT NULL);`

// baseVersion ist die Schemaversion, die schema beschreibt (PRAGMA user_version). schema bleibt dieser Ausgangsstand und wird nie geändert;
// jede spätere Änderung ist ein Eintrag in migrations. Eine Datenbank ohne Version (user_version 0) ist eine, die vor der Versionierung
// angelegt wurde und genau diesem Stand entspricht.
const baseVersion = 1

// migrations: Eintrag i hebt die Datenbank von Version baseVersion+i auf baseVersion+i+1. Jeder läuft in einer eigenen Transaktion
// zusammen mit dem Setzen der Version, ein Fehler lässt die Datenbank unverändert.
var migrations = []func(tx *sql.Tx) error{migrateUptime, migratePush}

// migrate bringt die Datenbank auf die aktuelle Version. Eine neuere Datenbank (Programm zurückgerollt) wird nicht angefasst.
// Die Version wird je Schritt innerhalb der Transaktion gelesen: Starten zwei Prozesse gleichzeitig, führt nur einer eine Migration aus.
// shortcut: zwei gleichzeitige Starter können sich um die Schreibsperre streiten (SQLITE_BUSY nach busy_timeout); ein Prozess je Datenbank ist der Normalfall.
func migrate(db *sql.DB) error {
	want := baseVersion + len(migrations)
	for {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		var v int
		if err := tx.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
			_ = tx.Rollback() // der Fehler davor zählt
			return fmt.Errorf("Schemaversion lesen: %w", err)
		}
		switch {
		case v > want:
			_ = tx.Rollback()
			return fmt.Errorf("die Datenbank hat Schemaversion %d, dieses Programm kennt nur %d; bitte Sitewatch aktualisieren", v, want)
		case v == want:
			return tx.Rollback()
		}
		step := func(tx *sql.Tx) error { return nil } // unversionierte Altdatenbank: Schema ist schon Version 1
		if v >= baseVersion {
			step = migrations[v-baseVersion]
		}
		next := max(v, baseVersion-1) + 1
		if err := step(tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Migration auf Version %d: %w", next, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, next)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("Schemaversion %d setzen: %w", next, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("Schemaversion %d speichern: %w", next, err)
		}
	}
}

// OpenSQLite öffnet (und legt bei Bedarf an) die Datenbank. Die Datei ist nur für den Besitzer lesbar.
func OpenSQLite(path string, ret Retention) (*SQLite, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, errors.New("Pfad der Datenbank darf kein ? oder # enthalten")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db, ret: ret}, nil
}

// Close schließt die Datenbank.
func (s *SQLite) Close() error { return s.db.Close() }

// Setting liest eine Einstellung des Cockpits (Tabelle meta, Schlüssel mit Präfix); ok=false: nicht gesetzt.
func (s *SQLite) Setting(key string) (value string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT value FROM meta WHERE key=?`, "setting."+key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

// SetSetting speichert eine Einstellung; DeleteSetting setzt sie zurück.
func (s *SQLite) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "setting."+key, value)
	return err
}

// DeleteSetting entfernt eine Einstellung, es gilt dann wieder der Standard.
func (s *SQLite) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM meta WHERE key=?`, "setting."+key)
	return err
}

// SetRetention ändert die Aufbewahrung; sie gilt ab der nächsten Bereinigung (Maintain).
func (s *SQLite) SetRetention(r Retention) {
	s.mu.Lock()
	s.ret = r
	s.mu.Unlock()
}

// DB liefert die Datenbank für Tabellen anderer Pakete (Agenten); sie nutzen dieselbe einzige Verbindung.
func (s *SQLite) DB() *sql.DB { return s.db }

// Save speichert den Report als Tagesstand und als Messpunkt. level ist die Bewertung zum Eingang (status.Level als Zahl).
// Ein älterer, nachgesendeter Report überschreibt den Tagesstand nicht.
func (s *SQLite) Save(e Entry, level int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(e, level)
}

func (s *SQLite) save(e Entry, level int) error {
	id := e.Report.Site.ID
	if !report.ValidID(id) {
		return errors.New("ungültige Site-ID")
	}
	data, err := json.Marshal(e.Report)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Ein später eintreffender älterer Report (nachgesendeter Spool) überschreibt den Tagesstand nicht.
	if _, err := tx.Exec(`INSERT INTO daily_reports(site_id, day, received_ns, collected_ns, report) VALUES(?,?,?,?,?)
		ON CONFLICT(site_id, day) DO UPDATE SET received_ns=excluded.received_ns, collected_ns=excluded.collected_ns, report=excluded.report
		WHERE excluded.collected_ns >= daily_reports.collected_ns`,
		id, e.ReceivedAt.UTC().Format("2006-01-02"), e.ReceivedAt.UnixNano(), e.Report.CollectedAt.UnixNano(), string(data)); err != nil {
		return err
	}
	sm := SampleOf(e, level)
	if _, err := tx.Exec(`INSERT OR REPLACE INTO samples(site_id, at, level, disk, updates, errors, migrations, cron_age, backup_age, contao, php, mariadb, nginx)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, sm.At.Unix(), sm.Level, nullInt(sm.DiskFreePct), sm.OpenUpdates, sm.Errors, nullInt(sm.PendingMigrations),
		nullInt(sm.CronAgeSec), nullInt(sm.BackupAgeSec), sm.Contao, sm.PHP, sm.MariaDB, sm.Nginx); err != nil {
		return err
	}
	return tx.Commit()
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func ptr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func scanEntry(sc interface{ Scan(...any) error }) (Entry, error) {
	var data string
	var ns int64
	if err := sc.Scan(&data, &ns); err != nil {
		return Entry{}, err
	}
	var e Entry
	e.ReceivedAt = time.Unix(0, ns).UTC()
	return e, json.Unmarshal([]byte(data), &e.Report)
}

// Latest liefert je Site den jüngsten Report, nach Site-ID sortiert.
func (s *SQLite) Latest() ([]Entry, error) {
	rows, err := s.db.Query(`SELECT report, received_ns FROM daily_reports d
		WHERE day = (SELECT MAX(day) FROM daily_reports WHERE site_id = d.site_id) ORDER BY site_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get liefert den jüngsten Report einer Site; ok ist false, wenn sie noch nie gemeldet hat.
func (s *SQLite) Get(siteID string) (Entry, bool, error) {
	e, err := scanEntry(s.db.QueryRow(`SELECT report, received_ns FROM daily_reports WHERE site_id=? ORDER BY day DESC LIMIT 1`, siteID))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, false, nil
	}
	return e, err == nil, err
}

// GetDay liefert den Tagesstand (letzter Report des Tages, UTC, Format YYYY-MM-DD).
func (s *SQLite) GetDay(siteID, day string) (Entry, bool, error) {
	e, err := scanEntry(s.db.QueryRow(`SELECT report, received_ns FROM daily_reports WHERE site_id=? AND day=?`, siteID, day))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, false, nil
	}
	return e, err == nil, err
}

// Days liefert die Tage mit Tagesstand, neueste zuerst.
func (s *SQLite) Days(siteID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT day FROM daily_reports WHERE site_id=? ORDER BY day DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

const sampleCols = "at, level, disk, updates, errors, migrations, cron_age, backup_age, contao, php, mariadb, nginx"

// scanSample liest eine Zeile mit sampleCols; lead nimmt davor stehende Spalten auf (z. B. site_id).
func scanSample(sc interface{ Scan(...any) error }, lead ...any) (Sample, error) {
	var sm Sample
	var at int64
	var disk, mig, cron, backup sql.NullInt64
	dest := append(lead, &at, &sm.Level, &disk, &sm.OpenUpdates, &sm.Errors, &mig, &cron, &backup, &sm.Contao, &sm.PHP, &sm.MariaDB, &sm.Nginx)
	if err := sc.Scan(dest...); err != nil {
		return sm, err
	}
	sm.At = time.Unix(at, 0).UTC()
	sm.DiskFreePct, sm.PendingMigrations, sm.CronAgeSec, sm.BackupAgeSec = ptr(disk), ptr(mig), ptr(cron), ptr(backup)
	return sm, nil
}

// History liefert die Messpunkte einer Site, neueste zuerst; limit <= 0 heißt alle.
func (s *SQLite) History(siteID string, limit int) ([]Sample, error) {
	if limit <= 0 {
		limit = -1 // SQLite: kein Limit
	}
	rows, err := s.db.Query(`SELECT `+sampleCols+` FROM samples WHERE site_id=? ORDER BY at DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		sm, err := scanSample(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

// Baselines liefert je Site den ältesten Punkt ab since (Vergleichswert für Trendpfeile). Sites ohne Punkt fehlen.
func (s *SQLite) Baselines(since time.Time) (map[string]Sample, error) {
	rows, err := s.db.Query(`SELECT s.site_id, s.at, s.level, s.disk, s.updates, s.errors, s.migrations, s.cron_age, s.backup_age, s.contao, s.php, s.mariadb, s.nginx
		FROM samples s JOIN (SELECT site_id, MIN(at) m FROM samples WHERE at >= ? GROUP BY site_id) x ON s.site_id = x.site_id AND s.at = x.m`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Sample{}
	for rows.Next() {
		var id string
		sm, err := scanSample(rows, &id)
		if err != nil {
			return nil, err
		}
		out[id] = sm
	}
	return out, rows.Err()
}

// AlertState liefert die Sites, für die ein Alarm offen ist (siehe alert.State).
func (s *SQLite) AlertState() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT site_id FROM alert_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// DeleteSite entfernt alle Daten der Site: Tagesstände, Verlauf, Alarmzustand und Aufträge samt Ausgabe, atomar in einer Transaktion.
// Gibt es nichts, ist das kein Fehler. Auch noch offene Aufträge werden gelöscht; ein späteres Ergebnis des Agenten läuft dann ins Leere.
// Neue Tabellen mit Site-Bezug müssen hier ergänzt werden (TestDeleteSite prüft die bestehenden).
func (s *SQLite) DeleteSite(siteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM job_chunks WHERE job_id IN (SELECT id FROM jobs WHERE site=?)`,
		`DELETE FROM jobs WHERE site=?`,
		`DELETE FROM daily_reports WHERE site_id=?`,
		`DELETE FROM samples WHERE site_id=?`,
		`DELETE FROM alert_state WHERE site_id=?`,
		`DELETE FROM uptime_raw WHERE site_id=?`,
		`DELETE FROM uptime_day WHERE site_id=?`,
		`DELETE FROM uptime_site WHERE site_id=?`,
	} {
		if _, err := tx.Exec(q, siteID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetAlerted merkt sich (on) oder vergisst (!on), dass für die Site ein Alarm ausgelöst wurde, damit er nicht bei jeder Prüfung neu kommt.
func (s *SQLite) SetAlerted(siteID string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := `DELETE FROM alert_state WHERE site_id=?`
	if on {
		q = `INSERT OR IGNORE INTO alert_state(site_id) VALUES(?)`
	}
	_, err := s.db.Exec(q, siteID)
	return err
}

// Maintain verdichtet den Verlauf und löscht Abgelaufenes. Wiederholbar: Ein zweiter Lauf ändert nichts mehr.
//   - älter als FullDays: ein Punkt je 6-Stunden-Block (der letzte; Status = schlimmster, Speicher = kleinster Wert im Block)
//   - älter als SixHourDays: ein Punkt je Tag, gleiche Regel
//   - älter als MaxDays: gelöscht
//
// Vollständige Tagesstände älter als ReportDays werden gelöscht, der jüngste je Site bleibt.
func (s *SQLite) Maintain(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	day := func(n int) int64 { return now.AddDate(0, 0, -n).Unix() }
	cut30, cut90, cut365 := day(s.ret.FullDays), day(s.ret.SixHourDays), day(s.ret.MaxDays)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM samples WHERE at < ?`, cut365); err != nil {
		return err
	}
	if err := s.compactUptime(tx, now); err != nil {
		return err
	}
	jobCut := now.AddDate(0, 0, -s.ret.ReportDays).UnixNano()
	if _, err := tx.Exec(`DELETE FROM job_chunks WHERE job_id IN (SELECT id FROM jobs WHERE created_ns < ?)`, jobCut); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM jobs WHERE created_ns < ?`, jobCut); err != nil {
		return err
	}
	type row struct {
		site  string
		at    int64
		level int
		disk  sql.NullInt64
	}
	var old []row
	rows, err := tx.Query(`SELECT site_id, at, level, disk FROM samples WHERE at < ? ORDER BY site_id, at`, cut30)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.site, &r.at, &r.level, &r.disk); err != nil {
			rows.Close()
			return err
		}
		old = append(old, r)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	type key struct {
		site string
		size int64
		blk  int64
	}
	groups := map[key][]row{}
	var order []key
	for _, r := range old {
		size := int64(86400)
		if r.at >= cut90 {
			size = 6 * 3600
		}
		k := key{r.site, size, r.at / size}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	for _, k := range order {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		last, level, disk := g[len(g)-1], 0, sql.NullInt64{}
		for _, r := range g {
			level = max(level, r.level)
			if r.disk.Valid && (!disk.Valid || r.disk.Int64 < disk.Int64) {
				disk = r.disk
			}
		}
		if _, err := tx.Exec(`UPDATE samples SET level=?, disk=? WHERE site_id=? AND at=?`, level, disk, last.site, last.at); err != nil {
			return err
		}
		for _, r := range g[:len(g)-1] {
			if _, err := tx.Exec(`DELETE FROM samples WHERE site_id=? AND at=?`, r.site, r.at); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM daily_reports WHERE day < ? AND EXISTS
		(SELECT 1 FROM daily_reports n WHERE n.site_id = daily_reports.site_id AND n.day > daily_reports.day)`,
		now.UTC().AddDate(0, 0, -s.ret.ReportDays).Format("2006-01-02")); err != nil {
		return err
	}
	return tx.Commit()
}

// ImportFiles übernimmt einmalig die Dateien des früheren FileStore (<id>.history.jsonl, <id>.latest.json) aus dir.
// Die Dateien bleiben unverändert liegen. level bewertet einen alten Report (status.Level).
func (s *SQLite) ImportFiles(dir string, level func(Entry) int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var done string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key='files_imported'`).Scan(&done); err == nil {
		return 0, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	n := 0
	for _, pattern := range []string{"*.history.jsonl", "*.latest.json"} {
		files, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return n, err
		}
		for _, name := range files {
			c, err := s.importFile(name, level)
			n += c
			if err != nil {
				return n, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	_, err := s.db.Exec(`INSERT INTO meta(key, value) VALUES('files_imported', ?)`, time.Now().UTC().Format(time.RFC3339))
	return n, err
}

func (s *SQLite) importFile(name string, level func(Entry) int) (int, error) {
	f, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Report.CollectedAt.IsZero() {
			continue // beschädigte Zeile überspringen, wie der alte FileStore
		}
		if err := s.save(e, level(e)); err != nil {
			continue // z. B. ungültige Site-ID
		}
		n++
	}
	return n, sc.Err()
}
