package store

import (
	"database/sql"
	"time"
)

// DiskAcks speichert, bei welchem Stand defekter Sektoren eine Platte „zur Kenntnis genommen“ wurde.
// Bis zu diesem Wert bleibt der Host OK; steigt er, warnt Sitewatch erneut.
type DiskAcks interface {
	SetDiskAck(siteID, disk string, badSectors int, now time.Time) error
	DeleteDiskAck(siteID, disk string) error
	// DiskAck liefert den bestätigten Wert und den Zeitpunkt; ok=false: nicht bestätigt (oder Fehler beim Lesen).
	DiskAck(siteID, disk string) (badSectors int, at time.Time, ok bool)
}

func migrateDiskAcks(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS disk_acks(site_id TEXT NOT NULL, disk TEXT NOT NULL, bad_sectors INTEGER NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(site_id, disk))`)
	return err
}

func (s *SQLite) SetDiskAck(siteID, disk string, bad int, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR REPLACE INTO disk_acks(site_id, disk, bad_sectors, at) VALUES(?,?,?,?)`, siteID, disk, bad, now.Unix())
	return err
}

func (s *SQLite) DeleteDiskAck(siteID, disk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM disk_acks WHERE site_id=? AND disk=?`, siteID, disk)
	return err
}

func (s *SQLite) DiskAck(siteID, disk string) (int, time.Time, bool) {
	var bad int
	var at int64
	if err := s.db.QueryRow(`SELECT bad_sectors, at FROM disk_acks WHERE site_id=? AND disk=?`, siteID, disk).Scan(&bad, &at); err != nil {
		return 0, time.Time{}, false
	}
	return bad, time.Unix(at, 0).UTC(), true
}
