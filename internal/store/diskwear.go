package store

import (
	"database/sql"
	"sort"
	"time"
)

// DiskWears liefert den Verlauf von Verschleiß und Schreibvolumen je Platte (NVMe).
type DiskWears interface {
	// DiskWear liefert die Reihen einer Site, je Platte aufsteigend nach Zeit; sortiert nach Plattenschlüssel.
	DiskWear(siteID string) ([]DiskSeries, error)
}

// DiskSeries ist der Verlauf einer Platte (Schlüssel wie report.Disk.Key). Nil-Werte waren unbekannt.
type DiskSeries struct {
	Key, Device string
	Points      []DiskPoint
}

// DiskPoint ist ein Messpunkt; bei verdichteten Punkten gilt das Maximum im Block.
type DiskPoint struct {
	At           time.Time
	WearPct      *int
	WrittenBytes *int64
}

// migrateDiskWear legt den Verlauf je Platte an (eigene Tabelle, weil samples nur einen Wert je Site hält).
func migrateDiskWear(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS disk_wear(site_id TEXT NOT NULL, disk TEXT NOT NULL, at INTEGER NOT NULL, device TEXT NOT NULL,
		wear_pct INTEGER, written_bytes INTEGER, PRIMARY KEY(site_id, disk, at))`)
	return err
}

func (s *SQLite) DiskWear(siteID string) ([]DiskSeries, error) {
	rows, err := s.db.Query(`SELECT disk, device, at, wear_pct, written_bytes FROM disk_wear WHERE site_id=? ORDER BY disk, at`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DiskSeries
	for rows.Next() {
		var key, dev string
		var at int64
		var w, b sql.NullInt64
		if err := rows.Scan(&key, &dev, &at, &w, &b); err != nil {
			return nil, err
		}
		if n := len(out); n == 0 || out[n-1].Key != key {
			out = append(out, DiskSeries{Key: key})
		}
		sr := &out[len(out)-1]
		sr.Device = dev // der jüngste Name gilt
		p := DiskPoint{At: time.Unix(at, 0).UTC(), WearPct: ptr(w)}
		if b.Valid {
			p.WrittenBytes = &b.Int64
		}
		sr.Points = append(sr.Points, p)
	}
	return out, rows.Err()
}

// compactDiskWear verdichtet wie samples: älter als cut30 ein Punkt je 6-Stunden-Block, älter als cut90 je Tag, jeweils das Maximum.
func compactDiskWear(tx *sql.Tx, cut30, cut90 int64) error {
	type row struct {
		site, disk string
		at         int64
		w, b       sql.NullInt64
	}
	rows, err := tx.Query(`SELECT site_id, disk, at, wear_pct, written_bytes FROM disk_wear WHERE at < ? ORDER BY site_id, disk, at`, cut30)
	if err != nil {
		return err
	}
	type key struct {
		site, disk string
		size, blk  int64
	}
	groups := map[key][]row{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.site, &r.disk, &r.at, &r.w, &r.b); err != nil {
			rows.Close()
			return err
		}
		size := int64(86400)
		if r.at >= cut90 {
			size = 6 * 3600
		}
		k := key{r.site, r.disk, size, r.at / size}
		groups[k] = append(groups[k], r)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].blk < keys[j].blk }) // Reihenfolge egal, nur reproduzierbar
	for _, k := range keys {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		last, w, b := g[len(g)-1], sql.NullInt64{}, sql.NullInt64{}
		for _, r := range g {
			w, b = maxNull(w, r.w), maxNull(b, r.b)
		}
		if _, err := tx.Exec(`UPDATE disk_wear SET wear_pct=?, written_bytes=? WHERE site_id=? AND disk=? AND at=?`, w, b, last.site, last.disk, last.at); err != nil {
			return err
		}
		for _, r := range g[:len(g)-1] {
			if _, err := tx.Exec(`DELETE FROM disk_wear WHERE site_id=? AND disk=? AND at=?`, r.site, r.disk, r.at); err != nil {
				return err
			}
		}
	}
	return nil
}
