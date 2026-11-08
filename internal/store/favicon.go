package store

import (
	"database/sql"
	"time"
)

// Favicon ist das gespeicherte Symbol einer Site (nur Bilder, die Sitewatch selbst am Inhalt erkannt hat).
type Favicon struct {
	Data    []byte // bei FaviconMeta leer
	Type    string // image/png, image/x-icon, image/gif oder image/jpeg
	URL     string // Adresse der Site, für die das Symbol geholt wurde; ändert sie sich, gilt es nicht mehr
	Fetched time.Time
}

// Favicons ist der Speicher der Symbole (SQLite).
type Favicons interface {
	SetFavicon(siteID string, f Favicon) error
	GetFavicon(siteID string) (Favicon, bool, error)
	FaviconMeta() (map[string]Favicon, error) // ohne Daten
	DeleteFavicon(siteID string) error
}

func migrateFavicon(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS favicons(site_id TEXT PRIMARY KEY, data BLOB NOT NULL, type TEXT NOT NULL, url TEXT NOT NULL, fetched INTEGER NOT NULL)`)
	return err
}

func (s *SQLite) SetFavicon(siteID string, f Favicon) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR REPLACE INTO favicons(site_id, data, type, url, fetched) VALUES(?,?,?,?,?)`, siteID, f.Data, f.Type, f.URL, f.Fetched.Unix())
	return err
}

func (s *SQLite) GetFavicon(siteID string) (Favicon, bool, error) {
	var f Favicon
	var at int64
	err := s.db.QueryRow(`SELECT data, type, url, fetched FROM favicons WHERE site_id=?`, siteID).Scan(&f.Data, &f.Type, &f.URL, &at)
	if err == sql.ErrNoRows {
		return Favicon{}, false, nil
	}
	f.Fetched = time.Unix(at, 0).UTC()
	return f, err == nil, err
}

func (s *SQLite) FaviconMeta() (map[string]Favicon, error) {
	rows, err := s.db.Query(`SELECT site_id, type, url, fetched FROM favicons`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Favicon{}
	for rows.Next() {
		var id string
		var f Favicon
		var at int64
		if err := rows.Scan(&id, &f.Type, &f.URL, &at); err != nil {
			return nil, err
		}
		f.Fetched = time.Unix(at, 0).UTC()
		out[id] = f
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteFavicon(siteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM favicons WHERE site_id=?`, siteID)
	return err
}
