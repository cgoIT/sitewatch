package store

import "database/sql"

// PushSub ist die Web-Push-Anmeldung eines Geräts (Endpoint beim Push-Dienst des Browsers samt Schlüsseln).
type PushSub struct{ Endpoint, P256dh, Auth string }

func migratePush(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS push_subs(endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL)`)
	return err
}

func (s *SQLite) PushSubs() ([]PushSub, error) {
	rows, err := s.db.Query(`SELECT endpoint, p256dh, auth FROM push_subs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSub
	for rows.Next() {
		var p PushSub
		if err := rows.Scan(&p.Endpoint, &p.P256dh, &p.Auth); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AddPushSub legt die Anmeldung an oder ersetzt die zum selben Endpoint.
func (s *SQLite) AddPushSub(p PushSub) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR REPLACE INTO push_subs(endpoint, p256dh, auth) VALUES(?,?,?)`, p.Endpoint, p.P256dh, p.Auth)
	return err
}

func (s *SQLite) DeletePushSub(endpoint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM push_subs WHERE endpoint=?`, endpoint)
	return err
}
