package store

import "database/sql"

func migrateDiskHealth(tx *sql.Tx) error {
	for _, col := range []string{"bad_sectors", "raid_missing"} { // idempotent, wie die übrigen Migrationen
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('samples') WHERE name=?`, col).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.Exec(`ALTER TABLE samples ADD COLUMN ` + col + ` INTEGER`); err != nil {
				return err
			}
		}
	}
	return nil
}

// maxNull liefert das größere der beiden Werte; NULL (unbekannt) weicht jedem Wert.
func maxNull(a, b sql.NullInt64) sql.NullInt64 {
	if !a.Valid || (b.Valid && b.Int64 > a.Int64) {
		return b
	}
	return a
}
