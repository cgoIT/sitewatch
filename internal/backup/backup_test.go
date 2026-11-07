package backup

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/status"
	"sitewatch/internal/store"
)

// fresh öffnet eine leere Installation (Datenbank im temporären Verzeichnis).
func fresh(t *testing.T) (*agents.Store, *store.SQLite) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "sitewatch.db"), store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	as, err := agents.Open(st.DB())
	if err != nil {
		t.Fatal(err)
	}
	return as, st
}

func TestExportImportRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	src, srcSt := fresh(t)
	if err := srcSt.SetUptimeSetting("kunde-b", store.UptimeSetting{Enabled: false, IntervalS: 900}); err != nil {
		t.Fatal(err)
	}
	tokB, err := src.CreateBundle("kunde-b", "Kunde B", "https://b.example", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Create("server1", now); err != nil {
		t.Fatal(err)
	}
	cfg, _ := status.DefaultConfig().With(map[string]int{"tls_warn_days": 30})
	f, err := Export(src, srcSt, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f)

	dst, dstSt := fresh(t)
	if err := Import(data, dst, dstSt, dstSt); err != nil {
		t.Fatal(err)
	}
	if a, ok, err := dst.ByToken(tokB); err != nil || !ok || a.ID != "kunde-b" {
		t.Errorf("Token nach dem Import ungültig: %+v %v %v", a, ok, err)
	}
	if raw, ok, _ := dstSt.Setting(ThresholdsKey); !ok || raw != `{"tls_warn_days":30}` {
		t.Errorf("Schwellwerte: %q %v", raw, ok)
	}
	if u, _ := dstSt.UptimeSettings(); u["kunde-b"].Enabled || u["kunde-b"].IntervalS != 900 {
		t.Errorf("Einstellung der Erreichbarkeitsprüfung: %+v", u)
	}
	if err := Import(data, dst, dstSt, dstSt); err == nil {
		t.Error("zweiter Import in eine nicht leere Installation ohne Fehler")
	}
}

func TestImportRejects(t *testing.T) {
	good := `{"version":1,"agents":[{"id":"kunde-b","type":"contao-bundle","token_hash":"` + strings.Repeat("a", 64) +
		`","config":{"sites":[{"id":"kunde-b","name":"B"}]},"updated":"2026-11-01T12:00:00Z"}],"thresholds":{}}`
	as, st := fresh(t)
	for name, bad := range map[string]string{
		"kein json":          `{`,
		"unbekanntes Feld":   strings.Replace(good, `"thresholds"`, `"extra":1,"thresholds"`, 1),
		"Version":            strings.Replace(good, `"version":1`, `"version":2`, 1),
		"Schwellwert":        strings.Replace(good, `"thresholds":{}`, `"thresholds":{"disk_crit_pct":30}`, 1),
		"Token-Hash":         strings.Replace(good, strings.Repeat("a", 64), "abc", 1),
		"Bundle fremde Site": strings.Replace(good, `"sites":[{"id":"kunde-b"`, `"sites":[{"id":"andere"`, 1),
		"Typ":                strings.Replace(good, `"contao-bundle"`, `"xyz"`, 1),
	} {
		if err := Import([]byte(bad), as, st, st); err == nil {
			t.Errorf("%s: kein Fehler", name)
		}
	}
	if l, _ := as.List(); len(l) != 0 {
		t.Errorf("fehlerhafte Importe haben %d Agenten hinterlassen", len(l))
	}
	if err := Import([]byte(good), as, st, st); err != nil {
		t.Errorf("gültige Datei: %v", err)
	}
}

func TestImportWithoutSettingsStore(t *testing.T) {
	as, _ := fresh(t)
	data := `{"version":1,"agents":[],"thresholds":{"tls_warn_days":30}}`
	if err := Import([]byte(data), as, nil, nil); err == nil {
		t.Error("ohne Speicher für Schwellwerte kein Fehler")
	}
}
