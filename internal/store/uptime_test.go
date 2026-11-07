package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestUptimeStatsAndCompaction(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "u.db"), DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	add := func(ago time.Duration, st string, ms int) {
		if err := s.AddCheck("a", Check{At: now.Add(-ago), State: st, LatencyMS: ms, Code: 200}); err != nil {
			t.Fatal(err)
		}
	}
	// Vor 10 Tagen: 2 Prüfungen, davon 1 Ausfall und 1 Wartung. Heute: up, down, down, up.
	add(10*24*time.Hour, CheckUp, 100)
	add(10*24*time.Hour-time.Minute, CheckDown, 0)
	add(10*24*time.Hour-2*time.Minute, CheckMaint, 0)
	add(30*time.Minute, CheckUp, 100)
	add(20*time.Minute, CheckDown, 0)
	add(10*time.Minute, CheckDown, 0)
	add(time.Minute, CheckUp, 300)

	if err := s.Maintain(now); err != nil {
		t.Fatal(err)
	}
	var raw int
	s.db.QueryRow(`SELECT COUNT(*) FROM uptime_raw WHERE at < ?`, now.AddDate(0, 0, -rawDays).UnixNano()).Scan(&raw)
	if raw != 0 {
		t.Errorf("alte Rohwerte nicht verdichtet: %d", raw)
	}
	days, err := s.UptimeDays(now.AddDate(0, 0, -30))
	if err != nil {
		t.Fatal(err)
	}
	var checks, ups, maint int
	for _, d := range days["a"] {
		checks, ups, maint = checks+d.Checks, ups+d.Ups, maint+d.Maint
	}
	if checks != 7 || ups != 3 || maint != 1 {
		t.Errorf("Tageswerte: checks=%d ups=%d maint=%d", checks, ups, maint)
	}
	if r, ok := days["a"][0].Ratio(); !ok || r != 0.5 { // 1 up von 2 (Wartung zählt nicht)
		t.Errorf("Ratio des ältesten Tages: %v %v", r, ok)
	}
	if m, _ := s.MedianLatency(now.Add(-time.Hour)); m["a"] != 300 {
		t.Errorf("Median: %v", m)
	}
	out, _ := s.Outages("a", now.Add(-time.Hour))
	if len(out) != 1 || out[0].Checks != 2 {
		t.Errorf("Ausfälle: %+v", out)
	}
	if err := s.SetUptimeSetting("a", UptimeSetting{Enabled: false, IntervalS: 60}); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.UptimeSettings(); st["a"].Enabled {
		t.Errorf("Einstellung nicht gespeichert")
	}
	if err := s.SetUptimeSetting("a", DefaultUptime()); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.UptimeSettings(); len(st) != 0 {
		t.Errorf("Standard sollte keine Zeile sein: %v", st)
	}
	if err := s.DeleteSite("a"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.RecentChecks("a", 5); len(c) != 0 {
		t.Errorf("DeleteSite lässt Messwerte zurück")
	}
}
