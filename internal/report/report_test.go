package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func valid(now time.Time) Report {
	return Report{Schema: 1, Site: Site{ID: "kunde-c", Kind: "contao"}, CollectedAt: now}
}

func TestValidate(t *testing.T) {
	now := time.Date(2026, 10, 27, 19, 0, 0, 0, time.UTC)
	r := valid(now)
	if err := r.Validate(now); err != nil {
		t.Fatalf("gültiger Report abgelehnt: %v", err)
	}
	r.Site.Kind = "host"
	if err := r.Validate(now); err != nil {
		t.Fatalf("kind host abgelehnt: %v", err)
	}
	cases := map[string]func(*Report){
		"schema":         func(r *Report) { r.Schema = 2 },
		"id":             func(r *Report) { r.Site.ID = "../etc" },
		"kind":           func(r *Report) { r.Site.Kind = "wordpress" },
		"zukunft":        func(r *Report) { r.CollectedAt = now.Add(time.Hour) },
		"zu alt":         func(r *Report) { r.CollectedAt = now.Add(-8 * 24 * time.Hour) },
		"backup negativ": func(r *Report) { n := -1; r.Site.BackupCount = &n },
		"backup zukunft": func(r *Report) { t := now.Add(time.Hour); r.Site.LastBackup = &t },
		"zeit leer":      func(r *Report) { r.CollectedAt = time.Time{} },
	}
	for name, mutate := range cases {
		r := valid(now)
		mutate(&r)
		if err := r.Validate(now); err == nil {
			t.Errorf("%s: Fehler erwartet", name)
		}
	}
}

// Beispiel-Report des Contao-Bundles (cgoit/contao-sitewatch-bundle, Beispieldaten): fängt Schema-Abweichungen zwischen Bundle und Sitewatch ab.
func TestContaoBundleReportMatchesSchema(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contao-bundle-report.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(r.CollectedAt); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDisksRaids(t *testing.T) {
	now := time.Date(2026, 10, 27, 19, 0, 0, 0, time.UTC)
	neg := -1
	for name, h := range map[string]Host{
		"negative Sektoren": {Disks: []Disk{{Device: "/dev/sda", BadSectors: &neg}}},
		"langer Name":       {Raids: []Raid{{Name: strings.Repeat("x", 129)}}},
		"negative Anzahl":   {Raids: []Raid{{Name: "md0", Total: -2}}},
		"zu viele Platten":  {Disks: make([]Disk, 65)},
	} {
		r := Report{Schema: SchemaVersion, Site: Site{ID: "a", Kind: "host"}, CollectedAt: now, Host: h}
		if r.Validate(now) == nil {
			t.Errorf("%s: erwartet Fehler", name)
		}
	}
	r := Report{Schema: SchemaVersion, Site: Site{ID: "a", Kind: "host"}, CollectedAt: now,
		Host: Host{Disks: []Disk{{Device: "/dev/sda"}}, Raids: []Raid{{Name: "md0", Total: 2, Active: 2}}}}
	if err := r.Validate(now); err != nil {
		t.Errorf("gültig: %v", err)
	}
}
