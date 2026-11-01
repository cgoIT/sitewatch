// Package backup sichert und überträgt die Konfiguration von Sitewatch (Agenten samt Token-Hash und Schwellwerte) als JSON-Datei.
// Reports, Historie, EOL-Zwischenspeicher und der Signierschlüssel (signing.key) gehören nicht dazu.
package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/status"
)

// Version ist die Version des Dateiformats.
const Version = 1

// File ist der Inhalt der Datei. Sie enthält Token-Hashes und ist so schützenswert wie die Datenbank.
type File struct {
	Version    int            `json:"version"`
	ExportedAt time.Time      `json:"exported_at"`
	Agents     []agents.Agent `json:"agents"`
	Thresholds map[string]int `json:"thresholds"` // nur die vom Standard abweichenden Werte
}

// Export liest die aktuelle Konfiguration. as darf nil sein (Fernkonfiguration aus).
func Export(as *agents.Store, cfg status.Config, now time.Time) (File, error) {
	f := File{Version: Version, ExportedAt: now.UTC(), Agents: []agents.Agent{}, Thresholds: cfg.Diff()}
	if as != nil {
		list, err := as.List()
		if err != nil {
			return f, err
		}
		f.Agents = append(f.Agents, list...)
	}
	return f, nil
}

// Settings schreibt die Schwellwerte; ein leeres vals bedeutet Standardwerte.
type Settings interface {
	SetSetting(key, value string) error
}

// ThresholdsKey ist der Schlüssel der Schwellwerte in den Einstellungen.
const ThresholdsKey = "thresholds"

// Import liest data und übernimmt es in eine noch leere Installation. Alles wird vorab geprüft; bei einem Fehler
// ändert sich nichts. Eine Installation mit Agenten wird nicht überschrieben.
func Import(data []byte, as *agents.Store, set Settings) error {
	var f File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("keine gültige Sicherung: %w", err)
	}
	if f.Version != Version {
		return fmt.Errorf("Version %d der Sicherung wird nicht unterstützt (erwartet: %d)", f.Version, Version)
	}
	if _, err := status.DefaultConfig().With(f.Thresholds); err != nil {
		return fmt.Errorf("Schwellwerte: %w", err)
	}
	if as == nil {
		return errors.New("Agenten sind nicht eingeschaltet")
	}
	if err := as.Import(f.Agents); err != nil { // prüft und schreibt in einer Transaktion
		return err
	}
	if len(f.Thresholds) == 0 {
		return nil
	}
	b, _ := json.Marshal(f.Thresholds) // map[string]int kann nicht scheitern
	return set.SetSetting(ThresholdsKey, string(b))
}
