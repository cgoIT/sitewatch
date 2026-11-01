// Package agents verwaltet die Agenten (je Host einer) mit Token-Hash und der Konfiguration ihrer Sites.
// Ein Agent-Token darf für alle Sites melden, die in der Konfiguration des Agenten stehen.
package agents

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"sitewatch/internal/agentcfg"
	"sitewatch/internal/auth"
	"sitewatch/internal/report"
)

// Agent ist ein Absender von Reports mit eigenem Token. Ein Server-Agent (Type leer) holt seine Konfiguration von Sitewatch
// und kann mehrere Sites melden, ein Contao-Bundle genau eine. Das Token steht nie im Klartext hier, nur sein SHA-256-Hash.
type Agent struct {
	ID string `json:"id"`
	// Type: leer = Go-Agent auf einem Server; report.AgentContaoBundle = Contao-Bundle mit genau einer Site (Site-ID = Agent-ID), das ohne Abruf von Konfiguration meldet.
	Type      string          `json:"type,omitempty"`
	TokenHash string          `json:"token_hash"`
	Config    agentcfg.Remote `json:"config"`
	Updated   time.Time       `json:"updated"`
}

// Store hält die Agenten in der SQLite-Datenbank von Sitewatch (Tabelle agents).
// shortcut: jede Änderung schreibt die ganze Tabelle neu (in einer Transaktion); für wenige Agenten genügt das, bei vielen je Zeile ändern.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// Open legt die Tabelle bei Bedarf an. db kommt von store.SQLite.DB().
func Open(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY, type TEXT NOT NULL DEFAULT '', token_hash TEXT NOT NULL, config TEXT NOT NULL, updated TEXT NOT NULL)`)
	return &Store{db: db}, err
}

var ErrNotFound = errors.New("Agent nicht gefunden")

func (s *Store) load() ([]Agent, error) {
	rows, err := s.db.Query(`SELECT id, type, token_hash, config, updated FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var as []Agent
	for rows.Next() {
		var a Agent
		var cfg, updated string
		if err := rows.Scan(&a.ID, &a.Type, &a.TokenHash, &cfg, &updated); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cfg), &a.Config); err != nil {
			return nil, fmt.Errorf("Agent %q: %w", a.ID, err)
		}
		if a.Updated, err = time.Parse(time.RFC3339Nano, updated); err != nil {
			return nil, fmt.Errorf("Agent %q: %w", a.ID, err)
		}
		as = append(as, a)
	}
	return as, rows.Err()
}

func (s *Store) save(as []Agent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM agents`); err != nil {
		return err
	}
	for _, a := range as {
		cfg, err := json.Marshal(a.Config)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agents(id, type, token_hash, config, updated) VALUES(?, ?, ?, ?, ?)`,
			a.ID, a.Type, a.TokenHash, string(cfg), a.Updated.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ImportFile übernimmt einmalig die Agenten aus der Datei des früheren Speichers (agents.json). Die Datei bleibt
// unverändert liegen; bereits vorhandene IDs werden nicht überschrieben. Danach wird sie nie wieder gelesen.
func (s *Store) ImportFile(path string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var done string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key='agents_imported'`).Scan(&done); err == nil {
		return 0, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	n := 0
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist): // nichts zu importieren
	case err != nil:
		return 0, err
	default:
		var old []Agent
		if err := json.Unmarshal(b, &old); err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		as, err := s.load()
		if err != nil {
			return 0, err
		}
		have := map[string]bool{}
		for _, a := range as {
			have[a.ID] = true
		}
		for _, a := range old {
			if !have[a.ID] {
				as, n = append(as, a), n+1
			}
		}
		if err := s.save(as); err != nil {
			return 0, err
		}
	}
	_, err = s.db.Exec(`INSERT INTO meta(key, value) VALUES('agents_imported', ?)`, time.Now().UTC().Format(time.RFC3339))
	return n, err
}

// Import übernimmt Agenten aus einer Sicherung in eine noch leere Tabelle. Alle werden vorab geprüft wie beim Anlegen;
// bei einem Fehler wird nichts geschrieben.
func (s *Store) Import(in []Agent) error {
	seenSite := map[string]string{}
	seen := map[string]bool{}
	for _, a := range in {
		if !report.ValidID(a.ID) || seen[a.ID] {
			return fmt.Errorf("Agent %q: ungültige oder doppelte ID", a.ID)
		}
		seen[a.ID] = true
		if a.Updated.IsZero() {
			return fmt.Errorf("Agent %q: Änderungszeit fehlt", a.ID)
		}
		if b, err := hex.DecodeString(a.TokenHash); err != nil || len(b) != sha256.Size || a.TokenHash != hex.EncodeToString(b) { // genau auth.Hash: 64 Zeichen, klein
			return fmt.Errorf("Agent %q: ungültiger Token-Hash", a.ID)
		}
		switch {
		case a.Type == report.AgentContaoBundle:
			if len(a.Config.Sites) != 1 || a.Config.Sites[0].ID != a.ID {
				return fmt.Errorf("Agent %q: ein Contao-Bundle hat genau eine Site mit der ID des Agenten", a.ID)
			}
			if err := checkBundle(a.Config.Sites[0].Name, a.Config.Sites[0].URL); err != nil {
				return fmt.Errorf("Agent %q: %w", a.ID, err)
			}
		case a.Type == "":
			if err := a.Config.Validate(nil); err != nil {
				return fmt.Errorf("Agent %q: %w", a.ID, err)
			}
		default:
			return fmt.Errorf("Agent %q: unbekannter Typ %q", a.ID, a.Type)
		}
		for _, st := range a.Config.Sites {
			if o, dup := seenSite[st.ID]; dup {
				return fmt.Errorf("Site %q gehört zu den Agenten %q und %q", st.ID, o, a.ID)
			}
			seenSite[st.ID] = a.ID
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	have, err := s.load()
	if err != nil {
		return err
	}
	if len(have) > 0 {
		return errors.New("es gibt schon Agenten; eine Sicherung wird nur in eine leere Installation übernommen")
	}
	if err := s.save(in); err != nil {
		return err
	}
	// Eine alte agents.json soll danach nicht mehr eingemischt werden (siehe ImportFile).
	_, err = s.db.Exec(`INSERT OR REPLACE INTO meta(key, value) VALUES('agents_imported', ?)`, time.Now().UTC().Format(time.RFC3339))
	return err
}

// List liefert alle Agenten nach ID sortiert.
func (s *Store) List() ([]Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	as, err := s.load()
	sort.Slice(as, func(i, j int) bool { return as[i].ID < as[j].ID })
	return as, err
}

// Get liefert den Agenten mit der ID oder ErrNotFound.
func (s *Store) Get(id string) (Agent, error) {
	as, err := s.List()
	for _, a := range as {
		if a.ID == id {
			return a, nil
		}
	}
	if err == nil {
		err = ErrNotFound
	}
	return Agent{}, err
}

// Bundle meldet, ob der Agent ein Contao-Bundle ist.
func (a Agent) Bundle() bool { return a.Type == report.AgentContaoBundle }

// Create legt einen Agenten ohne Sites an und gibt das Token einmalig zurück.
func (s *Store) Create(id string, now time.Time) (string, error) {
	return s.create(id, "", agentcfg.Remote{}, now)
}

// CreateBundle legt ein Contao-Bundle an: ein Agent mit genau einer Site gleicher ID. Das Token wird einmalig zurückgegeben.
func (s *Store) CreateBundle(id, name, siteURL string, now time.Time) (string, error) {
	if err := checkBundle(name, siteURL); err != nil {
		return "", err
	}
	site := agentcfg.Site{ID: id, Name: name, Kind: "contao", URL: siteURL}
	return s.create(id, report.AgentContaoBundle, agentcfg.Remote{Sites: []agentcfg.Site{site}}, now)
}

// UpdateBundle ändert Anzeigename und URL eines Contao-Bundles.
func (s *Store) UpdateBundle(id, name, siteURL string, now time.Time) error {
	if err := checkBundle(name, siteURL); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	as, err := s.load()
	if err != nil {
		return err
	}
	for i := range as {
		if as[i].ID == id && as[i].Bundle() && len(as[i].Config.Sites) == 1 {
			as[i].Config.Sites[0].Name, as[i].Config.Sites[0].URL, as[i].Updated = name, siteURL, now.UTC()
			return s.save(as)
		}
	}
	return ErrNotFound
}

// checkBundle prüft, was in das YAML-Snippet des Bundles geschrieben wird.
func checkBundle(name, siteURL string) error {
	for _, v := range []string{name, siteURL} {
		if strings.ContainsFunc(v, unicode.IsControl) {
			return errors.New("Name und URL dürfen keine Steuerzeichen enthalten")
		}
	}
	if len(name) > 200 || len(siteURL) > 300 {
		return errors.New("Name oder URL zu lang")
	}
	if siteURL != "" {
		if u, err := url.Parse(siteURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("URL %q muss mit http:// oder https:// beginnen", siteURL)
		}
	}
	return nil
}

func (s *Store) create(id, typ string, cfg agentcfg.Remote, now time.Time) (string, error) {
	if !report.ValidID(id) {
		return "", errors.New("ungültige ID (erlaubt: a-z, 0-9, -)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	as, err := s.load()
	if err != nil {
		return "", err
	}
	for _, a := range as {
		if a.ID == id {
			return "", fmt.Errorf("Agent %q gibt es schon", id)
		}
		for _, o := range a.Config.Sites {
			for _, n := range cfg.Sites {
				if o.ID == n.ID {
					return "", fmt.Errorf("Site %q gehört schon zum Agenten %q", n.ID, a.ID)
				}
			}
		}
	}
	tok, hash, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	if err := s.save(append(as, Agent{ID: id, Type: typ, TokenHash: hash, Config: cfg, Updated: now.UTC()})); err != nil {
		return "", err
	}
	return tok, nil
}

// Save ersetzt die Konfiguration. Eine Site-ID darf nur zu einem Agenten gehören, sonst könnte ein Agent für fremde Sites melden.
func (s *Store) Save(id string, cfg agentcfg.Remote, now time.Time) error {
	if err := cfg.Validate(nil); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	as, err := s.load()
	if err != nil {
		return err
	}
	idx := -1
	for i, a := range as {
		if a.ID == id {
			idx = i
			continue
		}
		for _, o := range a.Config.Sites {
			for _, n := range cfg.Sites {
				if o.ID == n.ID {
					return fmt.Errorf("Site %q gehört schon zum Agenten %q", n.ID, a.ID)
				}
			}
		}
	}
	if idx < 0 {
		return ErrNotFound
	}
	if as[idx].Bundle() {
		return errors.New("ein Contao-Bundle hat keine Konfiguration von Sitewatch")
	}
	as[idx].Config, as[idx].Updated = cfg, now.UTC()
	return s.save(as)
}

// Rotate ersetzt das Token; das alte wird sofort ungültig.
func (s *Store) Rotate(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	as, err := s.load()
	if err != nil {
		return "", err
	}
	for i := range as {
		if as[i].ID == id {
			tok, hash, err := auth.NewToken()
			if err != nil {
				return "", err
			}
			as[i].TokenHash = hash
			return tok, s.save(as)
		}
	}
	return "", ErrNotFound
}

// Delete entfernt den Agenten samt Token; seine Reports bleiben erhalten. Gibt es ihn nicht, ist das ErrNotFound.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	as, err := s.load()
	if err != nil {
		return err
	}
	for i := range as {
		if as[i].ID == id {
			return s.save(append(as[:i], as[i+1:]...))
		}
	}
	return ErrNotFound
}

// ByToken sucht den Agenten zum Token. Es werden alle Hashes verglichen, damit die Dauer nicht verrät, ob es einen Treffer gab.
func (s *Store) ByToken(token string) (Agent, bool, error) {
	as, err := s.List()
	var found Agent
	ok := false
	for _, a := range as {
		if auth.Match(a.TokenHash, token) {
			found, ok = a, true
		}
	}
	return found, ok, err
}

// SiteIDs liefert die Sites aller Agenten.
func (s *Store) SiteIDs() ([]string, error) {
	as, err := s.List()
	var out []string
	for _, a := range as {
		for _, st := range a.Config.Sites {
			out = append(out, st.ID)
		}
	}
	return out, err
}
