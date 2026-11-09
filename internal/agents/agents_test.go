package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sitewatch/internal/agentcfg"
	"sitewatch/internal/store"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "sitewatch.db"), store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s, err := Open(st.DB())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func site(id string) agentcfg.Site { return agentcfg.Site{ID: id, Kind: "php", Path: "/var/www/" + id} }

func TestLifecycle(t *testing.T) {
	s := open(t)
	now := time.Now()
	tok, err := s.Create("server1", now)
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	if _, err := s.Create("server1", now); err == nil {
		t.Error("doppelte ID")
	}
	if _, err := s.Create("../x", now); err == nil {
		t.Error("ungültige ID")
	}
	if a, ok, _ := s.ByToken(tok); !ok || a.ID != "server1" {
		t.Fatal("Token muss passen")
	}
	if a, _ := s.Get("server1"); a.TokenHash == tok || a.TokenHash == "" {
		t.Error("nur der Hash wird gespeichert")
	}
	if err := s.Save("server1", agentcfg.Remote{Sites: []agentcfg.Site{site("a"), site("b")}}, now); err != nil {
		t.Fatal(err)
	}
	other, _ := s.Create("anderer", now)
	if err := s.Save("anderer", agentcfg.Remote{Sites: []agentcfg.Site{site("b")}}, now); err == nil {
		t.Error("Site b gehört schon zu server1")
	}
	if err := s.Save("anderer", agentcfg.Remote{Sites: []agentcfg.Site{{ID: "x", Kind: "php"}}}, now); err == nil {
		t.Error("ungültige Konfiguration (path fehlt)")
	}
	if err := s.Save("gibtsnicht", agentcfg.Remote{}, now); err != ErrNotFound {
		t.Errorf("unbekannter Agent: %v", err)
	}
	if ids, _ := s.SiteIDs(); len(ids) != 2 {
		t.Errorf("SiteIDs = %v", ids)
	}
	nt, err := s.Rotate("server1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ByToken(tok); ok {
		t.Error("altes Token muss ungültig sein")
	}
	if a, ok, _ := s.ByToken(nt); !ok || a.ID != "server1" {
		t.Error("neues Token")
	}
	if a, ok, _ := s.ByToken(other); !ok || a.ID != "anderer" {
		t.Error("anderes Token bleibt gültig")
	}
	if _, ok, _ := s.ByToken(""); ok {
		t.Error("leeres Token")
	}
	if err := s.Delete("server1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("server1"); err != ErrNotFound {
		t.Errorf("gelöscht: %v", err)
	}
}

func TestBundle(t *testing.T) {
	s := open(t)
	now := time.Now()
	tok, err := s.CreateBundle("kunde-x", "Kunde X", "https://x.example", now)
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	a, ok, err := s.ByToken(tok)
	if err != nil || !ok || !a.Bundle() || len(a.Config.Sites) != 1 || a.Config.Sites[0].ID != "kunde-x" || a.Config.Sites[0].Kind != "contao" {
		t.Fatalf("Bundle: %+v %v %v", a, ok, err)
	}
	if _, err := s.CreateBundle("kunde-x", "", "", now); err == nil {
		t.Error("doppelte ID")
	}
	if _, err := s.CreateBundle("a", "zwei\nZeilen", "", now); err == nil {
		t.Error("Steuerzeichen im Namen")
	}
	if _, err := s.CreateBundle("b", "", "ftp://x", now); err == nil {
		t.Error("ungültige URL")
	}
	// Eine Site gehört nur zu einem Agenten, auch nicht zu einem Bundle und einem Server-Agenten.
	if _, err := s.Create("server1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("server1", agentcfg.Remote{Sites: []agentcfg.Site{site("kunde-x")}}, now); err == nil {
		t.Error("Site des Bundles dem Server-Agenten zugewiesen")
	}
	if err := s.Save("kunde-x", agentcfg.Remote{}, now); err == nil {
		t.Error("Konfiguration eines Bundles überschrieben")
	}
	if err := s.UpdateBundle("kunde-x", "Neu", "", now); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.Get("kunde-x"); a.Config.Sites[0].Name != "Neu" || a.Config.Sites[0].URL != "" {
		t.Errorf("nicht geändert: %+v", a.Config.Sites[0])
	}
	if err := s.UpdateBundle("server1", "x", "", now); err == nil {
		t.Error("Server-Agent als Bundle geändert")
	}
}

// Der Import aus agents.json passiert genau einmal; die Datei bleibt unverändert, ein später gelöschter Agent kommt nicht zurück.
func TestImportFile(t *testing.T) {
	s := open(t)
	path := filepath.Join(t.TempDir(), "agents.json")
	old := `[{"id":"server1","token_hash":"` + strings.Repeat("a", 64) + `","config":{"interval":"10m","sites":[{"id":"kunde","kind":"contao","path":"/var/www/kunde"}]},"updated":"2026-10-01T10:00:00Z"}]`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ImportFile(path); err != nil || n != 1 {
		t.Fatalf("Import: %d %v", n, err)
	}
	a, err := s.Get("server1")
	if err != nil || a.Config.Interval != "10m" || len(a.Config.Sites) != 1 || a.Config.Sites[0].Path != "/var/www/kunde" || a.TokenHash == "" {
		t.Fatalf("importiert: %+v %v", a, err)
	}
	if b, _ := os.ReadFile(path); string(b) != old {
		t.Error("Datei wurde verändert")
	}
	if err := s.Delete("server1"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ImportFile(path); err != nil || n != 0 {
		t.Errorf("zweiter Import: %d %v", n, err)
	}
	if _, err := s.Get("server1"); err == nil {
		t.Error("gelöschter Agent kam zurück")
	}
}

func TestImportMissingFileIsNoError(t *testing.T) {
	if n, err := open(t).ImportFile(filepath.Join(t.TempDir(), "gibt-es-nicht.json")); err != nil || n != 0 {
		t.Errorf("%d %v", n, err)
	}
}

func TestRename(t *testing.T) {
	s := open(t)
	now := time.Now()
	tok, _ := s.Create("alt", now)
	if _, err := s.Create("andere", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateBundle("bundle", "B", "https://b.example", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("alt", "andere", now); err == nil {
		t.Error("vorhandene ID muss abgelehnt werden")
	}
	if err := s.Rename("alt", "../x", now); err == nil {
		t.Error("ungültige ID muss abgelehnt werden")
	}
	if err := s.Rename("bundle", "neu", now); err == nil {
		t.Error("Bundle darf nicht umbenannt werden")
	}
	if err := s.Rename("gibtsnicht", "neu", now); err != ErrNotFound {
		t.Errorf("unbekannt: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO jobs(id, agent, site, action, status, approved_by, created_ns, expires_ns, envelope) VALUES('j1','alt','s','a','queued','x',1,2,'{}')`); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("alt", "neu", now); err == nil {
		t.Error("mit wartendem Auftrag darf nicht umbenannt werden")
	}
	if _, err := s.db.Exec(`UPDATE jobs SET status='done'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("alt", "neu", now); err != nil {
		t.Fatal(err)
	}
	a, ok, _ := s.ByToken(tok)
	if !ok || a.ID != "neu" {
		t.Errorf("Token muss weiter gelten, jetzt für %q", a.ID)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE agent='neu'`).Scan(&n)
	if n != 1 {
		t.Errorf("Auftrag zog nicht um: %d", n)
	}
}
