package probe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/report"
	"sitewatch/internal/status"
	"sitewatch/internal/store"
)

// setup legt ein Bundle mit der Adresse des Testservers an (httptest, daher AllowInternal).
func setup(t *testing.T, handler http.Handler) (*Prober, *store.SQLite, *httptest.Server, time.Time) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "sitewatch.db"), store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	as, err := agents.Open(st.DB())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if _, err := as.CreateBundle("kunde-b", "B", srv.URL, now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	p := &Prober{Agents: as, Store: st, Settings: status.NewSettings(status.DefaultConfig()), Now: func() time.Time { return now }, AllowInternal: true, tlsConfig: &tls.Config{InsecureSkipVerify: true}}
	return p, st, srv, now
}

func TestCertExpiryAndOverlay(t *testing.T) {
	p, _, srv, _ := setup(t, http.NotFoundHandler())
	want := srv.Certificate().NotAfter
	got, err := p.CertExpiry(context.Background(), srv.URL)
	if err != nil || !got.Equal(want) {
		t.Fatalf("%v %v (erwartet %v)", got, err, want)
	}
	if _, err := p.CertExpiry(context.Background(), "http://example.org"); err == nil {
		t.Error("http-Adresse ohne Fehler")
	}
	r := &report.Report{Site: report.Site{ID: "kunde-b"}}
	p.Once(context.Background()) // ermittelt das Zertifikat
	if p.Overlay(r); r.Site.TLSExpires == nil || !r.Site.TLSExpires.Equal(want) {
		t.Errorf("Overlay: %v", r.Site.TLSExpires)
	}
	own := time.Now()
	r.Site.TLSExpires = &own
	if p.Overlay(r); *r.Site.TLSExpires != own {
		t.Error("Overlay überschreibt den Wert des Reports")
	}
}

// Ohne Report seit dem Anlegen des Agenten wird geweckt, aber nicht häufiger als alle 15 Minuten; Weiterleitungen werden nicht verfolgt.
func TestWakeWhenOverdue(t *testing.T) {
	var hits atomic.Int32
	p, st, _, now := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://intern.invalid/", http.StatusFound)
	}))
	ctx := context.Background()
	p.Once(ctx)
	if hits.Load() != 1 {
		t.Fatalf("erster Durchlauf: %d Aufrufe", hits.Load())
	}
	p.Once(ctx)
	if hits.Load() != 1 {
		t.Errorf("zweiter Durchlauf sofort danach: %d Aufrufe", hits.Load())
	}
	// Frischer Report: kein Weckruf, auch nach Ablauf der Sperrzeit.
	if err := st.Save(store.Entry{Report: report.Report{Schema: 1, Site: report.Site{ID: "kunde-b"}, CollectedAt: now}, ReceivedAt: now.Add(-10 * time.Minute)}, 0); err != nil {
		t.Fatal(err)
	}
	p.Now = func() time.Time { return now.Add(time.Hour) } // Report ist 70 Minuten alt (< 90)
	p.Once(ctx)
	if hits.Load() != 1 {
		t.Errorf("trotz frischem Report geweckt: %d", hits.Load())
	}
	p.Now = func() time.Time { return now.Add(2 * time.Hour) } // 130 Minuten alt
	p.Once(ctx)
	if hits.Load() != 2 {
		t.Errorf("überfällig, aber nicht geweckt: %d", hits.Load())
	}
}

func TestRefusesInternalTargets(t *testing.T) {
	p, _, srv, _ := setup(t, http.NotFoundHandler())
	p.AllowInternal = false
	if _, err := p.Ping(context.Background(), srv.URL); err == nil {
		t.Error("Weckruf an Loopback ohne Fehler")
	}
	if _, err := p.CertExpiry(context.Background(), srv.URL); err == nil {
		t.Error("Zertifikatsprüfung an Loopback ohne Fehler")
	}
}

func TestRefuseInternalTable(t *testing.T) {
	for addr, wantErr := range map[string]bool{
		"127.0.0.1:443": true, "[::1]:443": true, "10.0.0.1:443": true, "169.254.169.254:80": true, "100.64.0.1:443": true,
		"[fd00::1]:443": true, "[::ffff:127.0.0.1]:443": true, "[::ffff:10.0.0.1]:443": true, "0.1.2.3:443": true,
		"[64:ff9b::a00:1]:443": true, "198.18.0.1:443": true,
		"8.8.8.8:443": false, "[2001:4860::1]:443": false,
	} {
		if err := refuseInternal("tcp", addr, nil); (err != nil) != wantErr {
			t.Errorf("%s: Fehler=%v, erwartet %v", addr, err, wantErr)
		}
	}
}

func TestTarget(t *testing.T) {
	for raw, ok := range map[string]bool{"https://a.example": true, "https://a.example:8443/x": true, "http://a.example": false, "https://": false, "::": false} {
		if _, _, err := target(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

// Schlägt die Prüfung später fehl oder ändert sich die Adresse, darf kein altes Ablaufdatum übrig bleiben.
func TestStaleExpiryDropped(t *testing.T) {
	p, _, srv, now := setup(t, http.NotFoundHandler())
	r := &report.Report{Site: report.Site{ID: "kunde-b"}}
	p.Once(context.Background())
	if p.Overlay(r); r.Site.TLSExpires == nil {
		t.Fatal("kein Ablaufdatum ermittelt")
	}
	srv.Close() // nächste Prüfung scheitert
	p.Now = func() time.Time { return now.Add(7 * time.Hour) }
	p.Once(context.Background())
	r = &report.Report{Site: report.Site{ID: "kunde-b"}}
	if p.Overlay(r); r.Site.TLSExpires != nil {
		t.Error("veraltetes Ablaufdatum bleibt stehen")
	}
}

// Info hält Erfolg und Fehler fest; Fehlertexte nennen keine Adressen, und gelöschte Sites verschwinden.
func TestInfoRecorded(t *testing.T) {
	p, _, srv, now := setup(t, http.NotFoundHandler())
	ctx := context.Background()
	if _, ok := p.Info("kunde-b"); ok {
		t.Fatal("Info vor dem ersten Durchlauf")
	}
	p.Once(ctx)
	i, ok := p.Info("kunde-b")
	if !ok || i.PingCode != http.StatusNotFound || i.PingErr != "" || i.CertErr != "" || !i.CertExpires.Equal(srv.Certificate().NotAfter) {
		t.Fatalf("nach Erfolg: %+v %v", i, ok)
	}
	srv.Close()
	p.Now = func() time.Time { return now.Add(7 * time.Hour) }
	p.Once(ctx)
	i, _ = p.Info("kunde-b")
	if i.PingErr == "" || i.CertErr == "" || !i.CertExpires.IsZero() {
		t.Fatalf("nach Fehler: %+v", i)
	}
	for _, m := range []string{i.PingErr, i.CertErr} {
		if strings.Contains(m, "127.0.0.1") || strings.Contains(m, ":") {
			t.Errorf("Fehlertext verrät Einzelheiten: %q", m)
		}
	}
	if err := p.Agents.Delete("kunde-b"); err != nil {
		t.Fatal(err)
	}
	p.Once(ctx)
	if _, ok := p.Info("kunde-b"); ok {
		t.Error("Info einer gelöschten Site bleibt")
	}
}

func TestShortErr(t *testing.T) {
	p, _, srv, _ := setup(t, http.NotFoundHandler())
	p.AllowInternal = false
	_, err := p.Ping(context.Background(), srv.URL)
	if got := shortErr(err); got != "Ziel ist keine öffentliche Adresse" {
		t.Errorf("interne Adresse: %q (%v)", got, err)
	}
}
