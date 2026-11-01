package probe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
