package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDiskAcks(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "a.db"), DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	if _, _, ok := s.DiskAck("a", "sn:1"); ok {
		t.Fatal("nichts bestätigt")
	}
	if err := s.SetDiskAck("a", "sn:1", 16, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDiskAck("a", "sn:1", 20, now); err != nil { // überschreibt
		t.Fatal(err)
	}
	if bad, at, ok := s.DiskAck("a", "sn:1"); !ok || bad != 20 || at.Unix() != now.Unix() {
		t.Errorf("bad=%d at=%v ok=%v", bad, at, ok)
	}
	if err := s.SetDiskAck("b", "sn:1", 1, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSite("a"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.DiskAck("a", "sn:1"); ok {
		t.Error("DeleteSite muss die Kenntnisnahme entfernen")
	}
	if _, _, ok := s.DiskAck("b", "sn:1"); !ok {
		t.Error("andere Sites bleiben unberührt")
	}
	if err := s.DeleteDiskAck("b", "sn:1"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.DiskAck("b", "sn:1"); ok {
		t.Error("gelöscht")
	}
}
