package store

import (
	"path/filepath"
	"testing"
)

func TestPushSubs(t *testing.T) {
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "s.db"), DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := PushSub{"https://fcm.googleapis.com/a", "k1", "a1"}
	for _, p := range []PushSub{a, {a.Endpoint, "k2", "a2"}, {"https://fcm.googleapis.com/b", "k", "a"}} { // gleicher Endpoint ersetzt
		if err := st.AddPushSub(p); err != nil {
			t.Fatal(err)
		}
	}
	if subs, _ := st.PushSubs(); len(subs) != 2 {
		t.Fatalf("%d Anmeldungen", len(subs))
	}
	if err := st.DeletePushSub(a.Endpoint); err != nil {
		t.Fatal(err)
	}
	if subs, _ := st.PushSubs(); len(subs) != 1 || subs[0].P256dh != "k" {
		t.Errorf("nach Löschen: %+v", subs)
	}
}
