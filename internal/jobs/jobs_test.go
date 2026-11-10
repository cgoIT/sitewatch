package jobs

import "testing"

func TestActionsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Actions {
		switch {
		case a.Name == "" || a.Label == "" || seen[a.Name]:
			t.Errorf("Name/Label fehlt oder doppelt: %+v", a)
		case btoi(len(a.Site) > 0)+btoi(len(a.Console) > 0)+btoi(len(a.Host) > 0) != 1:
			t.Errorf("%s: genau eines von Site, Console und Host", a.Name)
		case len(a.Host) > 0 && !(len(a.Kinds) == 1 && a.Kinds[0] == "host"):
			t.Errorf("%s: Host-Aktionen nur für Sites der Art host", a.Name)
		case a.Arg != "" && (a.Arg != ArgUnit || a.Level != Direct || len(a.Host) == 0):
			t.Errorf("%s: Arg nur als Unit, lesend und bei Host-Aktionen", a.Name)
		case len(a.Kinds) == 0:
			t.Errorf("%s: ohne Site-Arten", a.Name)
		case a.Limit() > MaxTimeout:
			t.Errorf("%s: Zeitlimit über MaxTimeout", a.Name)
		}
		seen[a.Name] = true
	}
	if a, ok := Find("maintenance-on"); !ok || !a.NeedsID() || !a.AllowsKind("contao") || a.AllowsKind("php") {
		t.Errorf("maintenance-on: %+v", a)
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestValidUnit(t *testing.T) {
	for s, want := range map[string]bool{"logrotate.service": true, "user@1000.service": true, "apt-daily.timer": true,
		"": false, "-n.service": false, "--file=/etc/shadow": false, "a b.service": false, "x.service;id": false, "../x.service": false, "logrotate": false} {
		if ValidUnit(s) != want {
			t.Errorf("ValidUnit(%q) = %v", s, !want)
		}
	}
}
