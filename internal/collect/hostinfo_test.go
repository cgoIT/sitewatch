package collect

import (
	"reflect"
	"testing"
)

func TestParseAptUpgradable(t *testing.T) {
	in := "Listing...\n" +
		"curl/stable-security 7.88.1-10+deb12u5 amd64 [upgradable from: 7.88.1-10+deb12u4]\n" +
		"vim/stable 2:9.0.1378-2 amd64 [upgradable from: 2:9.0.1378-1]\n" +
		"WARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n"
	u := ParseAptUpgradable(in, nil)
	if u.Total != 2 || u.Security != 1 || len(u.Packages) != 2 {
		t.Fatalf("Zahlen: %+v", u)
	}
	if p := u.Packages[0]; p.Name != "curl" || !p.Security || p.New != "7.88.1-10+deb12u5" || p.Installed != "7.88.1-10+deb12u4" {
		t.Errorf("curl: %+v", p)
	}
	// Ausgabe von "apt-get -s upgrade" (Beispieldaten): zurückgestellte Pakete zählen nicht.
	sim := "Reading package lists...\nCalculating upgrade...\nThe following upgrades have been deferred due to phasing:\n" +
		"  distro-info python3-distro-info\n  vim\n0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n"
	if d := ParseAptDeferred(sim); len(d) != 3 || !d["vim"] || !d["python3-distro-info"] {
		t.Errorf("zurückgestellt: %v", d)
	}
	if u := ParseAptUpgradable(in, ParseAptDeferred(sim)); u.Total != 1 || u.Packages[0].Name != "curl" {
		t.Errorf("mit Phasing: %+v", u)
	}
	if d := ParseAptDeferred("Reading package lists...\n0 upgraded, 0 newly installed.\n"); len(d) != 0 {
		t.Errorf("ohne Phasing: %v", d)
	}
	if e := ParseAptUpgradable("Listing...\n", nil); e.Total != 0 || e.Manager != "apt" {
		t.Errorf("leer: %+v", e)
	}
}

func TestParseFailedUnits(t *testing.T) {
	got := ParseFailedUnits("● foo.service loaded failed failed Foo\n  bar.mount loaded failed failed Bar\n")
	if want := []string{"foo.service", "bar.mount"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if got := ParseFailedUnits(""); got == nil || len(got) != 0 {
		t.Errorf("leer muss eine leere, nicht nil-Liste sein: %v", got)
	}
}

func TestParseNetworkFiles(t *testing.T) {
	route := "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0100A8C0\t0003\neth0\t0000A8C0\t00000000\t0001\n"
	if g := ParseDefaultGateway(route); g != "192.168.0.1" {
		t.Errorf("Gateway %q", g)
	}
	if g := ParseDefaultGateway("Iface\tDestination\tGateway\n"); g != "" {
		t.Errorf("ohne Route: %q", g)
	}
	if d := ParseResolv("# x\nnameserver 1.1.1.1\nsearch lan\nnameserver 9.9.9.9\n"); !reflect.DeepEqual(d, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Errorf("DNS %v", d)
	}
}

func TestParseMeminfoOSUptime(t *testing.T) {
	mem, swap := ParseMeminfo("MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")
	if mem == nil || *mem != 25 || swap == nil || *swap != 25 {
		t.Errorf("mem %v swap %v", mem, swap)
	}
	if _, s := ParseMeminfo("MemTotal: 1000 kB\nSwapTotal: 0 kB\n"); s != nil {
		t.Errorf("ohne Swap muss nil sein")
	}
	if n := ParseOSRelease("NAME=\"Debian\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"); n != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("os-release %q", n)
	}
	if u := ParseUptime("350735.47 234388.90\n"); u == nil || *u != 350735 {
		t.Errorf("uptime %v", u)
	}
	if ParseUptime("x") != nil {
		t.Errorf("ungültige Uptime muss nil sein")
	}
}
