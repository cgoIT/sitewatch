package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sitewatch/internal/report"
)

func TestParseOutdated(t *testing.T) {
	in := `{"installed":[
	 {"name":"vendor/b","version":"2.1.0","latest":"3.0.0","latest-status":"update-possible","abandoned":false},
	 {"name":"contao/core-bundle","version":"5.3.9","latest":"5.3.14","latest-status":"semver-safe-update","abandoned":"foo/bar"}]}`
	got, err := ParseOutdated(in)
	if err != nil || len(got) != 2 {
		t.Fatalf("err=%v got=%v", err, got)
	}
	if got[0].Name != "contao/core-bundle" || !got[0].Abandoned || got[1].Abandoned {
		t.Errorf("unerwartet: %+v", got)
	}
}

func TestParseAudit(t *testing.T) {
	for _, empty := range []string{`{"advisories":[]}`, `{"advisories":{}}`} {
		got, err := ParseAudit(empty)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: err=%v got=%v", empty, err, got)
		}
	}
	got, err := ParseAudit(`{"advisories":{"symfony/http-kernel":[{"title":"Beispiel","cve":"CVE-2026-0001","link":"https://example.org"}]}}`)
	if err != nil || len(got) != 1 || got[0].Package != "symfony/http-kernel" || got[0].CVE != "CVE-2026-0001" {
		t.Errorf("err=%v got=%v", err, got)
	}
}

func TestReadLogErrors(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 27, 19, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02T15:04:05.000000-07:00") }
	log := "[" + ts(time.Hour) + "] request.CRITICAL: Uncaught exception {\"exception\":\"x\"} []\n" +
		"[" + ts(2*time.Hour) + "] request.CRITICAL: Uncaught exception {\"exception\":\"y\"} []\n" +
		"[" + ts(3*time.Hour) + "] app.WARNING: nur eine Warnung [] []\n" +
		"[" + ts(48*time.Hour) + "] app.ERROR: zu alt [] []\n" +
		"keine Logzeile\n"
	if err := os.WriteFile(filepath.Join(dir, "prod-2026-10-27.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	// ModTime auf "jetzt" setzen, damit die Datei im Fenster liegt
	if err := os.Chtimes(filepath.Join(dir, "prod-2026-10-27.log"), now, now); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLogErrors(dir, now, 24*time.Hour, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Count != 2 || got[0].Message != "Uncaught exception" || got[0].Level != "CRITICAL" {
		t.Fatalf("unerwartet: %+v", got)
	}
}

func TestCollectHostKind(t *testing.T) {
	r, err := Collect(context.Background(), Config{SiteID: "host-a", Kind: "host", PHP: "/gibt/es/nicht", NoHostInfo: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Site.Kind != "host" || r.Site.PHP != "" {
		t.Errorf("Site: %+v", r.Site)
	}
	for _, p := range r.Site.Problems {
		if strings.Contains(p, "PHP") || strings.Contains(p, "composer") {
			t.Errorf("host-Eintrag meldet PHP/composer-Problem: %q", p)
		}
	}
	if r.Host.Name == "" {
		t.Error("Hostname fehlt")
	}
}

func TestRunEnvPassesEnvAndPWD(t *testing.T) {
	dir := t.TempDir()
	out, _, code, err := runEnv(context.Background(), []string{"SITE_DIR=/x"}, dir, "sh", "-c", `echo "$SITE_DIR|$PWD"`)
	want := "/x|" + dir
	if real, e := filepath.EvalSymlinks(dir); e == nil {
		want = "/x|" + real
	}
	if err != nil || code != 0 || (strings.TrimSpace(out) != "/x|"+dir && strings.TrimSpace(out) != want) {
		t.Errorf("out=%q code=%d err=%v", out, code, err)
	}
}

func TestMarkIgnored(t *testing.T) {
	pk := []report.Package{
		{Name: "contao/calendar-bundle", Latest: "6.0.4"},
		{Name: "contao/core-bundle", Latest: "v5.7.16"},
		{Name: "vendor/x", Latest: "2.0.0"},
		{Name: "other/y", Latest: "1.1.0"},
	}
	MarkIgnored(pk, []string{"contao/*:6.*", "vendor/x"})
	for i, want := range []bool{true, false, true, false} {
		if pk[i].Ignored != want {
			t.Errorf("%s: Ignored=%v, erwartet %v", pk[i].Name, pk[i].Ignored, want)
		}
	}
}

func TestHostViaConfiguredPrograms(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := Config{SiteID: "h", Kind: "host", Path: dir, NoSMART: true, NoHostInfo: true,
		Nginx:   script("ng", "echo 'nginx version: nginx/1.27.0' >&2"),
		MariaDB: script("db", "echo 'mariadb  Ver 15.1 Distrib 11.4.2-MariaDB, for debian-linux-gnu'")}
	r, err := Collect(context.Background(), cfg)
	if err != nil || r.Host.Nginx != "1.27.0" || r.Host.MariaDB != "11.4.2" || len(r.Site.Problems) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	cfg.Nginx = script("bad", "exit 1")
	if r, _ = Collect(context.Background(), cfg); r.Host.Nginx != "" || len(r.Site.Problems) != 1 {
		t.Errorf("fehlgeschlagenes Programm: %+v", r.Site.Problems)
	}
}

func TestWrappersWorkWithoutHostFlag(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ng")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho 'nginx version: nginx/1.27.0' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), Config{SiteID: "s", Kind: "php", Path: dir, PHP: "true", Nginx: p})
	if err != nil || r.Host.Nginx != "1.27.0" || r.Host.DiskFreePct != nil {
		t.Fatalf("%+v %v", r.Host, err)
	}
}

func TestMariaDBVersionFormats(t *testing.T) {
	for _, out := range []string{
		"mariadb  Ver 15.1 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64) using  EditLine wrapper",
		"mariadb from 11.4.2-MariaDB, client 15.2 for debian-linux-gnu (x86_64) using  EditLine wrapper",
	} {
		if m := mariadbRe.FindStringSubmatch(out); m == nil || m[1] == "" {
			t.Errorf("nicht erkannt: %s", out)
		}
	}
}

func TestNoNginxNoMariaDB(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), Config{SiteID: "s", Kind: "php", Path: dir, PHP: "true",
		Nginx: bad, MariaDB: bad, NoNginx: true, NoMariaDB: true})
	if err != nil || len(r.Site.Problems) != 0 || r.Host.Nginx != "" || r.Host.MariaDB != "" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestParseSMART(t *testing.T) {
	d, ok := ParseSMART(`{"model_name":"X","smart_status":{"passed":false},"temperature":{"current":41},
	 "ata_smart_attributes":{"table":[{"id":5,"raw":{"value":8}},{"id":197,"raw":{"value":2}},{"id":9,"raw":{"value":100}}]}}`)
	if !ok || d.Passed == nil || *d.Passed || d.BadSectors == nil || *d.BadSectors != 10 || *d.TempC != 41 {
		t.Errorf("ATA: ok=%v %+v", ok, d)
	}
	d, ok = ParseSMART(`{"smart_status":{"passed":true},"nvme_smart_health_information_log":{"media_errors":0}}`)
	if !ok || !*d.Passed || *d.BadSectors != 0 {
		t.Errorf("NVMe: ok=%v %+v", ok, d)
	}
	if _, ok = ParseSMART(`{"smartctl":{"messages":[{"string":"Permission denied"}]}}`); ok {
		t.Error("ohne Urteil darf ok nicht gelten")
	}
}

func TestParseMdstat(t *testing.T) {
	in := `Personalities : [raid1] [raid6]
md0 : active raid1 sdb1[1] sda1[0]
      976630336 blocks super 1.2 [2/2] [UU]
      bitmap: 0/8 pages [0KB], 65536KB chunk

md1 : active (auto-read-only) raid1 sdb2[1] sda2[0](F)
      976630336 blocks super 1.2 [2/1] [_U]
      [>....................]  recovery =  3.2% (31232/976630336) finish=80.5min

md2 : inactive sdc1[0](S)
      1000 blocks super 1.2

unused devices: <none>
`
	got := ParseMdstat(in)
	if len(got) != 3 {
		t.Fatalf("%d Verbünde: %+v", len(got), got)
	}
	if a := got[0]; a.Name != "md0" || a.Level != "raid1" || a.Total != 2 || a.Active != 2 || a.Missing() != 0 || a.Syncing {
		t.Errorf("md0: %+v", a)
	}
	if a := got[1]; a.Level != "raid1" || a.Active != 1 || a.Failed != 1 || a.Missing() != 1 || !a.Syncing {
		t.Errorf("md1: %+v", a)
	}
	if a := got[2]; !a.Inactive || a.Missing() != 1 {
		t.Errorf("md2: %+v", a)
	}
	if len(ParseMdstat("Personalities :\nunused devices: <none>\n")) != 0 {
		t.Error("ohne Verbund muss die Liste leer sein")
	}
}

func TestCollectSMARTViaProgram(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "smartctl")
	body := "#!/bin/sh\ncase \"$2\" in\n--scan) echo '{\"devices\":[{\"name\":\"/dev/sda\",\"type\":\"sat\"},{\"name\":\"/dev/sdb\",\"type\":\"sat\"}]}';;\n*) case \"$*\" in *sda) echo '{\"smart_status\":{\"passed\":false}}';; *) echo '{}';; esac;;\nesac\nexit 4\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), Config{SiteID: "h", Kind: "host", Path: dir, Smartctl: p, NoHostInfo: true, Nginx: "/bin/false", MariaDB: "/bin/false", NoNginx: true, NoMariaDB: true})
	if err != nil || len(r.Host.Disks) != 1 || r.Host.Disks[0].Device != "/dev/sda" || !r.Host.Disks[0].Failed() {
		t.Fatalf("Platten: %+v %v", r.Host.Disks, err)
	}
	if len(r.Site.Problems) != 1 || !strings.Contains(r.Site.Problems[0], "/dev/sdb") {
		t.Errorf("sdb ohne Urteil muss ein Problem sein: %v", r.Site.Problems)
	}
}

func TestSMARTProblems(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "smartctl")
	scan := `echo '{"devices":[{"name":"/dev/a","type":"sat"},{"name":"/dev/b","type":"sat"},{"name":"/dev/c","type":"sat"},{"name":"/dev/d","type":"sat"}]}'`
	os.WriteFile(p, []byte("#!/bin/sh\ncase \"$2\" in --scan) "+scan+";; *) echo '{}';; esac\n"), 0o755)
	cfg := Config{SiteID: "h", Kind: "host", Path: dir, Smartctl: p, NoHostInfo: true, NoNginx: true, NoMariaDB: true}
	r, _ := Collect(context.Background(), cfg)
	if len(r.Site.Problems) != 1 || !strings.Contains(r.Site.Problems[0], "4 Platten") {
		t.Errorf("Sammelzeile erwartet: %v", r.Site.Problems)
	}
	os.WriteFile(p, []byte("#!/bin/sh\necho kaputt\n"), 0o755)
	r, _ = Collect(context.Background(), cfg)
	if len(r.Site.Problems) != 1 || !strings.Contains(r.Site.Problems[0], "kein gültiges JSON") {
		t.Errorf("ungültiges JSON muss ein Problem sein: %v", r.Site.Problems)
	}
}

func TestParseSMARTTemperature(t *testing.T) {
	for name, tc := range map[string]struct {
		temp string
		want int
	}{"normal": {`"temperature":{"current":36}`, 36}, "null": {`"temperature":{"current":0}`, 0}, "ohne Wert": {`"temperature":{}`, 0}, "fehlt": {`"x":1`, 0}} {
		d, ok := ParseSMART(`{"smart_status":{"passed":true},` + tc.temp + `}`)
		if !ok || d.Temp() != tc.want || (tc.want == 0 && d.TempC != nil) {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

func TestSmartArgs(t *testing.T) {
	for typ, want := range map[string]string{
		"scsi": "-j -H -A /dev/sdb", "sat": "-j -H -A -d sat /dev/sdb", "": "-j -H -A /dev/sdb", "nvme": "-j -H -A -d nvme /dev/sdb", "megaraid,3": "-j -H -A -d megaraid,3 /dev/sdb",
	} {
		if got := strings.Join(smartArgs(typ, "/dev/sdb"), " "); got != want {
			t.Errorf("Typ %q: %q, erwartet %q", typ, got, want)
		}
	}
}

func TestParseSMARTSerial(t *testing.T) {
	d, ok := ParseSMART(`{"serial_number":" 14100C06C859 ","smart_status":{"passed":true}}`)
	if !ok || d.Serial != "14100C06C859" || d.Key() != "sn:14100C06C859" {
		t.Errorf("%+v", d)
	}
	if d, _ := ParseSMART(`{"smart_status":{"passed":true}}`); d.Serial != "" {
		t.Errorf("ohne Seriennummer: %+v", d)
	}
}

func TestParseSMARTNVMeWear(t *testing.T) {
	d, ok := ParseSMART(`{"smart_status":{"passed":true},"nvme_smart_health_information_log":{"media_errors":0,"percentage_used":247,"available_spare":100,"data_units_written":1000}}`)
	if !ok || d.WearPct == nil || *d.WearPct != 247 || *d.SpareLeftPct != 100 || d.WrittenBytes == nil || *d.WrittenBytes != 512000000 {
		t.Errorf("NVMe: ok=%v %+v", ok, d)
	}
	d, _ = ParseSMART(`{"smart_status":{"passed":true},"nvme_smart_health_information_log":{"media_errors":0}}`)
	if d.WearPct != nil || d.SpareLeftPct != nil || d.WrittenBytes != nil {
		t.Errorf("fehlende Felder müssen nil bleiben: %+v", d)
	}
	d, _ = ParseSMART(`{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":0}}]}}`)
	if d.WearPct != nil || d.SpareLeftPct != nil || d.WrittenBytes != nil {
		t.Errorf("ATA: %+v", d)
	}
}
