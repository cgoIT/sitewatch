package collect

import (
	"fmt"
	"testing"
	"time"
)

// cspLine baut eine Monolog-Zeile, wie Contao (CspReportListener) sie schreibt. Beispieldaten.
func cspLine(ts time.Time, directive, ua string) string {
	return fmt.Sprintf(`[%s] app.ERROR: Content-Security-Policy violation reported for "%s" on line 1 {"contao":{"Contao\\CoreBundle\\Monolog\\ContaoContext":"{\"func\":\"x\",\"action\":\"ERROR\",\"username\":\"N\\/A\",\"browser\":\"%s\",\"uri\":\"https:\\/\\/example.org\\/iPhone-Android-Chrome-Windows\",\"pageId\":null}"}} []`,
		ts.Format(time.RFC3339), directive, ua)
}

// User-Agents (Beispieldaten), "/" wie in der Log-Zeile doppelt maskiert.
const (
	uaIPhoneSafari  = `Mozilla\\/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit\\/605.1.15 (KHTML, like Gecko) Version\\/27.2 Mobile\\/15E148 Safari\\/604.1`
	uaInstagram     = `Mozilla\\/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit\\/605.1.15 (KHTML, like Gecko) Mobile\\/22H20 Instagram 400.0.0`
	uaIPhoneCriOS   = `Mozilla\\/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit\\/605.1.15 (KHTML, like Gecko) CriOS\\/151.0.0.0 Mobile\\/15E148 Safari\\/604.1`
	uaAndroidChrome = `Mozilla\\/5.0 (Linux; Android 10; K) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/151.0.0.0 Mobile Safari\\/537.36`
	uaWinChrome     = `Mozilla\\/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/151.0.0.0 Safari\\/537.36`
	uaWinEdge       = uaWinChrome + ` Edg\\/151.0.0.0`
	uaWinFirefox    = `Mozilla\\/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko\\/20100101 Firefox\\/150.0`
	uaMacSafari     = `Mozilla\\/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit\\/605.1.15 (KHTML, like Gecko) Version\\/27.2 Safari\\/605.1.15`
)

func TestKnownCSP(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		directive, ua string
		known         bool
	}{
		{"style-src-attr", uaIPhoneSafari, true},
		{"style-src-attr", uaInstagram, true},
		{"style-src-elem", uaAndroidChrome, true},
		{"connect-src", uaWinChrome, true},
		{"connect-src", uaWinEdge, true},
		{"script-src", uaWinChrome, false},
		{"script-src-elem", uaWinFirefox, false},
		{"frame-src", uaWinChrome, false},
		{"img-src", uaIPhoneCriOS, false},
		{"style-src-attr", uaWinFirefox, false},
		{"style-src-elem", uaWinChrome, false},
		{"style-src-attr", uaMacSafari, false},
		{"connect-src", uaMacSafari, false},
		{"connect-src", uaAndroidChrome, false},
		{"connect-src", uaIPhoneSafari, false},
		{"style-src-attr", "", false}, // ohne User-Agent nie ausblenden, auch wenn die URI passende Wörter enthält
	} {
		_, _, msg, ok := parseMonolog(cspLine(now, c.directive, c.ua))
		if !ok {
			t.Fatalf("Zeile nicht erkannt: %s", c.directive)
		}
		if got := knownCSP(msg); got != c.known {
			t.Errorf("%s / %s: known = %v, erwartet %v", c.directive, c.ua, got, c.known)
		}
	}
	if knownCSP(`Uncaught PHP Exception RuntimeException: "Boom" at Foo.php line 3 {"exception":"[object]"} []`) {
		t.Error("PHP-Exception darf nie ausgeblendet werden")
	}
}

// Ausgeblendete Meldungen werden gezählt und stehen nicht in der Liste.
func TestErrorSetCountsKnownCSP(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	s := newErrorSet(now, 24*time.Hour)
	for _, l := range []string{
		cspLine(now, "style-src-attr", uaIPhoneSafari),
		cspLine(now, "connect-src", uaWinEdge),
		cspLine(now, "script-src", uaWinChrome),
		cspLine(now.Add(-48*time.Hour), "style-src-attr", uaIPhoneSafari), // außerhalb des Zeitfensters
	} {
		s.addLine(parseMonolog, l)
	}
	list := s.list(10)
	if s.known != 2 || len(list) != 1 || list[0].Message != `Content-Security-Policy violation reported for "script-src" on line 1` {
		t.Fatalf("known = %d, Liste = %+v", s.known, list)
	}
}
