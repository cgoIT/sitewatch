package collect

import (
	"slices"
	"strings"
)

// cspRule blendet CSP-Meldungen von Besuchergeräten aus: Direktive aus directives und ein User-Agent,
// der alle Teile einer Gruppe aus ua enthält und keinen aus notUA.
type cspRule struct {
	directives []string
	ua         [][]string
	notUA      []string
}

// cspNoise ist die einzige Stelle für die Ausnahmeregeln: bekanntes Rauschen aus Besucher-Browsern
// (In-App-Browser, Erweiterungen), kein Fehler der Seite. Alles andere bleibt sichtbar, auch neue Direktiven.
var cspNoise = []cspRule{
	// mobiles WebKit (Safari, In-App-Browser, Chrome auf iOS) und Chrome auf Android
	{directives: []string{"style-src-attr", "style-src-elem"}, ua: [][]string{{"iPhone"}, {"iPad"}, {"Android", "Chrome"}}},
	// Desktop-Chrome und -Edge (Erweiterungen)
	{directives: []string{"connect-src"}, ua: [][]string{{"Windows", "Chrome"}, {"Windows", "Edg/"}, {"Macintosh", "Chrome"}, {"Macintosh", "Edg/"}}, notUA: []string{"Mobile", "Android"}},
}

// knownCSP meldet, ob msg (Monolog-Meldung samt Kontext) eine CSP-Meldung von Contao ist, die unter cspNoise fällt.
// Der User-Agent steht im Kontext (ContaoContext, als JSON in JSON); fehlt er, bleibt die Meldung sichtbar.
func knownCSP(msg string) bool {
	rest, ok := strings.CutPrefix(msg, `Content-Security-Policy violation reported for "`)
	if !ok {
		return false
	}
	directive, rest, _ := strings.Cut(rest, `"`)
	_, ua, _ := strings.Cut(rest, `\"browser\":\"`)
	ua, _, _ = strings.Cut(ua, `\",\"uri\":`)
	ua = strings.ReplaceAll(ua, `\\/`, "/")
	contains := func(part string) bool { return strings.Contains(ua, part) }
	for _, r := range cspNoise {
		if !slices.Contains(r.directives, directive) || slices.ContainsFunc(r.notUA, contains) {
			continue
		}
		for _, all := range r.ua {
			if !slices.ContainsFunc(all, func(p string) bool { return !contains(p) }) {
				return true
			}
		}
	}
	return false
}
