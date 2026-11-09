package idn

import "testing"

func TestASCIIHost(t *testing.T) {
	for in, want := range map[string]string{
		"götzinger.eu":  "xn--gtzinger-n4a.eu",
		"Götzinger.EU":  "xn--gtzinger-n4a.EU",
		"www.bücher.de": "www.xn--bcher-kva.de",
		"münchen.de":    "xn--mnchen-3ya.de",
		"example.com":   "example.com",
		"Example.COM":   "Example.COM",
		"2a01::1":       "2a01::1",
		"bad\xffhost":   "bad\xffhost",
		"日本語.jp":        "xn--wgv71a119e.jp",
		"ドメイン名例.jp":     "xn--eckwd4c7cu47r2wf.jp",
		"점심.한국":         "xn--cw4b17g.xn--3e0b707e",
	} {
		if got := ASCIIHost(in); got != want {
			t.Errorf("ASCIIHost(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

func TestASCIIHostEdgeCases(t *testing.T) {
	for in, want := range map[string]string{
		"a..b":       "a..b",
		".bücher.de": ".xn--bcher-kva.de",
		"bücher.de.": "xn--bcher-kva.de.",
		"BÜcher.de":  "xn--bcher-kva.de",
		"":           "",
	} {
		if got := ASCIIHost(in); got != want {
			t.Errorf("ASCIIHost(%q) = %q, erwartet %q", in, got, want)
		}
	}
}
