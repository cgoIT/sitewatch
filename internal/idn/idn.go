// Package idn wandelt internationalisierte Domainnamen (götzinger.eu) in ihre ASCII-Form (xn--gtzinger-65a.eu).
// net/http macht das selbst, ein direkter TLS-Verbindungsaufbau (Zertifikatsprüfung) nicht.
package idn

import (
	"strings"
	"unicode/utf8"
)

// ASCIIHost liefert den Hostnamen in ASCII-Form (Punycode je Label, kleingeschrieben). Reine ASCII-Namen bleiben unverändert.
// shortcut: keine Unicode-Normalisierung (UTS 46, z. B. ß oder Kompatibilitätszeichen); die Eingabe sollte in NFC vorliegen.
func ASCIIHost(host string) string {
	if !utf8.ValidString(host) {
		return host
	}
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if isASCII(l) {
			continue
		}
		if e, ok := encode(strings.ToLower(l)); ok {
			labels[i] = "xn--" + e
		}
	}
	return strings.Join(labels, ".")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// encode ist Punycode nach RFC 3492.
func encode(s string) (string, bool) {
	const base, tmin, tmax, skew, damp = 36, 1, 26, 38, 700
	runes := []rune(s)
	var out []byte
	for _, r := range runes {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := 128, 0, 72
	digit := func(d int) byte {
		if d < 26 {
			return byte('a' + d)
		}
		return byte('0' + d - 26)
	}
	for h < len(runes) {
		m := rune(0x7fffffff)
		for _, r := range runes {
			if int(r) >= n && r < m {
				m = r
			}
		}
		delta += (int(m) - n) * (h + 1)
		if delta < 0 {
			return "", false
		}
		n = int(m)
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) != n {
				continue
			}
			q := delta
			for k := base; ; k += base {
				t := min(max(k-bias, tmin), tmax)
				if q < t {
					break
				}
				out = append(out, digit(t+(q-t)%(base-t)))
				q = (q - t) / (base - t)
			}
			out = append(out, digit(q))
			// Bias anpassen
			d := delta
			if h == b {
				d /= damp
			} else {
				d /= 2
			}
			d += d / (h + 1)
			k := 0
			for d > ((base-tmin)*tmax)/2 {
				d /= base - tmin
				k += base
			}
			bias = k + (base-tmin+1)*d/(d+skew)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return string(out), true
}
