package routing

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// registryDomain accepts the provider's Unicode letter/number labels and turns
// them into explicit DNS A-labels. It does not guess URL repairs, strip junk,
// expand wildcards, or apply compatibility mappings. Combining/control/joiner
// characters requiring an IDNA context policy are conservatively rejected.
func registryDomain(raw string) (string, error) {
	if !utf8.ValidString(raw) || len(raw) > 1024 {
		return "", errors.New("invalid registry name")
	}
	// Simple Unicode lowercase is not the complete IDNA mapping policy. Reject
	// non-roundtripping folds instead of matching a distinct ASCII destination.
	for _, c := range raw {
		lower := unicode.ToLower(c)
		if c > 127 && lower != c && unicode.ToUpper(lower) != c {
			return "", errors.New("unsupported registry Unicode case fold")
		}
	}
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(raw, ".")), ".")
	for i, label := range labels {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid registry label boundary")
		}
		ascii := true
		for _, c := range label {
			if c > 127 {
				ascii = false
				if !unicode.IsLetter(c) && !unicode.IsNumber(c) {
					return "", errors.New("unsupported registry Unicode label")
				}
			}
		}
		if !ascii {
			encoded, e := punycodeLabel(label)
			if e != nil {
				return "", e
			}
			labels[i] = "xn--" + encoded
		}
	}
	return CanonicalDomain(strings.Join(labels, "."))
}

// RFC 3492 Bootstring with Punycode parameters. Input is bounded to a DNS label;
// all arithmetic increments are checked against uint32 overflow.
func punycodeLabel(label string) (string, error) {
	input := []rune(label)
	if len(input) == 0 || len(input) > 63 {
		return "", errors.New("invalid IDN label length")
	}
	out := []byte{}
	for _, c := range input {
		if c < 128 {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return "", errors.New("invalid IDN basic character")
			}
			out = append(out, byte(c))
		}
	}
	basic := len(out)
	handled := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := uint64(128), uint64(0), uint64(72)
	adapt := func(value, points uint64, first bool) uint64 {
		if first {
			value /= 700
		} else {
			value /= 2
		}
		value += value / points
		k := uint64(0)
		for value > 455 {
			value /= 35
			k += 36
		}
		return k + 36*value/(value+38)
	}
	digit := func(d uint64) byte {
		if d < 26 {
			return byte('a' + d)
		}
		return byte('0' + d - 26)
	}
	for handled < len(input) {
		m := uint64(0x110000)
		for _, c := range input {
			if uint64(c) >= n && uint64(c) < m {
				m = uint64(c)
			}
		}
		increase := (m - n) * uint64(handled+1)
		if increase > 0xffffffff-delta {
			return "", errors.New("IDN overflow")
		}
		delta += increase
		n = m
		for _, c := range input {
			v := uint64(c)
			if v < n {
				delta++
				if delta > 0xffffffff {
					return "", errors.New("IDN overflow")
				}
			}
			if v != n {
				continue
			}
			q := delta
			for k := uint64(36); ; k += 36 {
				threshold := uint64(1)
				if k > bias {
					threshold = k - bias
				}
				if threshold > 26 {
					threshold = 26
				}
				if q < threshold {
					break
				}
				out = append(out, digit(threshold+(q-threshold)%(36-threshold)))
				q = (q - threshold) / (36 - threshold)
			}
			out = append(out, digit(q))
			bias = adapt(delta, uint64(handled+1), handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
		if len(out) > 59 {
			return "", errors.New("IDN DNS label too long")
		}
	}
	return string(out), nil
}
