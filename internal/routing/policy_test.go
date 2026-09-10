package routing

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func TestCanonicalNamesAndPrefixes(t *testing.T) {
	for _, s := range []string{"*.example.com", "https://example.com", "example.com:443", "a..com", "a\x00.com", "example.com ", "-a.example", "127.0.0.1", "пример.рф"} {
		if _, e := CanonicalDomain(s); e == nil {
			t.Errorf("accepted invalid domain %q", s)
		}
	}
	if got, e := CanonicalDomain(
		"XN--E1AFMKFD.XN--P1AI.",
	); e != nil ||
		got != "xn--e1afmkfd.xn--p1ai" {
		t.Fatal(got, e)
	}
	for _, s := range []string{"10.0.0.0/8", "128.0.0.0/1", "1.2.3.4/24", "::ffff:8.8.8.8/128", "2000::/3", "0.0.0.0/0"} {
		if _, e := CanonicalPrefix(s); e == nil {
			t.Errorf("accepted unsafe prefix %q", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "93.184.216.0/24", "2606:4700::/32"} {
		if _, e := CanonicalPrefix(s); e != nil {
			t.Errorf("rejected public prefix %q: %v", s, e)
		}
	}
}

func TestClassifierKeepsSharedCDNDirectAndEnforcesPrecedence(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("93.184.216.34")
	c, e := NewClassifier(
		[]model.RoutingRule{
			{Action: "bypass", Domain: "example.net", IncludeSubdomains: true},
			{Action: "direct", Domain: "allowed.example.net"},
			{Action: "direct", Domain: "blocked.example"},
		},
		Snapshot{
			Domains: []string{"blocked.example", "listed.example"},
			CIDRs:   []string{"8.8.8.0/24"},
		},
		map[string]time.Time{
			"learned.example": now.Add(time.Minute),
			"expired.example": now.Add(-time.Second),
		},
	)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ domain, address, action, reason string }{
		{"listed.example", ip.String(), "bypass", "Antifilter registry"},
		{"unlisted.example", ip.String(), "direct", "Default direct"},
		{"blocked.example", ip.String(), "direct", "Manual exception"},
		{"allowed.example.net", ip.String(), "direct", "Manual exception"},
		{"x.example.net", ip.String(), "bypass", "Manual exception"},
		{"notexample.net", ip.String(), "direct", "Default direct"},
		{"x.listed.example", ip.String(), "direct", "Default direct"},
		{"learned.example", ip.String(), "bypass", "Detected restriction"},
		{"expired.example", ip.String(), "direct", "Default direct"},
		{"listed.example", "192.168.1.1", "direct", "Local destination"},
		{"printer.lan", ip.String(), "direct", "Local destination"},
		{"unlisted.example", "8.8.8.8", "bypass", "Antifilter registry"},
	} {
		got := c.Decide(tc.domain, netip.MustParseAddr(tc.address), now)
		if got.Action != tc.action || got.Reason != tc.reason {
			t.Errorf("%s %s: %+v", tc.domain, tc.address, got)
		}
	}
}

func FuzzCanonicalDomain(f *testing.F) {
	for _, s := range []string{"example.com", "*.example.com", "localhost", "abc\x00.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, e := CanonicalDomain(s)
		if e == nil {
			again, e := CanonicalDomain(d)
			if e != nil || again != d {
				t.Fatal("not idempotent")
			}
		}
	})
}
