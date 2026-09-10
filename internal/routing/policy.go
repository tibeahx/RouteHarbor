// Package routing classifies destinations without retaining DNS request history.
package routing

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

// CanonicalDomain accepts DNS A-labels. Unicode must first be explicitly encoded
// by the caller as IDNA; wildcards, URLs, ports and IP literals are never domains.
func CanonicalDomain(value string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(d) == 0 || len(d) > 253 || strings.TrimSpace(d) != d {
		return "", errors.New("invalid domain")
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", errors.New("domain cannot be an IP literal")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return "", errors.New("domain must use ASCII DNS labels")
			}
		}
	}
	return d, nil
}

func LocalDomain(d string) bool {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	return !strings.Contains(d, ".") || d == "localhost" || d == "local" || d == "lan" ||
		d == "home.arpa" ||
		strings.HasSuffix(d, ".localhost") ||
		strings.HasSuffix(d, ".local") ||
		strings.HasSuffix(d, ".lan") ||
		strings.HasSuffix(d, ".home.arpa") ||
		strings.HasSuffix(d, ".in-addr.arpa") ||
		strings.HasSuffix(d, ".ip6.arpa")
}

// CanonicalPrefix rejects host bits and nonpublic coverage. Explicit host IPs
// are accepted and represented as /32 or /128. Broad prefixes are checked at
// both boundaries and against every special-use interval, not only their base.
func CanonicalPrefix(value string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		a, e := netip.ParseAddr(value)
		if e != nil || a.Zone() != "" || a.Is4In6() {
			return netip.Prefix{}, errors.New("invalid address prefix")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() || p != p.Masked() || !platform.PublicAddress(p.Addr()) {
		return netip.Prefix{}, errors.New("prefix must be canonical and public")
	}
	// A routable base alone is insufficient (for example 128.0.0.0/1).
	for _, bad := range reserved {
		if p.Overlaps(bad) {
			return netip.Prefix{}, errors.New("prefix includes special-use addresses")
		}
	}
	return p, nil
}

var reserved = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/96",
		"::ffff:0:0/96",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"100::/64",
		"2001::/23",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
		"fec0::/10",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	result := make([]netip.Prefix, len(values))
	for i, s := range values {
		result[i] = netip.MustParsePrefix(s)
	}
	return result
}()

func ValidateRule(r model.RoutingRule) error {
	if r.Action != "direct" && r.Action != "bypass" {
		return errors.New("routing action must be direct or bypass")
	}
	if (r.Domain == "") == (r.CIDR == "") {
		return errors.New("routing rule requires exactly one domain or address prefix")
	}
	if r.Domain != "" {
		d, err := CanonicalDomain(r.Domain)
		if err != nil {
			return err
		}
		if LocalDomain(d) {
			return errors.New("local domains cannot be overridden")
		}
		return nil
	}
	if r.IncludeSubdomains {
		return errors.New("subdomain matching requires a domain")
	}
	_, err := CanonicalPrefix(r.CIDR)
	return err
}

type Decision struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// Classifier is immutable after construction and safe for concurrent readers.
type Classifier struct {
	rules    []model.RoutingRule
	domains  map[string]struct{}
	prefixes []netip.Prefix
	learned  map[string]time.Time
}

func NewClassifier(
	rules []model.RoutingRule,
	snapshot Snapshot,
	learned map[string]time.Time,
) (*Classifier, error) {
	c := &Classifier{
		domains: make(map[string]struct{}, len(snapshot.Domains)),
		learned: make(map[string]time.Time, len(learned)),
	}
	for _, r := range rules {
		if err := ValidateRule(r); err != nil {
			return nil, err
		}
		if r.Domain != "" {
			r.Domain, _ = CanonicalDomain(r.Domain)
		} else {
			p, _ := CanonicalPrefix(r.CIDR)
			r.CIDR = p.String()
		}
		c.rules = append(c.rules, r)
	}
	for _, d := range snapshot.Domains {
		v, e := CanonicalDomain(d)
		if e != nil || LocalDomain(v) {
			return nil, errors.New("invalid listed domain")
		}
		c.domains[v] = struct{}{}
	}
	for _, cidr := range snapshot.CIDRs {
		p, e := CanonicalPrefix(cidr)
		if e != nil {
			return nil, e
		}
		c.prefixes = append(c.prefixes, p)
	}
	for d, expiry := range learned {
		v, e := CanonicalDomain(d)
		if e != nil || LocalDomain(v) {
			return nil, errors.New("invalid learned domain")
		}
		c.learned[v] = expiry
	}
	return c, nil
}

func (c *Classifier) Decide(domain string, ip netip.Addr, now time.Time) Decision {
	d, _ := CanonicalDomain(domain)
	if (d != "" && LocalDomain(d)) || (ip.IsValid() && !platform.PublicAddress(ip)) {
		return Decision{"direct", "Local destination"}
	}
	for _, action := range []string{"direct", "bypass"} {
		for _, r := range c.rules {
			if r.Action != action {
				continue
			}
			match := r.Domain != "" && d != "" &&
				(r.Domain == d || r.IncludeSubdomains && strings.HasSuffix(d, "."+r.Domain))
			if r.CIDR != "" && ip.IsValid() {
				p, _ := netip.ParsePrefix(r.CIDR)
				match = p.Contains(ip.Unmap())
			}
			if match {
				return Decision{action, "Manual exception"}
			}
		}
	}
	if _, ok := c.domains[d]; ok {
		return Decision{"bypass", "Antifilter registry"}
	}
	for _, p := range c.prefixes {
		if p.Contains(ip.Unmap()) {
			return Decision{"bypass", "Antifilter registry"}
		}
	}
	if expiry, ok := c.learned[d]; ok && now.Before(expiry) {
		return Decision{"bypass", "Detected restriction"}
	}
	return Decision{"direct", "Default direct"}
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, s := range values {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
