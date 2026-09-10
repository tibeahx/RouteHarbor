package dataplane

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	SelectiveSourceID = "__selective"
	DefaultFakeIPv4   = "198.18.0.0/15"
	DefaultFakeIPv6   = "fd66:6f70:656e::/48"
)

type SelectiveSnapshotRef struct {
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
}

// SelectiveIntent carries bounded, typed dispatcher metadata, never engine JSON.
// Snapshot content lives outside both the request and the transaction journal.
type SelectiveIntent struct {
	FakePool      uint8                `json:"fake_pool"`
	Path          Path                 `json:"path"`
	DNSFrontPort  uint16               `json:"dns_front_port"`
	FakeIPv4      string               `json:"fake_ipv4"`
	FakeIPv6      string               `json:"fake_ipv6"`
	FailurePolicy string               `json:"failure_policy"`
	PolicyHash    string               `json:"policy_hash"`
	Snapshot      SelectiveSnapshotRef `json:"snapshot"`
}

func (s SelectiveIntent) Validate() error {
	p := s.Path
	if s.FakePool > 1 || p.SourceID != SelectiveSourceID || p.Kind != "tproxy" || p.Slot == 0 ||
		p.Slot > MaxPaths ||
		p.Port < 1024 ||
		p.Interface != "" ||
		!p.UDP ||
		s.DNSFrontPort < 1024 ||
		s.DNSFrontPort == p.Port ||
		s.FailurePolicy != "direct" ||
		s.FakeIPv4 != DefaultFakeIPv4 ||
		s.FakeIPv6 != DefaultFakeIPv6 {
		return errors.New(
			"invalid_selective: invalid fixed dispatcher allocation or failure policy",
		)
	}
	if len(s.PolicyHash) != 64 || strings.ToLower(s.PolicyHash) != s.PolicyHash {
		return errors.New("invalid_selective: verified policy hash required")
	}
	if _, err := hex.DecodeString(s.PolicyHash); err != nil {
		return errors.New("invalid_selective: invalid policy hash")
	}
	if s.Snapshot.Generation == 0 || len(s.Snapshot.SHA256) != 64 {
		return errors.New("invalid_selective: verified snapshot reference required")
	}
	if _, err := hex.DecodeString(s.Snapshot.SHA256); err != nil {
		return errors.New("invalid_selective: invalid snapshot digest")
	}
	return nil
}

func compileSelective(d Desired) (Plan, error) {
	s := d.Selective
	if d.Fallback != "closed" {
		return Plan{}, errors.New("invalid_selective: bypass fallback must remain closed")
	}
	if d.Network.DNS != "block" && d.Network.DNS != "selected-path" {
		return Plan{}, errors.New("invalid_selective: invalid DNS policy")
	}
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	if d.Network.IPv6 == "proxy" && !s.Path.IPv6 {
		return Plan{}, errors.New("invalid_selective: dispatcher must support protected IPv6")
	}
	if d.BreakExisting {
		return Plan{}, errors.New(
			"invalid_selective: selective routing preserves ordinary connections",
		)
	}
	for _, prefix := range d.Network.LocalPrefixes {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		} // Shared network validation returns its precise error.
		for _, fake := range []string{s.FakeIPv4, s.FakeIPv6} {
			f := netip.MustParsePrefix(fake)
			if p.Overlaps(f) {
				return Plan{}, errors.New("invalid_selective: fake IP overlaps a local prefix")
			}
		}
	}
	paths := append([]Path(nil), d.Paths...)
	if d.Continuity != nil {
		if _, err := materializeContinuity(d); err != nil {
			return Plan{}, err
		}
		paths = append(paths, d.Continuity.Path)
	}
	selected := d.Selected == ""
	for _, p := range paths {
		if p.SourceID == SelectiveSourceID || p.Slot == s.Path.Slot || p.Port == s.DNSFrontPort ||
			p.DNSPort == s.DNSFrontPort {
			return Plan{}, errors.New("invalid_selective: dispatcher allocation collision")
		}
		if p.SourceID == d.Selected {
			selected = true
			if p.Kind == "direct" && d.Continuity == nil {
				return Plan{}, errors.New("invalid_selective: direct cannot be a bypass source")
			}
		}
	}
	if !selected {
		return Plan{}, errors.New("invalid_selective: selected bypass is not prepared")
	}
	// Reuse all source/network validation and policy route allocation, then render
	// one permanent classifier independent of the selected bypass source.
	normalized := d
	normalized.Selective, normalized.Continuity = nil, nil
	normalized.Paths = append(paths, s.Path)
	normalized.Selected, normalized.Fallback = SelectiveSourceID, "closed"
	normalized.Network.DNS = "block" // DNS uses the local front, not source DNS ports.
	p, err := Compile(normalized)
	if err != nil {
		return p, err
	}
	p.Desired = d
	p.NFT = renderSelective(d, false)
	p.GuardNFT = renderSelective(d, true)
	p.Warnings = []string{
		"Selective routing uses managed DNS; clients with private encrypted DNS may bypass domain classification.",
		"Classifier failure restores direct WAN and DNS; cached synthetic addresses require DNS refresh.",
		"Flow offload must be disabled.",
	}
	return p, nil
}

func selectiveSyntheticRules(b *strings.Builder, s *SelectiveIntent, action string) {
	fmt.Fprintf(b, "  ip daddr %s %s\n  ip6 daddr %s %s\n", s.FakeIPv4, action, s.FakeIPv6, action)
}

func renderSelective(d Desired, guard bool) string {
	s := d.Selective
	table := Table
	if guard {
		table = GuardTable
	}
	var b strings.Builder
	fmt.Fprintf(
		&b,
		"add table inet %s { comment %q; }\nflush table inet %s\ntable inet %s {\n",
		table,
		Owner,
		table,
		table,
	)
	if guard {
		// The approved emergency policy is direct, including DNS. The sole lasting
		// interception is rejection of stale synthetic destinations.
		b.WriteString(
			" chain prerouting { type filter hook prerouting priority -160; policy accept;\n",
		)
		selectiveSyntheticRules(&b, s, "drop")
		b.WriteString(" }\n chain output { type filter hook output priority -160; policy accept;\n")
		selectiveSyntheticRules(&b, s, "drop")
		b.WriteString(" }\n}\n")
		return b.String()
	}
	lan := quotedSet(d.Network.LANInterfaces)
	mark := markHex(Mark(s.Path.Slot))
	fmt.Fprintf(
		&b,
		" chain dns_classify { type filter hook prerouting priority -156; policy accept; iifname %s meta l4proto { tcp, udp } th dport 53 ct mark set (ct mark & 0x0000ffff) | %s; }\n",
		lan,
		mark,
	)
	fmt.Fprintf(
		&b,
		" chain dns { type nat hook prerouting priority -155; policy accept; iifname %s meta l4proto { tcp, udp } th dport 53 redirect to :%d; }\n",
		lan,
		s.DNSFrontPort,
	)
	fmt.Fprintf(
		&b,
		" chain prerouting { type filter hook prerouting priority -150; policy accept; iifname %s jump protect; }\n chain protect {\n",
		lan,
	)
	// Synthetic interception precedes all private/router-address exceptions.
	fmt.Fprintf(&b, "  ip daddr %s jump dispatch\n", s.FakeIPv4)
	if d.Network.IPv6 == "block" {
		fmt.Fprintf(&b, "  ip6 daddr %s drop\n", s.FakeIPv6)
	} else {
		fmt.Fprintf(&b, "  ip6 daddr %s jump dispatch\n", s.FakeIPv6)
	}
	b.WriteString(
		"  meta l4proto { tcp, udp } th dport 53 return\n  # helper injects current router addresses here\n  ip daddr 224.0.0.0/24 return\n  ip6 daddr ff02::/16 return\n  ip6 daddr fe80::/10 return\n",
	)
	for _, prefix := range d.Network.LocalPrefixes {
		family := "ip"
		if strings.Contains(prefix, ":") {
			family = "ip6"
		}
		fmt.Fprintf(&b, "  %s daddr %s return\n", family, prefix)
	}
	if d.Network.IPv6 == "block" {
		b.WriteString("  meta nfproto ipv6 drop\n")
	}
	b.WriteString("  jump dispatch\n }\n chain dispatch {\n")
	fmt.Fprintf(
		&b,
		"  meta nfproto ipv4 meta l4proto { tcp, udp } ct mark set (ct mark & 0x0000ffff) | %s meta mark set (meta mark & 0x0000ffff) | %s tproxy ip to 127.0.0.1:%d accept\n",
		mark,
		mark,
		s.Path.Port,
	)
	if d.Network.IPv6 == "proxy" {
		fmt.Fprintf(
			&b,
			"  meta nfproto ipv6 meta l4proto { tcp, udp } ct mark set (ct mark & 0x0000ffff) | %s meta mark set (meta mark & 0x0000ffff) | %s tproxy ip6 to [::1]:%d accept\n",
			mark,
			mark,
			s.Path.Port,
		)
	}
	// Preserve legacy IPv6 policy and prevent unmappable synthetic protocols.
	selectiveSyntheticRules(&b, s, "drop")
	b.WriteString(" }\n chain output { type filter hook output priority -5; policy accept;\n")
	selectiveSyntheticRules(&b, s, "drop")
	for _, p := range d.Paths {
		m := markHex(Mark(p.Slot))
		if p.Kind == "interface" {
			fmt.Fprintf(&b, "  meta mark & 0xffff0000 == %s oifname != %q drop\n", m, p.Interface)
		}
		if p.Kind == "packet-engine" {
			fmt.Fprintf(
				&b,
				"  meta mark & 0xffff0000 == %s meta mark & 0x0000c000 == 0 meta l4proto { tcp, udp } meta mark set meta mark | 0x4000 queue num %d\n",
				m,
				Queue(p.Slot),
			)
		}
	}
	b.WriteString(" }\n chain forward { type filter hook forward priority -5; policy accept;\n")
	selectiveSyntheticRules(&b, s, "drop")
	// A vanished local dispatch route cannot make a marked LAN flow escape.
	fmt.Fprintf(&b, "  iifname %s ct mark & 0xffff0000 == %s drop\n }\n}\n", lan, mark)
	return b.String()
}

// EmergencyDirectNFT is the complete service-owned emergency forwarding table.
// It retains synthetic rejection while restoring the original router DNS/WAN.
func EmergencyDirectNFT(d Desired) (string, error) {
	if d.Selective == nil {
		return "", errors.New("selective_policy_required")
	}
	if _, err := Compile(d); err != nil {
		return "", err
	}
	text := strings.ReplaceAll(renderSelective(d, true), GuardTable, Table)
	// nft flush clears chain contents but preserves base-chain hook metadata.
	// Replacing the active table must retain its existing hook priorities.
	text = strings.Replace(
		text,
		"chain prerouting { type filter hook prerouting priority -160",
		"chain prerouting { type filter hook prerouting priority -150",
		1,
	)
	text = strings.Replace(
		text,
		"chain output { type filter hook output priority -160",
		"chain output { type filter hook output priority -5",
		1,
	)
	return text, nil
}
