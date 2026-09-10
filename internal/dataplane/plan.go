// Package dataplane compiles typed network intent into a service-owned nftables
// table and a bounded set of policy routes. It never accepts nft text from clients.
package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

const (
	Table                = "routeharbor"
	GuardTable           = "routeharbor_guard"
	ProbeTable           = "routeharbor_probe"
	Owner                = "RouteHarbor service-owned v1"
	MarkMask      uint32 = 0xffff0000
	NamespaceMask uint32 = 0xff000000
	Namespace     uint32 = 0x4f000000
	BypassMark    uint32 = 0x4ffe0000
	MaxPaths             = 250
)

type Path struct {
	SourceID  string `json:"source_id"`
	Kind      string `json:"kind"`
	Slot      uint16 `json:"slot"`
	Port      uint16 `json:"port,omitempty"`
	DNSPort   uint16 `json:"dns_port,omitempty"`
	Interface string `json:"interface,omitempty"`
	IPv6      bool   `json:"ipv6"`
	UDP       bool   `json:"udp"`
}
type Desired struct {
	Network       model.Network     `json:"network"`
	Paths         []Path            `json:"paths"`
	Unavailable   []string          `json:"unavailable,omitempty"`
	Selected      string            `json:"selected"`
	Fallback      string            `json:"fallback"`
	BreakExisting bool              `json:"break_existing,omitempty"`
	Continuity    *ContinuityIntent `json:"continuity,omitempty"`
	Selective     *SelectiveIntent  `json:"selective,omitempty"`
}
type Route struct {
	Family   int    `json:"family"`
	Table    int    `json:"table"`
	Priority int    `json:"priority"`
	Mark     uint32 `json:"mark"`
	Device   string `json:"device"`
	Local    bool   `json:"local"`
}
type Plan struct {
	// SafetyNetworks is trusted helper-only recovery metadata, never client input.
	SafetyNetworks []model.Network `json:"-"`
	IngressDevices []string        `json:"-"`
	DNSGuardUID    uint32          `json:"-"`
	Desired        Desired         `json:"desired"`
	NFT            string          `json:"nft"`
	GuardNFT       string          `json:"guard_nft"`
	Routes         []Route         `json:"routes"`
	Warnings       []string        `json:"warnings"`
}

func Mark(slot uint16) uint32 {
	return Namespace | uint32(slot)<<16
}

func Queue(slot uint16) uint16 {
	return 21000 + slot
}

func Build(network model.Network, paths []Path, selected, fallback string) (Plan, error) {
	return Compile(Desired{Network: network, Paths: paths, Selected: selected, Fallback: fallback})
}

func Compile(d Desired) (Plan, error) {
	if d.Selective != nil {
		return compileSelective(d)
	}
	p := Plan{Desired: d, Routes: []Route{}, Warnings: []string{}}
	if d.Continuity != nil {
		var err error
		d, err = materializeContinuity(d)
		if err != nil {
			return p, err
		}
	}
	if !d.Network.Enabled {
		return p, errors.New("network_disabled: explicit enabled network intent is required")
	}
	if len(d.Network.LANInterfaces) == 0 || len(d.Network.LANInterfaces) > 32 {
		return p, errors.New("invalid_network: select between 1 and 32 LAN devices")
	}
	if !platform.ValidInterfaceName(d.Network.WANInterface) {
		return p, errors.New("invalid_network: WAN device must be selected explicitly")
	}
	seen := map[string]bool{}
	for _, dev := range d.Network.LANInterfaces {
		if !platform.ValidInterfaceName(dev) || dev == d.Network.WANInterface || dev == "lo" ||
			seen[dev] {
			return p, errors.New(
				"invalid_network: invalid, duplicate, or overlapping LAN/WAN devices",
			)
		}
		seen[dev] = true
	}
	if d.Network.IPv6 != "block" && d.Network.IPv6 != "proxy" {
		return p, errors.New("invalid_network: IPv6 must be block or proxy")
	}
	if d.Network.DNS == "selected-path" {
		ip, e := netip.ParseAddr(d.Network.DNSResolver)
		if e != nil || !platform.PublicAddress(ip) || ip.Is4In6() {
			return p, errors.New(
				"invalid_network: selected-path DNS requires an explicit public resolver IP",
			)
		}
	}
	if d.Network.DNS != "block" && d.Network.DNS != "selected-path" {
		return p, errors.New("invalid_network: DNS must be block or selected-path")
	}
	if d.Fallback != "closed" && d.Fallback != "direct" {
		return p, errors.New("invalid_policy: fallback must be closed or direct")
	}
	if len(d.Network.LocalPrefixes) == 0 || len(d.Network.LocalPrefixes) > 64 {
		return p, errors.New("invalid_network: explicit local prefixes are required")
	}
	for _, s := range d.Network.LocalPrefixes {
		q, e := netip.ParsePrefix(s)
		if e != nil || q != q.Masked() || q.Bits() == 0 ||
			(!q.Addr().IsPrivate() && !q.Addr().IsLinkLocalUnicast()) {
			return p, errors.New(
				"invalid_network: local prefixes must be canonical private or link-local subnets",
			)
		}
	}
	if len(d.Paths) > MaxPaths {
		return p, errors.New(
			"resource_exhausted: at most 250 concurrent paths fit the reserved mark namespace; saved sources are unlimited",
		)
	}
	slots := map[uint16]bool{}
	ids := map[string]bool{}
	if len(d.Unavailable) > 250 {
		return p, errors.New(
			"resource_exhausted: unavailable source metadata exceeds the transaction limit",
		)
	}
	for _, id := range d.Unavailable {
		if len(id) == 0 || len(id) > 80 || !validID(id) || ids[id] || id == d.Selected {
			return p, errors.New(
				"invalid_path: unavailable identities must be unique and cannot be selected",
			)
		}
		ids[id] = true
	}
	if len(d.Unavailable) > 0 {
		p.Warnings = append(
			p.Warnings,
			"New unavailable sources are excluded from this routing transaction; prepare and confirm again after they recover",
		)
	}
	ports := map[uint16]bool{}
	found := d.Selected == ""
	for _, path := range d.Paths {
		if len(path.SourceID) == 0 || len(path.SourceID) > 80 || !validID(path.SourceID) ||
			path.Slot == 0 ||
			path.Slot > MaxPaths ||
			slots[path.Slot] ||
			ids[path.SourceID] {
			return p, errors.New("invalid_path: invalid source identity or duplicate allocation")
		}
		slots[path.Slot] = true
		ids[path.SourceID] = true
		if path.SourceID == d.Selected {
			found = true
		}
		if path.Interface != "" && !platform.ValidInterfaceName(path.Interface) {
			return p, errors.New("invalid_path: invalid tunnel device")
		}
		switch path.Kind {
		case "direct":
			if path.Port != 0 || path.DNSPort != 0 || path.Interface != "" {
				return p, errors.New(
					"invalid_path: direct paths cannot have proxy or tunnel parameters",
				)
			}
		case "tproxy":
			if path.Port < 1024 || ports[path.Port] || path.Interface != "" {
				return p, errors.New(
					"invalid_path: transparent paths require a unique unprivileged listener",
				)
			}
			ports[path.Port] = true
			if path.DNSPort != 0 {
				if path.DNSPort < 1024 || ports[path.DNSPort] {
					return p, errors.New(
						"invalid_path: dedicated DNS listener must have a unique unprivileged port",
					)
				}
				ports[path.DNSPort] = true
			}
		case "interface":
			if path.Port != 0 || path.DNSPort != 0 || path.Interface == "" ||
				seen[path.Interface] ||
				path.Interface == d.Network.WANInterface ||
				path.Interface == "lo" {
				return p, errors.New(
					"invalid_path: interface paths require a separate tunnel device",
				)
			}
		case "packet-engine":
			if path.Port != 0 || path.DNSPort != 0 || path.Interface != "" || !path.UDP {
				return p, errors.New(
					"invalid_path: packet engines require their allocated queue and TCP/UDP support",
				)
			}
		default:
			return p, errors.New("invalid_path: unknown dataplane path kind")
		}
		if path.Kind != "direct" && d.Network.IPv6 == "proxy" && !path.IPv6 &&
			(d.Continuity == nil || path.SourceID == ContinuitySourceID) {
			return p, errors.New(
				"capability_unavailable: each retained protected path must support IPv6",
			)
		}
		if path.Kind == "tproxy" && d.Network.DNS == "selected-path" && path.DNSPort == 0 &&
			(d.Continuity == nil || path.SourceID == ContinuitySourceID) {
			return p, errors.New(
				"capability_unavailable: selected-path DNS requires a dedicated transparent resolver",
			)
		}
		if path.Kind == "direct" || path.Kind == "packet-engine" {
			for _, fam := range []int{4, 6} {
				if fam == 6 && d.Network.IPv6 == "block" {
					continue
				}
				p.Routes = append(
					p.Routes,
					Route{
						Family:   fam,
						Table:    254,
						Priority: 22000 + int(path.Slot),
						Mark:     Mark(path.Slot),
					},
				)
			}
		}
		if path.Kind == "tproxy" || path.Kind == "interface" {
			for _, fam := range []int{4, 6} {
				if fam == 6 && d.Network.IPv6 == "block" {
					continue
				}
				dev := path.Interface
				local := path.Kind == "tproxy"
				if local {
					dev = "lo"
				}
				p.Routes = append(
					p.Routes,
					Route{
						fam,
						20000 + int(path.Slot),
						22000 + int(path.Slot),
						Mark(path.Slot),
						dev,
						local,
					},
				)
			}
		}
	}
	if !found {
		return p, errors.New("invalid_path: selected source is not prepared")
	}
	if d.Selected == "" && d.Fallback == "direct" {
		return p, errors.New(
			"invalid_policy: direct fallback requires selecting an explicit prepared direct source",
		)
	}
	sort.Slice(p.Routes, func(i, j int) bool {
		if p.Routes[i].Family != p.Routes[j].Family {
			return p.Routes[i].Family < p.Routes[j].Family
		}
		return p.Routes[i].Table < p.Routes[j].Table
	})
	for _, path := range d.Paths {
		if path.SourceID == d.Selected && path.Kind == "tproxy" && !path.UDP {
			p.Warnings = append(
				p.Warnings,
				"The selected source supports TCP only; external UDP is blocked to prevent direct escape.",
			)
		}
	}
	if d.BreakExisting {
		p.Warnings = append(
			p.Warnings,
			"After confirmation, reset only the previous selected source connection tracking; applications may need to reconnect",
		)
	}
	p.NFT = render(d, false)
	p.GuardNFT = render(d, true)
	if d.Network.DNS == "block" {
		p.Warnings = append(
			p.Warnings,
			"Plain DNS on TCP/UDP port 53 is blocked for protected traffic. Configure an encrypted DNS client or an adapter with dedicated DNS support.",
		)
	}
	if d.Network.IPv6 == "block" {
		p.Warnings = append(
			p.Warnings,
			"External IPv6 is blocked. LAN management and local IPv6 services remain reachable.",
		)
	}
	p.Warnings = append(
		p.Warnings,
		"Flow offload must be disabled; fw4/mark/route conflicts are checked again by the privileged helper.",
	)
	return p, nil
}

func validID(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' &&
			r != '_' {
			return false
		}
	}
	return true
}

func quotedSet(values []string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = strconv.Quote(v)
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

func markHex(mark uint32) string {
	return fmt.Sprintf("0x%08x", mark)
}

func render(d Desired, guard bool) string {
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
	if !guard {
		b.WriteString(" chain select_flow { comment \"RouteHarbor classifier v1\";\n")
		b.WriteString(selectionRules(d))
		b.WriteString(" }\n")
		// Conntrack exists after priority -200. Classify DNS before NAT (-155),
		// including queries addressed to the router; established flows retain marks.
		fmt.Fprintf(
			&b,
			" chain dns_classify { type filter hook prerouting priority -156; policy accept; iifname %s meta l4proto { tcp, udp } th dport 53 jump select_flow; }\n",
			quotedSet(d.Network.LANInterfaces),
		)
		if d.Network.DNS == "selected-path" {
			resolver, _ := netip.ParseAddr(d.Network.DNSResolver)
			family, nf := "ip", "ipv4"
			if resolver.Is6() {
				family, nf = "ip6", "ipv6"
			}
			b.WriteString(" chain dns { type nat hook prerouting priority -155; policy accept;\n")
			for _, path := range d.Paths {
				if path.Kind != "tproxy" {
					fmt.Fprintf(
						&b,
						"  iifname %s ct mark & 0xffff0000 == %s meta nfproto %s meta l4proto { tcp, udp } th dport 53 dnat %s to %s\n",
						quotedSet(d.Network.LANInterfaces),
						markHex(Mark(path.Slot)),
						nf,
						family,
						resolver.String(),
					)
				}
			}
			b.WriteString(" }\n")
		}
	}
	// A separate early hook prevents direct escape while route operations are in progress.
	priority := -150
	if guard {
		priority = -160
	}
	fmt.Fprintf(
		&b,
		" chain prerouting { type filter hook prerouting priority %d; policy accept; iifname %s jump protect; }\n chain protect {\n",
		priority,
		quotedSet(d.Network.LANInterfaces),
	)
	if d.Network.DNS == "block" {
		if !guard {
			b.WriteString("  meta l4proto { tcp, udp } th dport 53 jump dns_block\n")
		} else {
			b.WriteString("  meta l4proto { tcp, udp } th dport 53 drop\n")
		}
	}
	// Dispatch DNS using the connection owner, never the currently selected path.
	// This is deliberately before router/local-prefix exceptions for transparent DNS.
	if !guard && d.Network.DNS == "selected-path" {
		resolver, _ := netip.ParseAddr(d.Network.DNSResolver)
		other := "ipv6"
		if resolver.Is6() {
			other = "ipv4"
		}
		for _, path := range d.Paths {
			if path.Kind == "tproxy" && path.DNSPort == 0 {
				continue
			}
			m := markHex(Mark(path.Slot))
			if path.Kind == "tproxy" {
				fmt.Fprintf(
					&b,
					"  ct mark & 0xffff0000 == %s meta l4proto { tcp, udp } th dport 53 meta mark set (meta mark & 0x0000ffff) | %s tproxy to :%d accept\n",
					m,
					m,
					path.DNSPort,
				)
			} else {
				fmt.Fprintf(
					&b,
					"  ct mark & 0xffff0000 == %s meta nfproto %s meta l4proto { tcp, udp } th dport 53 drop\n",
					m,
					other,
				)
				if d.Network.IPv6 == "block" {
					fmt.Fprintf(
						&b,
						"  ct mark & 0xffff0000 == %s meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 drop\n",
						m,
					)
				}
				fmt.Fprintf(
					&b,
					"  ct mark & 0xffff0000 == %s meta l4proto { tcp, udp } th dport 53 meta mark set (meta mark & 0x0000ffff) | %s return\n",
					m,
					m,
				)
			}
		}
		b.WriteString("  meta l4proto { tcp, udp } th dport 53 drop\n")
	}
	b.WriteString("  # helper injects current router addresses here\n")
	// Preserve link-local multicast/neighbor discovery and only explicitly mapped LAN prefixes.
	b.WriteString(
		"  ip daddr 224.0.0.0/24 return\n  ip6 daddr ff02::/16 return\n  ip6 daddr fe80::/10 return\n",
	)
	for _, prefix := range d.Network.LocalPrefixes {
		family := "ip"
		if strings.Contains(prefix, ":") {
			family = "ip6"
		}
		fmt.Fprintf(&b, "  %s daddr %s return\n", family, prefix)
	}
	if guard {
		b.WriteString("  drop\n }\n}\n")
		return b.String()
	}
	if d.Network.IPv6 == "block" {
		b.WriteString("  meta nfproto ipv6 drop\n")
	}
	// Only this regular chain changes during an ordinary selection switch.
	b.WriteString("  jump select_flow\n")
	for _, path := range d.Paths {
		m := markHex(Mark(path.Slot))
		fmt.Fprintf(
			&b,
			"  ct mark & 0xffff0000 == %s meta mark set (meta mark & 0x0000ffff) | %s\n",
			m,
			m,
		)
	}
	for _, path := range d.Paths {
		m := markHex(Mark(path.Slot))
		switch path.Kind {
		case "direct":
			fmt.Fprintf(&b, "  meta mark & 0xffff0000 == %s return\n", m)
		case "packet-engine":
			fmt.Fprintf(&b, "  meta mark & 0xffff0000 == %s meta l4proto { tcp, udp } return\n", m)
		case "interface":
			fmt.Fprintf(&b, "  meta mark & 0xffff0000 == %s return\n", m)
		case "tproxy":
			protocol := "tcp"
			if path.UDP {
				protocol = "{ tcp, udp }"
			}
			fmt.Fprintf(
				&b,
				"  meta mark & 0xffff0000 == %s meta l4proto %s tproxy to :%d accept\n",
				m,
				protocol,
				path.Port,
			)
		}
	}
	// Unknown marks and unsupported protocols never fall through to the ordinary WAN.
	b.WriteString("  drop\n }\n")
	if d.Network.DNS == "block" {
		b.WriteString(" chain dns_block {\n")
		for _, path := range d.Paths {
			if path.Kind == "direct" {
				fmt.Fprintf(&b, "  ct mark & 0xffff0000 == %s return\n", markHex(Mark(path.Slot)))
			}
		}
		b.WriteString("  meta l4proto { tcp, udp } th dport 53 drop\n }\n")
	}
	// Guard the kernel forward path against route deletion or tunnel disappearance.
	fmt.Fprintf(
		&b,
		" chain forward { type filter hook forward priority -5; policy accept; iifname %s jump forward_check; }\n chain forward_check {\n",
		quotedSet(d.Network.LANInterfaces),
	)
	for _, prefix := range d.Network.LocalPrefixes {
		family := "ip"
		if strings.Contains(prefix, ":") {
			family = "ip6"
		}
		fmt.Fprintf(&b, "  %s daddr %s return\n", family, prefix)
	}
	for _, path := range d.Paths {
		switch path.Kind {
		case "direct", "packet-engine":
			fmt.Fprintf(&b, "  ct mark & 0xffff0000 == %s return\n", markHex(Mark(path.Slot)))
		case "interface":
			fmt.Fprintf(
				&b,
				"  ct mark & 0xffff0000 == %s oifname %q return\n",
				markHex(Mark(path.Slot)),
				path.Interface,
			)
		}
	}
	b.WriteString("  drop\n }\n")
	b.WriteString(" chain postrouting { type filter hook postrouting priority 90; policy accept;\n")
	for _, path := range d.Paths {
		if path.Kind == "packet-engine" {
			fmt.Fprintf(
				&b,
				"  meta mark & 0xffff0000 == %s meta mark & 0x0000c000 == 0 meta l4proto { tcp, udp } queue num %d\n",
				markHex(Mark(path.Slot)),
				Queue(path.Slot),
			)
		}
	}
	b.WriteString(" }\n}\n")
	return b.String()
}

// SafeRollback does not silently reopen direct access after a strict transaction.
func SafeRollback(candidate Desired, previous *Desired) Desired {
	if (candidate.Fallback == "direct" || candidate.Selective != nil) && previous != nil {
		return *previous
	}
	safe := candidate
	safe.Paths = nil
	safe.Continuity = nil
	safe.Selective = nil
	safe.Selected = ""
	safe.Fallback = "closed"
	safe.Network.DNS = "block"
	return safe
}

// WithRouterAddresses replaces a fixed template marker with kernel-discovered
// addresses. This is called by the helper immediately before nft validation and
// application, so DHCP changes do not turn router services into proxy traffic.
func WithRouterAddresses(p Plan, addresses []netip.Addr) (Plan, error) {
	return withRouterAddresses(p, addresses, false)
}

// WithQuarantineRouterAddresses can run before netifd creates or addresses LAN
// devices. An empty set removes only dynamic router-address exceptions; explicit
// LAN prefixes and link-local management remain, followed by the early drop.
// Ordinary routing checks and application must use strict WithRouterAddresses.
func WithQuarantineRouterAddresses(p Plan, addresses []netip.Addr) (Plan, error) {
	if p.Desired.Selected != "" || p.Desired.Fallback != "closed" || len(p.Desired.Paths) != 0 {
		return p, errors.New("quarantine_policy_required")
	}
	return withRouterAddresses(p, addresses, true)
}

func withRouterAddresses(p Plan, addresses []netip.Addr, quarantine bool) (Plan, error) {
	if len(addresses) == 0 && !quarantine || len(addresses) > 512 {
		return p, errors.New(
			"router_addresses_unavailable: cannot discover a bounded local address set",
		)
	}
	v4, v6 := []string{}, []string{}
	seen := map[netip.Addr]bool{}
	for _, a := range addresses {
		if !a.IsValid() {
			return p, errors.New("router_addresses_invalid")
		}
		a = a.Unmap().WithZone("")
		if seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	var text strings.Builder
	if len(v4) > 0 {
		fmt.Fprintf(&text, "  ip daddr { %s } return\n", strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&text, "  ip6 daddr { %s } return\n", strings.Join(v6, ", "))
	}
	marker := "  # helper injects current router addresses here\n"
	p.NFT = strings.ReplaceAll(p.NFT, marker, text.String())
	p.GuardNFT = strings.ReplaceAll(p.GuardNFT, marker, text.String())
	return p, nil
}
