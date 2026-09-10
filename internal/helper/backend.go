package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

// NetworkBackend invokes only fixed nft/ip operations built from validated intent.
// Detect is injectable so namespace integration tests need not impersonate OpenWrt.
type NetworkBackend struct {
	Runner      platform.Runner
	Detect      func(context.Context) platform.Report
	NFTBinary   string
	IPBinary    string
	Packet      *PacketManager
	Ingress     func(context.Context, model.Network) ([]string, error)
	DNSIdentity func(context.Context) (DNSGuardIdentity, error)
}

func NewNetworkBackend() *NetworkBackend {
	return &NetworkBackend{
		Runner:      platform.ProductionRunner{},
		Detect:      platform.Detect,
		NFTBinary:   "/usr/sbin/nft",
		IPBinary:    "/sbin/ip",
		DNSIdentity: inspectDNSIdentity,
		Ingress:     discoverIngress,
	}
}

func (b *NetworkBackend) Check(ctx context.Context, p dataplane.Plan) error {
	if runtime.GOOS != "linux" {
		return errors.New(
			"platform_unsupported: network mutation is only available on OpenWrt Linux",
		)
	}
	checked, err := dataplane.Compile(p.Desired)
	if err != nil {
		return err
	}
	if checked.NFT != p.NFT {
		return errors.New("invalid_plan: generated rules do not match typed intent")
	}
	if err = b.checkEnvironment(ctx, p, false); err != nil {
		return err
	}
	if err = b.checkTables(ctx); err != nil {
		return err
	}
	p, err = withLocalAddresses(p)
	if err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--check", "--file", "-"},
		[]byte(p.GuardNFT+p.NFT),
	); err != nil {
		return errors.New("nft_check_failed: kernel rejected generated rules before mutation")
	}
	return nil
}

func (b *NetworkBackend) checkEnvironment(
	ctx context.Context,
	p dataplane.Plan,
	selectedOnly bool,
) error {
	report := b.Detect(ctx)
	if !report.Supported || report.Firewall != "fw4/nftables" {
		return errors.New(
			"platform_unsupported: OpenWrt with fw4 and safe flow offload settings is required",
		)
	}
	if !report.Capabilities["lifecycle_guard"].Available {
		return errors.New(
			"lifecycle_guard_unavailable: install the OpenRHP guard package and enable fw4 automatic includes",
		)
	}
	if !report.Capabilities["flow_offload_safe"].Available {
		return errors.New(
			"flow_offload_enabled: disable software and hardware flow offload before applying",
		)
	}
	devices := map[string]platform.Interface{}
	for _, i := range report.Interfaces {
		devices[i.Device] = i
	}
	if wan, ok := devices[p.Desired.Network.WANInterface]; !ok || wan.Role != "uplink" {
		return errors.New(
			"interface_mismatch: selected WAN must be an observed default-route device",
		)
	}
	localPrefixes := []netip.Prefix{}
	for _, dev := range p.Desired.Network.LANInterfaces {
		i, ok := devices[dev]
		if !ok || i.Role == "uplink" || !i.Up {
			return errors.New(
				"interface_mismatch: selected LAN device must be an active netifd local interface",
			)
		}
		for _, s := range i.Prefixes {
			if pref, e := netip.ParsePrefix(s); e == nil {
				localPrefixes = append(localPrefixes, pref)
			}
		}
	}
	for _, s := range p.Desired.Network.LocalPrefixes {
		pref, _ := netip.ParsePrefix(s)
		ok := false
		for _, actual := range localPrefixes {
			if actual.Addr().BitLen() == pref.Addr().BitLen() && actual.Bits() <= pref.Bits() &&
				actual.Contains(pref.Addr()) {
				ok = true
			}
		}
		if !ok {
			return errors.New(
				"prefix_mismatch: local exception is not part of a selected LAN subnet",
			)
		}
	}
	paths := p.Desired.Paths
	if p.Desired.Continuity != nil {
		paths = append(append([]dataplane.Path(nil), paths...), p.Desired.Continuity.Path)
	}
	if p.Desired.Selective != nil {
		if err := b.CheckFlowReset(ctx); err != nil {
			return err
		}
		paths = append(append([]dataplane.Path(nil), paths...), p.Desired.Selective.Path)
		for _, i := range report.Interfaces {
			if err := validateSelectivePrefixes(p, i.Prefixes); err != nil {
				return err
			}
		}
	}
	for _, path := range paths {
		if selectedOnly && path.SourceID != p.Desired.Selected {
			continue
		}
		if path.Kind == "packet-engine" {
			if !report.Capabilities["nfqueue"].Available {
				return errors.New(
					"capability_unavailable: NFQUEUE modules are required for retained packet paths",
				)
			}
			if path.SourceID == p.Desired.Selected &&
				(b.Packet == nil || !b.Packet.Running(path.SourceID, int(path.Slot))) {
				return errors.New(
					"capability_unavailable: the selected packet path requires its verified live engine",
				)
			}
		}
		if path.Kind == "tproxy" {
			if !report.Capabilities["tproxy"].Available {
				return errors.New("capability_unavailable: loaded TPROXY modules are required")
			}
			if p.Desired.Network.IPv6 == "proxy" && !report.Capabilities["ipv6"].Available {
				return errors.New("capability_unavailable: IPv6 TPROXY modules are required")
			}
		}
		if path.Kind == "interface" {
			i, ok := devices[path.Interface]
			if !ok || !i.Up || i.Protocol == "static" || i.Protocol == "dhcp" ||
				i.Protocol == "dhcpv6" {
				return errors.New("interface_mismatch: path is not an active netifd tunnel device")
			}
		}
	}
	return nil
}

func (b *NetworkBackend) checkTables(ctx context.Context) error {
	data, err := b.Runner.Run(ctx, b.NFTBinary, []string{"-j", "list", "ruleset"}, nil)
	if err != nil {
		return errors.New("firewall_unavailable: cannot inspect nftables rules")
	}
	var rules struct {
		NFT []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &rules) != nil {
		return errors.New("firewall_invalid: nftables returned invalid metadata")
	}
	for _, entry := range rules.NFT {
		if raw, ok := entry["table"]; ok {
			var table struct{ Family, Name, Comment string }
			if json.Unmarshal(raw, &table) != nil {
				return errors.New("firewall_invalid")
			}
			if table.Name == dataplane.Table || table.Name == dataplane.GuardTable ||
				table.Name == dataplane.ProbeTable {
				owned := table.Comment == dataplane.Owner
				if table.Family == "inet" && table.Comment == "" {
					raw, e := b.Runner.Run(
						ctx,
						b.NFTBinary,
						[]string{"list", "table", "inet", table.Name},
						nil,
					)
					owned = e == nil && nftTableOwnedText(raw, table.Name)
				}
				if table.Family != "inet" || !owned {
					return errors.New(
						"ownership_conflict: reserved nftables table belongs to another owner",
					)
				}
			}
		}
		if _, ok := entry["flowtable"]; ok {
			return errors.New(
				"flow_offload_enabled: an nftables flowtable can bypass protected traffic",
			)
		}
		if raw, ok := entry["rule"]; ok {
			var rule struct {
				Table string `json:"table"`
				Expr  any    `json:"expr"`
			}
			if json.Unmarshal(raw, &rule) != nil {
				return errors.New("firewall_invalid")
			}
			if rule.Table != dataplane.Table && rule.Table != dataplane.GuardTable &&
				rule.Table != dataplane.ProbeTable &&
				hasMarkExpression(rule.Expr) {
				return errors.New(
					"mark_conflict: foreign firewall rules use packet or conntrack marks; allocation requires explicit integration",
				)
			}
		}
	}
	return nil
}

func hasMarkExpression(v any) bool {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if hasMarkExpression(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if k == "key" && e == "mark" {
				return true
			}
			if hasMarkExpression(e) {
				return true
			}
		}
	}
	return false
}

func (b *NetworkBackend) Apply(
	ctx context.Context,
	p dataplane.Plan,
	previous *dataplane.Plan,
) error {
	if runtime.GOOS != "linux" {
		return errors.New("platform_unsupported")
	}
	fresh, err := dataplane.Compile(p.Desired)
	if err != nil {
		return err
	}
	fresh.DNSGuardUID = p.DNSGuardUID
	fresh.IngressDevices = p.IngressDevices
	p = fresh
	if err = b.checkTables(ctx); err != nil {
		return err
	}
	// Refuse reserved route collisions before the first mutation.
	if err = b.checkRoutes(ctx, p, previous); err != nil {
		return err
	}
	p, err = withLocalAddresses(p)
	if err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--check", "--file", "-"},
		[]byte(p.GuardNFT+p.NFT),
	); err != nil {
		return errors.New("nft_check_failed")
	}
	if err = b.applySelectiveGuards(ctx, p, previous); err != nil {
		return err
	}
	if err = b.applyDNSGuard(ctx, p, previous); err != nil {
		return err
	}
	if err = b.applySafety(ctx, p, previous); err != nil {
		return err
	}
	if err = b.saveGuard(p); err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"--file", "-"},
		[]byte(p.GuardNFT),
	); err != nil {
		return errors.New("guard_apply_failed")
	}
	// Any subsequent failure intentionally leaves the fail-closed guard installed.
	for _, r := range p.Routes {
		if r.Table != 254 {
			args := []string{
				"-" + strconv.Itoa(r.Family),
				"route",
				"replace",
				"table",
				strconv.Itoa(r.Table),
			}
			if r.Local {
				args = append(args, "local")
			}
			args = append(args, "default", "dev", r.Device)
			if _, err = b.Runner.Run(ctx, b.IPBinary, args, nil); err != nil {
				return errors.New("route_apply_failed")
			}
		}
		exists, err := b.ruleExists(ctx, r)
		if err != nil {
			return err
		}
		if !exists {
			args := []string{
				"-" + strconv.Itoa(r.Family),
				"rule",
				"add",
				"priority",
				strconv.Itoa(r.Priority),
				"fwmark",
				fmt.Sprintf("0x%08x/0xffff0000", r.Mark),
				"lookup",
				strconv.Itoa(r.Table),
			}
			if _, err = b.Runner.Run(ctx, b.IPBinary, args, nil); err != nil {
				return errors.New("rule_apply_failed")
			}
		}
	}
	if _, err = b.Runner.Run(ctx, b.NFTBinary, []string{"--file", "-"}, []byte(p.NFT)); err != nil {
		return errors.New("firewall_apply_failed")
	}
	if previous != nil {
		for _, r := range previous.Routes {
			if !containsRoute(p.Routes, r) {
				if err = b.removeRoute(ctx, r); err != nil {
					return err
				}
			}
		}
	}
	if err = b.cleanupSelectiveGuards(ctx, &p, previous, false); err != nil {
		return err
	}
	if p.Desired.Selective != nil && previous != nil {
		if err = b.removeDNSGuard(ctx, *previous); err != nil {
			return err
		}
	}
	if err = b.cleanupSafety(ctx, p, previous); err != nil {
		return err
	}
	if _, err = b.Runner.Run(
		ctx,
		b.NFTBinary,
		[]string{"delete", "table", "inet", dataplane.GuardTable},
		nil,
	); err != nil {
		return errors.New("guard_remove_failed")
	}
	return nil
}

func containsRoute(list []dataplane.Route, r dataplane.Route) bool {
	for _, v := range list {
		if v == r {
			return true
		}
	}
	return false
}

type ipRule struct {
	Priority          int             `json:"priority"`
	FWMark            json.RawMessage `json:"fwmark"`
	FWMask            json.RawMessage `json:"fwmask"`
	Table             json.RawMessage `json:"table"`
	IIF               string          `json:"iif"`
	IIFName           string          `json:"iifname"`
	Unsupported       bool            `json:"-"`
	UIDStart          *uint32         `json:"uid_start"`
	UIDEnd            *uint32         `json:"uid_end"`
	IPProto           string          `json:"ipproto"`
	DPort             uint16          `json:"dport"`
	Action            string          `json:"action"`
	Destination       string          `json:"dst,omitempty"`
	DestinationLength *int            `json:"dstlen,omitempty"`
}

// Unrecognized selectors or actions must not be mistaken for a standard or
// service-owned rule with the same priority. Only presentation metadata is ignored.
func (r *ipRule) UnmarshalJSON(data []byte) error {
	type fields ipRule
	var decoded fields
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key, value := range raw {
		switch key {
		case "priority",
			"fwmark",
			"fwmask",
			"table",
			"iif",
			"iifname",
			"protocol",
			"uid_start",
			"uid_end",
			"ipproto",
			"dport",
			"action":
		case "iif_detached":
			// iproute2 emits this presentation marker while an early-boot rule
			// waits for its named interface. The selector is still the exact iif.
			if string(value) != "null" || decoded.IIF == "" && decoded.IIFName == "" {
				decoded.Unsupported = true
			}
		case "dstlen":
		case "dst":
			if string(value) == `"all"` {
				decoded.Destination = ""
			}
		case "src":
			if string(value) != `"all"` {
				decoded.Unsupported = true
			}
		case "flags":
			var flags []string
			if json.Unmarshal(value, &flags) != nil || len(flags) != 0 {
				decoded.Unsupported = true
			}
		default:
			decoded.Unsupported = true
		}
	}
	if decoded.DestinationLength != nil {
		addr, err := netip.ParseAddr(decoded.Destination)
		if err != nil || *decoded.DestinationLength < 0 ||
			*decoded.DestinationLength > addr.BitLen() {
			decoded.Unsupported = true
		} else {
			prefix := netip.PrefixFrom(addr, *decoded.DestinationLength)
			if prefix != prefix.Masked() {
				decoded.Unsupported = true
			}
			decoded.Destination = prefix.String()
		}
	}
	*r = ipRule(decoded)
	return nil
}

func defaultRule(rule ipRule) bool {
	if rule.Unsupported || rule.Destination != "" || hasDNSSelectors(rule) ||
		len(rule.FWMark) != 0 ||
		len(rule.FWMask) != 0 ||
		rule.IIF != "" ||
		rule.IIFName != "" {
		return false
	}
	switch rule.Priority {
	case 0:
		return number(rule.Table) == 255
	case 32766:
		return number(rule.Table) == 254
	case 32767:
		return number(rule.Table) == 253
	default:
		return false
	}
}

func number(raw json.RawMessage) uint64 {
	s := strings.Trim(string(raw), "\"")
	if s == "main" {
		return 254
	}
	if s == "local" {
		return 255
	}
	if s == "default" {
		return 253
	}
	v, _ := strconv.ParseUint(s, 0, 64)
	return v
}

func (b *NetworkBackend) rules(ctx context.Context, family int) ([]ipRule, error) {
	data, err := b.Runner.Run(
		ctx,
		b.IPBinary,
		[]string{"-" + strconv.Itoa(family), "-j", "rule", "show"},
		nil,
	)
	if err != nil {
		return nil, errors.New("route_inspection_failed")
	}
	var rules []ipRule
	if json.Unmarshal(data, &rules) != nil {
		return nil, errors.New("route_inspection_failed")
	}
	return rules, nil
}

func ruleMatches(rule ipRule, r dataplane.Route) bool {
	return !rule.Unsupported && rule.Destination == "" && !hasDNSSelectors(rule) &&
		rule.IIF == "" &&
		rule.IIFName == "" &&
		rule.Priority == r.Priority &&
		number(rule.FWMark) == uint64(r.Mark) &&
		number(rule.FWMask) == uint64(dataplane.MarkMask) &&
		number(rule.Table) == uint64(r.Table)
}

func (b *NetworkBackend) ruleExists(ctx context.Context, r dataplane.Route) (bool, error) {
	rules, err := b.rules(ctx, r.Family)
	if err != nil {
		return false, err
	}
	for _, rule := range rules {
		if rule.Priority == r.Priority {
			if !ruleMatches(rule, r) {
				return false, errors.New(
					"ownership_conflict: policy rule priority belongs to another owner",
				)
			}
			return true, nil
		}
	}
	return false, nil
}

func (b *NetworkBackend) checkRoutes(
	ctx context.Context,
	p dataplane.Plan,
	previous *dataplane.Plan,
) error {
	allowed := []dataplane.Route{}
	if previous != nil {
		allowed = append(allowed, previous.Routes...)
	}
	for _, family := range []int{4, 6} {
		rules, err := b.rules(ctx, family)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if defaultRule(rule) {
				continue
			}
			ours := safetyRuleAllowed(rule, previous) || dnsRuleAllowed(rule, previous) ||
				selectiveRuleAllowed(family, rule, previous)
			for _, r := range allowed {
				if r.Family == family && ruleMatches(rule, r) {
					ours = true
				}
			}
			if !ours {
				return errors.New(
					"ownership_conflict: existing non-default policy routing requires explicit integration",
				)
			}
		}
	}
	all := append(append([]dataplane.Route{}, p.Routes...), allowed...)
	for _, family := range []int{4, 6} {
		entries, err := b.routeEntries(ctx, family)
		if err != nil {
			return err
		}
		seen := map[int]bool{}
		for _, r := range all {
			if r.Table == 254 || r.Family != family || seen[r.Table] {
				continue
			}
			seen[r.Table] = true
			matches := []routeEntry{}
			for _, entry := range entries {
				if number(entry.Table) == uint64(r.Table) {
					matches = append(matches, entry)
				}
			}
			if len(matches) > 0 {
				expected := false
				for _, prior := range allowed {
					if prior.Family == r.Family && prior.Table == r.Table && len(matches) == 1 &&
						routeEntryMatches(matches[0], prior) {
						expected = true
					}
				}
				if !expected {
					return errors.New(
						"ownership_conflict: reserved route table contains foreign routes",
					)
				}
			}
		}
	}

	return nil
}

type routeEntry struct {
	Type    string          `json:"type"`
	Dst     string          `json:"dst"`
	Dev     string          `json:"dev"`
	Gateway string          `json:"gateway"`
	Table   json.RawMessage `json:"table"`
}

func routeEntryMatches(e routeEntry, r dataplane.Route) bool {
	return number(e.Table) == uint64(r.Table) && e.Dst == "default" && e.Dev == r.Device &&
		e.Gateway == "" &&
		((r.Local && e.Type == "local") || (!r.Local && (e.Type == "" || e.Type == "unicast")))
}

func (b *NetworkBackend) routeEntries(ctx context.Context, family int) ([]routeEntry, error) {
	data, err := b.Runner.Run(
		ctx,
		b.IPBinary,
		[]string{"-" + strconv.Itoa(family), "-j", "route", "show", "table", "all"},
		nil,
	)
	if err != nil {
		return nil, errors.New("route_inspection_failed")
	}
	var entries []routeEntry
	if json.Unmarshal(data, &entries) != nil {
		return nil, errors.New("route_inspection_failed")
	}
	return entries, nil
}

func (b *NetworkBackend) removeRoute(ctx context.Context, r dataplane.Route) error {
	exists, err := b.ruleExists(ctx, r)
	if err != nil {
		return err
	}
	if exists {
		args := []string{
			"-" + strconv.Itoa(r.Family),
			"rule",
			"del",
			"priority",
			strconv.Itoa(r.Priority),
			"fwmark",
			fmt.Sprintf("0x%08x/0xffff0000", r.Mark),
			"lookup",
			strconv.Itoa(r.Table),
		}
		if _, err = b.Runner.Run(ctx, b.IPBinary, args, nil); err != nil {
			return errors.New("route_cleanup_failed")
		}
	}
	if r.Table == 254 {
		return nil
	}
	entries, err := b.routeEntries(ctx, r.Family)
	if err != nil {
		return err
	}
	present := false
	for _, entry := range entries {
		if number(entry.Table) == uint64(r.Table) {
			if !routeEntryMatches(entry, r) {
				return errors.New("ownership_conflict: route changed before cleanup")
			}
			present = true
		}
	}
	if !present {
		return nil
	}
	args := []string{"-" + strconv.Itoa(r.Family), "route", "del", "table", strconv.Itoa(r.Table)}
	if r.Local {
		args = append(args, "local")
	}
	args = append(args, "default", "dev", r.Device)
	if _, err = b.Runner.Run(ctx, b.IPBinary, args, nil); err != nil {
		return errors.New("route_cleanup_failed")
	}
	return nil
}

func withLocalAddresses(p dataplane.Plan) (dataplane.Plan, error) {
	addresses, err := localAddresses()
	if err != nil {
		return p, err
	}
	p, err = dataplane.WithIngressDevices(p)
	if err != nil {
		return p, err
	}
	return dataplane.WithRouterAddresses(p, addresses)
}

func localAddresses() ([]netip.Addr, error) {
	all, e := net.InterfaceAddrs()
	if e != nil {
		return nil, errors.New("router_addresses_unavailable")
	}
	addresses := []netip.Addr{}
	for _, address := range all {
		pref, e := netip.ParsePrefix(address.String())
		if e == nil {
			addresses = append(addresses, pref.Addr())
		}
	}
	return addresses, nil
}

// nft 1.0.6 exposes table comments in text output but omits them from JSON.
// Only the exact top-level table comment is authoritative, never a rule comment.
func nftTableOwnedText(data []byte, name string) bool {
	if name != dataplane.Table && name != dataplane.GuardTable && name != dataplane.ProbeTable {
		return false
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
			if len(lines) == 2 {
				break
			}
		}
	}
	return len(lines) == 2 && lines[0] == "table inet "+name+" {" &&
		lines[1] == "comment \""+dataplane.Owner+"\""
}
