// Package dispatch generates a fixed sing-box data plane from typed allocations.
// User engine JSON, listeners, paths and commands are never accepted here.
package dispatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/platform"
	"github.com/tibeahx/OpenRHP/internal/routing"
)

const (
	FakeIPv4 = "198.18.0.0/15"
	FakeIPv6 = "fd66:6f70:656e::/48"
	Selector = "bypass"
)

// Bridge credentials travel only in private inherited configuration descriptors.
type Bridge struct {
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Spec struct {
	Allocation adapter.DispatcherAllocation `json:"allocation"`
	Network    model.Network                `json:"network"`
	Routing    model.RoutingConfig          `json:"routing"`
	Sources    []adapter.Path               `json:"sources"`
	Selected   string                       `json:"selected"`
	Continuity *Bridge                      `json:"continuity,omitempty"`
}

type Files struct{ RuleSet, Cache string }

func PolicyHash(r model.RoutingConfig) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Validate(s Spec) error {
	if len(s.Routing.Exceptions) > 4096 || len(s.Routing.Detection.ControlTargetIDs) > 64 ||
		(s.Routing.Registry.Provider != "" && s.Routing.Registry.Provider != "antifilter") {
		return errors.New("invalid_dispatcher_policy")
	}
	for _, rule := range s.Routing.Exceptions {
		if routing.ValidateRule(rule) != nil {
			return errors.New("invalid_dispatcher_rule")
		}
	}
	a, p := s.Allocation, s.Allocation.Path
	if a.FakePool > 1 || s.Routing.Mode != "selective" || s.Routing.FailurePolicy != "direct" ||
		!platform.ValidInterfaceName(
			s.Network.WANInterface,
		) || p.SourceID != adapter.DispatcherSourceID ||
		p.Kind != "dispatcher" || p.Slot < 1 || p.Slot > adapter.MaxActivePaths ||
		p.Mark != adapter.Mark(p.Slot) || !p.UDP || p.IPv6 != (s.Network.IPv6 == "proxy") {
		return errors.New("invalid_dispatcher_intent")
	}
	ip, err := netip.ParseAddr(s.Network.DNSResolver)
	if err != nil || !platform.PublicAddress(ip) {
		return errors.New("invalid_dispatcher_resolver")
	}
	ports := map[int]bool{}
	for _, port := range []int{p.TransparentPort, p.ProxyPort, p.DNSPort, a.DNSFrontPort, a.DirectPort, a.APIPort} {
		if port < 1024 || port > 65535 || ports[port] {
			return errors.New("invalid_dispatcher_ports")
		}
		ports[port] = true
	}
	seen, slots := map[string]bool{}, map[int]bool{p.Slot: true}
	eligible := 0
	for _, source := range s.Sources {
		if source.SourceID == "" || seen[source.SourceID] || source.Slot < 1 || source.Slot > 250 ||
			slots[source.Slot] ||
			source.Mark != adapter.Mark(source.Slot) ||
			source.ProxyURL != nil {
			return errors.New("invalid_dispatcher_source")
		}
		seen[source.SourceID], slots[source.Slot] = true, true
		switch source.Kind {
		case "direct":
			continue
		case "interface":
			if !platform.ValidInterfaceName(source.Interface) {
				return errors.New("invalid_dispatcher_source")
			}
		case "packet-engine":
		case "socks5", "http-connect", "sing-box", "xray":
			if source.ProxyPort < 1024 || source.ProxyPort > 65535 || ports[source.ProxyPort] {
				return errors.New("invalid_dispatcher_source")
			}
		default:
			return errors.New("invalid_dispatcher_source")
		}
		eligible++
	}
	if s.Continuity != nil {
		b := s.Continuity
		if b.Port < 1024 || b.Port > 65535 || ports[b.Port] || len(b.Username) != 32 ||
			len(b.Password) != 64 {
			return errors.New("invalid_dispatcher_bridge")
		}
	} else if eligible == 0 {
		return errors.New("dispatcher_requires_bypass_source")
	}
	if s.Selected != "" && !seen[s.Selected] {
		return errors.New("invalid_dispatcher_selection")
	}
	if s.Continuity == nil {
		for _, source := range s.Sources {
			if source.SourceID == s.Selected && source.Kind == "direct" {
				return errors.New("invalid_dispatcher_selection")
			}
		}
	}
	return nil
}

func matchRule(r model.RoutingRule) map[string]any {
	m := map[string]any{}
	if r.Domain != "" {
		key := "domain"
		if r.IncludeSubdomains {
			key = "domain_suffix"
		}
		m[key] = []string{r.Domain}
	} else {
		m["ip_cidr"] = []string{r.CIDR}
	}
	return m
}

func copyMatch(m map[string]any) map[string]any {
	v := map[string]any{}
	for k, x := range m {
		v[k] = x
	}
	return v
}

// Generate uses a private selector API only behind fixed helper verbs. Global
// mode means bypass unavailable, not "send every connection through a proxy".
func Generate(s Spec, files Files, secret string) ([]byte, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	if files.RuleSet == "" || files.Cache == "" || len(secret) < 32 {
		return nil, errors.New("invalid_dispatcher_files")
	}
	p := s.Allocation.Path
	inbounds := []any{
		map[string]any{
			"type":        "tproxy",
			"tag":         "lan4",
			"listen":      "127.0.0.1",
			"listen_port": p.TransparentPort,
		},
		map[string]any{
			"type":        "direct",
			"tag":         "client-dns",
			"listen":      "127.0.0.1",
			"listen_port": p.DNSPort,
		},
		map[string]any{
			"type":        "socks",
			"tag":         "bypass-check",
			"listen":      "127.0.0.1",
			"listen_port": p.ProxyPort,
		},
		map[string]any{
			"type":        "socks",
			"tag":         "direct-check",
			"listen":      "127.0.0.1",
			"listen_port": s.Allocation.DirectPort,
		},
	}
	if p.IPv6 {
		inbounds = append(
			inbounds,
			map[string]any{
				"type":        "tproxy",
				"tag":         "lan6",
				"listen":      "::1",
				"listen_port": p.TransparentPort,
			},
		)
	}
	outbounds := []any{
		map[string]any{
			"type":            "direct",
			"tag":             "wan",
			"bind_interface":  s.Network.WANInterface,
			"domain_resolver": "real-direct",
		},
	}
	tags := []string{}
	selected := ""
	if s.Continuity != nil {
		b := s.Continuity
		outbounds = append(
			outbounds,
			map[string]any{
				"type":            "socks",
				"tag":             "relay",
				"server":          "127.0.0.1",
				"server_port":     b.Port,
				"version":         "5",
				"username":        b.Username,
				"password":        b.Password,
				"domain_resolver": "real-bypass",
			},
		)
		tags = append(tags, "relay")
		selected = "relay"
	} else {
		for _, src := range s.Sources {
			if src.Kind == "direct" {
				continue
			}
			tag := "source-" + strconv.Itoa(src.Slot)
			tags = append(tags, tag)
			if src.SourceID == s.Selected {
				selected = tag
			}
			o := map[string]any{"tag": tag, "domain_resolver": "real-bypass"}
			if src.ProxyPort != 0 {
				o["type"] = "socks"
				o["server"] = "127.0.0.1"
				o["server_port"] = src.ProxyPort
				o["version"] = "5"
			} else {
				o["type"] = "direct"
				o["routing_mark"] = src.Mark
				if src.Kind == "interface" {
					o["bind_interface"] = src.Interface
				} else {
					o["bind_interface"] = s.Network.WANInterface
				}
			}
			outbounds = append(outbounds, o)
		}
	}
	if selected == "" {
		selected = tags[0]
	}
	outbounds = append(
		outbounds,
		map[string]any{
			"type":                        "selector",
			"tag":                         Selector,
			"outbounds":                   tags,
			"default":                     selected,
			"interrupt_exist_connections": false,
		},
	)
	rules := []any{
		map[string]any{"inbound": []string{"client-dns"}, "action": "hijack-dns"},
		map[string]any{"action": "resolve"},
		map[string]any{"ip_is_private": true, "action": "reject"},
		map[string]any{"inbound": []string{"direct-check"}, "outbound": "wan"},
	}
	appendBypass := func(match map[string]any) {
		closed := copyMatch(match)
		closed["clash_mode"] = "Global"
		closed["action"] = "reject"
		rules = append(rules, closed)
		route := copyMatch(match)
		route["outbound"] = Selector
		rules = append(rules, route)
	}
	appendBypass(map[string]any{"inbound": []string{"bypass-check"}})
	dnsRules := []any{
		map[string]any{
			"inbound":    []string{"client-dns"},
			"query_type": []string{"A", "AAAA"},
			"server":     "fake",
		},
	}
	for _, r := range s.Routing.Exceptions {
		if r.Action != "direct" {
			continue
		}
		m := matchRule(r)
		m["outbound"] = "wan"
		rules = append(rules, m)
		if r.Domain != "" {
			m = matchRule(r)
			m["server"] = "real-direct"
			dnsRules = append(dnsRules, m)
		}
	}
	for _, r := range s.Routing.Exceptions {
		if r.Action != "bypass" {
			continue
		}
		appendBypass(matchRule(r))
		if r.Domain != "" {
			m := matchRule(r)
			m["server"] = "real-bypass"
			dnsRules = append(dnsRules, m)
		}
	}
	appendBypass(map[string]any{"rule_set": []string{"restricted"}})
	dnsRules = append(
		dnsRules,
		map[string]any{"rule_set": []string{"restricted"}, "server": "real-bypass"},
	)
	dns := map[string]any{"servers": []any{
		map[string]any{
			"type":        "fakeip",
			"tag":         "fake",
			"inet4_range": FakePoolIPv4(s.Allocation.FakePool),
			"inet6_range": FakePoolIPv6(s.Allocation.FakePool),
		},
		map[string]any{
			"type":           "tcp",
			"tag":            "real-direct",
			"server":         s.Network.DNSResolver,
			"server_port":    53,
			"bind_interface": s.Network.WANInterface,
		},
		map[string]any{
			"type":        "tcp",
			"tag":         "real-bypass",
			"server":      s.Network.DNSResolver,
			"server_port": 53,
			"detour":      Selector,
		},
	}, "rules": dnsRules, "final": "real-direct"}
	mode := "Rule"
	if s.Selected == "" {
		mode = "Global"
	}
	return json.Marshal(map[string]any{
		"log": map[string]any{
			"disabled": true,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"dns":       dns,
		"route": map[string]any{
			"rules": rules,
			"rule_set": []any{
				map[string]any{
					"type":   "local",
					"tag":    "restricted",
					"format": "source",
					"path":   files.RuleSet,
				},
			},
			"final":                   "wan",
			"default_domain_resolver": "real-direct",
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled":      true,
				"path":         files.Cache,
				"cache_id":     "selective-pool-" + strconv.Itoa(int(s.Allocation.FakePool)),
				"store_fakeip": true,
			},
			"clash_api": map[string]any{
				"external_controller":         "127.0.0.1:" + strconv.Itoa(s.Allocation.APIPort),
				"secret":                      secret,
				"default_mode":                mode,
				"access_control_allow_origin": []string{"http://openrhp.invalid"},
			},
		},
	})
}

// Staged instances use disjoint pools. A durable cache belongs to the pool,
// independent of port/slot allocation, preventing stale FakeIP reassignment
// to another domain when a new configuration is applied or rolled back.
func FakePoolIPv4(pool uint8) string {
	if pool == 1 {
		return "198.19.0.0/16"
	}
	return "198.18.0.0/16"
}

func FakePoolIPv6(pool uint8) string {
	if pool == 1 {
		return "fd66:6f70:656e:8000::/49"
	}
	return "fd66:6f70:656e::/49"
}
