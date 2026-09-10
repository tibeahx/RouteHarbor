package dispatch

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/model"
)

func dispatcherFixture(ipv6 bool, kind string) Spec {
	p := adapter.AllocatePath(adapter.DispatcherSourceID, "dispatcher", 250)
	p.TransparentPort, p.ProxyPort, p.DNSPort, p.IPv6, p.UDP = 11250, 12250, 13250, ipv6, true
	source := adapter.AllocatePath("restricted-egress", kind, 4)
	source.IPv6, source.UDP = ipv6, true
	source.TransparentPort, source.DNSPort, source.ProxyPort = 0, 0, 0
	if kind == "interface" {
		source.Interface = "vpn0"
	} else if kind != "packet-engine" && kind != "direct" {
		source.ProxyPort = 12004
	}
	mode := "block"
	if ipv6 {
		mode = "proxy"
	}
	return Spec{
		Allocation: adapter.DispatcherAllocation{
			Path:         p,
			DNSFrontPort: 14250,
			DirectPort:   15250,
			APIPort:      16250,
		},
		Network: model.Network{
			Enabled:       true,
			LANInterfaces: []string{"lan0"},
			WANInterface:  "wan0",
			LocalPrefixes: []string{"10.77.0.0/24"},
			IPv6:          mode,
			DNS:           "selected-path",
			DNSResolver:   "11.0.0.53",
		},
		Routing: model.RoutingConfig{
			Mode:          "selective",
			FailurePolicy: "direct",
			Registry:      model.RoutingRegistry{Provider: "antifilter", Enabled: true},
		},
		Sources:  []adapter.Path{source},
		Selected: source.SourceID,
	}
}

func TestDispatcherTypedGenerationAndDirectIsolation(t *testing.T) {
	for _, kind := range []string{"interface", "packet-engine", "socks5", "http-connect", "sing-box", "xray"} {
		for _, ipv6 := range []bool{false, true} {
			s := dispatcherFixture(ipv6, kind)
			raw, err := Generate(
				s,
				Files{RuleSet: "/private/rules.json", Cache: "/private/cache.db"},
				strings.Repeat("a", 32),
			)
			if err != nil {
				t.Fatal(kind, ipv6, err)
			}
			var cfg struct {
				Route struct {
					Final string `json:"final"`
				} `json:"route"`
				Outbounds []map[string]any `json:"outbounds"`
			}
			if err = json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Route.Final != "wan" {
				t.Fatal("ordinary destinations do not default direct")
			}
			for _, out := range cfg.Outbounds {
				if out["type"] == "selector" {
					for _, tag := range out["outbounds"].([]any) {
						if tag == "wan" {
							t.Fatal("direct entered bypass selector")
						}
					}
				}
			}
		}
	}
}

func TestDispatcherRejectsInvalidTypedInputs(t *testing.T) {
	for _, change := range []func(*Spec){func(s *Spec) { s.Selected = "absent" }, func(s *Spec) { s.Allocation.DNSFrontPort = s.Allocation.Path.TransparentPort }, func(s *Spec) { s.Network.DNSResolver = "127.0.0.1" }, func(s *Spec) { s.Sources[0].Mark = 0 }, func(s *Spec) { s.Sources[0].Kind = "arbitrary-script" }} {
		s := dispatcherFixture(true, "interface")
		change(&s)
		if _, err := Generate(
			s,
			Files{RuleSet: "/rules", Cache: "/cache"},
			strings.Repeat("a", 32),
		); err == nil {
			t.Fatal("untyped allocation accepted")
		}
	}
}
