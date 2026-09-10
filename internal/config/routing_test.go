package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func TestRoutingNewDefaultsAndLegacyDecode(t *testing.T) {
	c := Defaults()
	if !model.SelectiveRouting(c) || c.Network.Enabled || c.Routing.Detection.Enabled {
		t.Fatal("new defaults must be selective but inactive, without unsolicited probes")
	}
	c.Routing = nil
	raw, _ := json.Marshal(c)
	old, err := Decode(raw)
	if err != nil || old.Routing != nil {
		t.Fatal("legacy semantics changed", err)
	}
}

func TestRoutingValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Config)
	}{
		{"implicit control", func(c *model.Config) { c.Routing.Detection.Enabled = true }},
		{
			"unknown control",
			func(c *model.Config) { c.Routing.Detection.ControlTargetIDs = []string{"missing"} },
		},
		{
			"excess controls",
			func(c *model.Config) { c.Routing.Detection.ControlTargetIDs = make([]string, 65) },
		},
		{"direct fallback", func(c *model.Config) { c.Policy.Fallback = "direct" }},
		{"break ordinary connections", func(c *model.Config) { c.Policy.BreakExisting = true }},
		{"control on different port", func(c *model.Config) {
			c.Targets = []model.Target{
				{
					ID:          "control",
					URL:         "https://example.org:8443",
					StatusCodes: []int{200},
					MaxBytes:    1024,
				},
			}
			c.Routing.Detection.ControlTargetIDs = []string{"control"}
		}},
		{
			"unsafe provider",
			func(c *model.Config) { c.Routing.Registry.Provider = "https://private.example" },
		},
		{"ambiguous rule", func(c *model.Config) {
			c.Routing.Exceptions = []model.RoutingRule{
				{Action: "bypass", Domain: "example.org", CIDR: "8.8.8.0/24"},
			}
		}},
		{"wildcard syntax", func(c *model.Config) {
			c.Routing.Exceptions = []model.RoutingRule{{Action: "bypass", Domain: "*.example.org"}}
		}},
		{"private prefix", func(c *model.Config) {
			c.Routing.Exceptions = []model.RoutingRule{{Action: "bypass", CIDR: "192.168.0.0/16"}}
		}},
		{"broad public-base prefix", func(c *model.Config) {
			c.Routing.Exceptions = []model.RoutingRule{{Action: "bypass", CIDR: "8.0.0.0/5"}}
		}},
		{"noncanonical prefix", func(c *model.Config) {
			c.Routing.Exceptions = []model.RoutingRule{{Action: "bypass", CIDR: "8.8.8.1/24"}}
		}},
		{"duplicate", func(c *model.Config) {
			r := model.RoutingRule{Action: "direct", Domain: "example.org"}
			c.Routing.Exceptions = []model.RoutingRule{r, r}
		}},
		{"no emergency consent", func(c *model.Config) { c.Routing.FailurePolicy = "closed" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Defaults()
			tt.mutate(&c)
			if Validate(c) == nil {
				t.Fatal("accepted invalid routing")
			}
		})
	}
	c := Defaults()
	c.Targets = []model.Target{
		{ID: "control", URL: "https://example.org", StatusCodes: []int{200}, MaxBytes: 1024},
	}
	c.Routing.Detection.Enabled = true
	c.Routing.Detection.ControlTargetIDs = []string{"control"}
	c.Routing.Exceptions = []model.RoutingRule{
		{Action: "bypass", Domain: "example.org", IncludeSubdomains: true},
		{Action: "direct", CIDR: "8.8.8.0/24"},
		{Action: "direct", CIDR: "1.1.1.1"},
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	out := RedactRouting(c.Routing)
	out.Exceptions[0].Domain = "other.example"
	out.Detection.ControlTargetIDs[0] = "other"
	if c.Routing.Exceptions[0].Domain != "example.org" ||
		c.Routing.Detection.ControlTargetIDs[0] != "control" {
		t.Fatal("redacted settings alias private config")
	}
}

func TestRoutingDomainRejectsURLsIPsLocalAndAmbiguousNames(t *testing.T) {
	for _, v := range []string{"", "example", "https://example.org", "example.org.", "EXAMPLE.org", "8.8.8.8", "x.local", "x.lan", "home.arpa", "1.0.0.127.in-addr.arpa", "x.home.arpa", "-x.example", "x..example", strings.Repeat("a", 64) + ".example", "x.example/path", "x.example\n"} {
		if ValidRoutingDomain(v) {
			t.Fatalf("accepted %q", v)
		}
	}
	for _, v := range []string{"example.org", "sub.example.org", "xn--e1afmkfd.xn--p1ai"} {
		if !ValidRoutingDomain(v) {
			t.Fatalf("rejected %q", v)
		}
	}
}

func TestSelectiveRoutingDirectIsOnlyRelayCarrier(t *testing.T) {
	c := Defaults()
	c.Sources = []model.Source{
		{
			ID:       "wan",
			Name:     "Direct WAN",
			Type:     "direct",
			Enabled:  true,
			Auto:     true,
			Settings: json.RawMessage(`{}`),
		},
	}
	c.Targets = []model.Target{
		{ID: "control", URL: "https://example.org", StatusCodes: []int{200}, MaxBytes: 1024},
	}
	c.Policy.Mode = "manual"
	c.Policy.Pinned = "wan"
	if err := Validate(c); err == nil {
		t.Fatal("direct destination exit accepted as bypass")
	}
	legacy := c
	legacy.Routing = nil
	if err := Validate(legacy); err != nil {
		t.Fatal("legacy direct source rejected", err)
	}
	relay := pairedContinuity()
	c.Continuity = &relay
	if err := Validate(c); err != nil {
		t.Fatal("direct carrier to configured relay rejected", err)
	}
}
