package dataplane

import (
	"strings"
	"testing"
)

func TestSelectionOnlyChangesNewConnectionClassifier(t *testing.T) {
	n := testNetwork()
	n.DNS, n.DNSResolver = "selected-path", "8.8.8.8"
	d := Desired{Network: n, Fallback: "closed", Selected: "proxy", Paths: []Path{
		{SourceID: "proxy", Kind: "tproxy", Slot: 1, Port: 12001, DNSPort: 14001, UDP: true},
		{SourceID: "second", Kind: "tproxy", Slot: 2, Port: 12002, DNSPort: 14002, UDP: true},
		{SourceID: "native", Kind: "interface", Slot: 3, Interface: "tun3", UDP: true},
		{SourceID: "wan", Kind: "direct", Slot: 4, UDP: true},
	}}
	for _, dns := range []string{"block", "selected-path"} {
		d.Network.DNS = dns
		before, err := Compile(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, selected := range []string{"second", "native", "wan", ""} {
			next := d
			next.Selected = selected
			after, err := Compile(next)
			if err != nil {
				t.Fatal(err)
			}
			oldBody := strings.Replace(before.NFT, selectionRules(d), "", 1)
			newBody := after.NFT
			if rule := selectionRules(next); rule != "" {
				newBody = strings.Replace(newBody, rule, "", 1)
			}
			if oldBody != newBody {
				t.Fatalf("%s -> %s changed dispatch/guards", dns, selected)
			}
			batch, err := SelectionNFT(d, next)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(batch, "table inet") || strings.Contains(batch, "guard") ||
				strings.Count(batch, "flush chain") != 1 {
				t.Fatal("selection rewrites topology", batch)
			}
		}
	}
}

func TestDNSClassificationPrecedesNATAndRetainsEveryOwner(t *testing.T) {
	n := testNetwork()
	n.DNS, n.DNSResolver = "selected-path", "8.8.8.8"
	p, err := Build(n, []Path{
		{SourceID: "old", Kind: "tproxy", Slot: 1, Port: 12001, DNSPort: 14001, UDP: true},
		{SourceID: "new", Kind: "tproxy", Slot: 2, Port: 12002, DNSPort: 14002, UDP: true},
		{SourceID: "native", Kind: "direct", Slot: 3, UDP: true},
	}, "new", "closed")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		"priority -156; policy accept; iifname { \"home_net\" } meta l4proto { tcp, udp } th dport 53 jump select_flow",
		"priority -155",
		"ct mark & 0xffff0000 == 0x4f010000 meta l4proto { tcp, udp } th dport 53 meta mark set (meta mark & 0x0000ffff) | 0x4f010000 tproxy to :14001 accept",
		"ct mark & 0xffff0000 == 0x4f020000 meta l4proto { tcp, udp } th dport 53 meta mark set (meta mark & 0x0000ffff) | 0x4f020000 tproxy to :14002 accept",
		"ct mark & 0xffff0000 == 0x4f030000 meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 dnat ip to 8.8.8.8",
	} {
		if !strings.Contains(p.NFT, rule) {
			t.Fatalf("missing DNS affinity rule %q", rule)
		}
	}
	if strings.Index(
		p.NFT,
		"tproxy to :14001",
	) > strings.Index(
		p.NFT,
		"helper injects current router addresses",
	) {
		t.Fatal("router DNS address escaped owner interception")
	}
}

func TestSelectionRefusesTopologyPolicyAndFlowResetChanges(t *testing.T) {
	d := Desired{
		Network:  testNetwork(),
		Fallback: "closed",
		Selected: "wan",
		Paths:    []Path{{SourceID: "wan", Kind: "direct", Slot: 1}},
	}
	for _, mutate := range []func(*Desired){
		func(d *Desired) { d.BreakExisting = true },
		func(d *Desired) { d.Fallback = "direct" },
		func(d *Desired) { d.Network.DNS = "selected-path"; d.Network.DNSResolver = "8.8.8.8" },
		func(d *Desired) { d.Paths = []Path{{SourceID: "wan", Kind: "direct", Slot: 2}} },
		func(d *Desired) { d.Unavailable = []string{"missing"} },
	} {
		next := d
		mutate(&next)
		if _, err := SelectionNFT(d, next); err == nil {
			t.Fatal("unsafe selection accepted", next)
		}
	}
}
