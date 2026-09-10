package dataplane

import (
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

func testNetwork() model.Network {
	return model.Network{
		Enabled:       true,
		LANInterfaces: []string{"home_net"},
		WANInterface:  "uplink9",
		LocalPrefixes: []string{"10.44.0.0/24"},
		IPv6:          "block",
		DNS:           "block",
	}
}

func TestBreakExistingIsPrivilegedPostCommitAction(t *testing.T) {
	d := Desired{Network: testNetwork(), Fallback: "closed"}
	ordinary, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	d.BreakExisting = true
	reset, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.NFT != reset.NFT || len(reset.Warnings) != len(ordinary.Warnings)+1 {
		t.Fatal("optional connection tracking reset altered packet selection")
	}
}

func TestUnavailableSourcesNeverAllocateRoutesOrBecomeSelected(t *testing.T) {
	base := Desired{
		Network:     testNetwork(),
		Fallback:    "closed",
		Selected:    "direct",
		Paths:       []Path{{SourceID: "direct", Kind: "direct", Slot: 1}},
		Unavailable: []string{"missing"},
	}
	plan, e := Compile(base)
	if e != nil || len(plan.Warnings) == 0 {
		t.Fatal(plan, e)
	}
	for _, ids := range [][]string{{"direct"}, {"missing", "missing"}, {"invalid name"}} {
		d := base
		d.Unavailable = ids
		if _, e := Compile(d); e == nil {
			t.Fatal("invalid unavailable partition accepted", ids)
		}
	}
	d := base
	d.Selected = "missing"
	if _, e := Compile(d); e == nil {
		t.Fatal("unavailable source selected")
	}
}

func TestPlanPreservesConnectionMarksAndHasFailClosedGuards(t *testing.T) {
	p, e := Build(
		testNetwork(),
		[]Path{
			{SourceID: "one", Kind: "tproxy", Slot: 1, Port: 12001, UDP: true},
			{SourceID: "two", Kind: "tproxy", Slot: 2, Port: 12002, UDP: true},
		},
		"two",
		"closed",
	)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"ct mark & 0xff000000 != 0x4f000000 ct mark set", "0x4f020000", "tproxy to :12001", "tproxy to :12002", "meta nfproto ipv6 drop", "th dport 53 drop", "helper injects current router addresses"} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(p.NFT, "flush ruleset") || strings.Contains(p.NFT, "table inet fw4") ||
		strings.Contains(p.NFT, " bypass") {
		t.Fatal("plan modifies foreign firewall or permits bypass")
	}
	if len(p.Routes) != 2 {
		t.Fatalf("routes %+v", p.Routes)
	}
	if !strings.Contains(p.GuardNFT, "drop") {
		t.Fatal("guard must block during apply")
	}
}

func TestMaliciousNetworkRejected(t *testing.T) {
	for _, name := range []string{"a\"; delete table inet fw4", "../device", "$(reboot)", "a b", "-f", "lo"} {
		n := testNetwork()
		n.LANInterfaces = []string{name}
		if _, e := Build(n, nil, "", "closed"); e == nil {
			t.Errorf("accepted device %q", name)
		}
	}
	n := testNetwork()
	n.LocalPrefixes = []string{"0.0.0.0/0"}
	if _, e := Build(n, nil, "", "closed"); e == nil {
		t.Fatal("accepted global local exception")
	}
}

func TestPacketQueuesNeverBypass(t *testing.T) {
	p, e := Build(
		testNetwork(),
		[]Path{{SourceID: "dpi", Kind: "packet-engine", Slot: 3, UDP: true}},
		"dpi",
		"closed",
	)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(
		p.NFT,
		"0x4f030000 meta mark & 0x0000c000 == 0 meta l4proto { tcp, udp } queue num 21003",
	) {
		t.Fatal(p.NFT)
	}
	if strings.Contains(p.NFT, "bypass") {
		t.Fatal("NFQUEUE must fail closed")
	}
}

func TestUnsupportedDNSRejectedBeforeApply(t *testing.T) {
	n := testNetwork()
	n.DNS = "selected-path"
	if _, e := Build(
		n,
		[]Path{{SourceID: "proxy", Kind: "tproxy", Slot: 1, Port: 14000, UDP: true}},
		"proxy",
		"closed",
	); e == nil {
		t.Fatal("dedicated DNS resolver required")
	}
}

func TestStrictRollbackNeverOpensDirect(t *testing.T) {
	n := testNetwork()
	old := Desired{
		Network:  n,
		Paths:    []Path{{SourceID: "wan", Kind: "direct", Slot: 1}},
		Selected: "wan",
		Fallback: "direct",
	}
	next := Desired{
		Network:  n,
		Paths:    []Path{{SourceID: "proxy", Kind: "tproxy", Slot: 2, Port: 12000, UDP: true}},
		Selected: "proxy",
		Fallback: "closed",
	}
	safe := SafeRollback(next, &old)
	if safe.Selected != "" || safe.Fallback != "closed" || len(safe.Paths) != 0 {
		t.Fatalf("rollback leaks %+v", safe)
	}
	if _, e := Compile(safe); e != nil {
		t.Fatal(e)
	}
}
