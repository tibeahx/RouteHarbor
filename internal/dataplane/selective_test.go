package dataplane

import (
	"reflect"
	"strings"
	"testing"
)

func selectiveFixture() Desired {
	return Desired{
		Network:  testNetwork(),
		Fallback: "closed",
		Selected: "tunnel",
		Paths: []Path{
			{
				SourceID:  "tunnel",
				Kind:      "interface",
				Slot:      2,
				Interface: "wg9",
				UDP:       true,
				IPv6:      true,
			},
		},
		Selective: &SelectiveIntent{
			Path: Path{
				SourceID: SelectiveSourceID,
				Kind:     "tproxy",
				Slot:     250,
				Port:     12250,
				UDP:      true,
				IPv6:     true,
			},
			DNSFrontPort:  12550,
			FakeIPv4:      DefaultFakeIPv4,
			FakeIPv6:      DefaultFakeIPv6,
			FailurePolicy: "direct",
			PolicyHash:    strings.Repeat("a", 64),
			Snapshot:      SelectiveSnapshotRef{Generation: 1, SHA256: strings.Repeat("a", 64)},
		},
	}
}

func TestSelectiveDispatchPrecedesLocalExceptions(t *testing.T) {
	d := selectiveFixture()
	p, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"th dport 53 redirect to :12550", "th dport 53 ct mark set", "ip daddr 198.18.0.0/15 jump dispatch", "ip6 daddr fd66:6f70:656e::/48 drop", "tproxy ip to 127.0.0.1:12250", "meta mark & 0xffff0000 == 0x4f020000 oifname != \"wg9\" drop"} {
		if !strings.Contains(p.NFT, rule) {
			t.Errorf("missing %s", rule)
		}
	}
	if strings.Index(p.NFT, "198.18.0.0/15 jump") > strings.Index(p.NFT, "helper injects") {
		t.Fatal("synthetic interception after local exceptions")
	}
	if strings.Contains(p.GuardNFT, "th dport 53") ||
		strings.Contains(p.GuardNFT, "chain protect") {
		t.Fatal("emergency policy blocks ordinary traffic or DNS")
	}
	d.Paths = append(
		d.Paths,
		Path{
			SourceID:  "tunnel2",
			Kind:      "interface",
			Slot:      3,
			Interface: "wg10",
			IPv6:      true,
			UDP:       true,
		},
	)
	p1, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Selected = "tunnel2"
	p2, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	if p1.NFT != p2.NFT || !reflect.DeepEqual(p1.Routes, p2.Routes) {
		t.Fatal("bypass selection changed LAN dispatch")
	}
	if _, err := SelectionNFT(p1.Desired, p2.Desired); err == nil {
		t.Fatal("legacy selector used for dispatcher")
	}
}

func TestSelectiveRejectsCollisionsAndDirectBypass(t *testing.T) {
	tests := []func(*Desired){
		func(d *Desired) { d.Network.LocalPrefixes = append(d.Network.LocalPrefixes, "fd66:6f70:656e::/64") },
		func(d *Desired) { d.Paths[0].Slot = 250 },
		func(d *Desired) { d.Selective.DNSFrontPort = d.Selective.Path.Port },
		func(d *Desired) { d.Selective.FakeIPv4 = "10.0.0.0/8" },
		func(d *Desired) { d.Selective.Snapshot.SHA256 = "missing" },
		func(d *Desired) { d.Paths[0] = Path{SourceID: "tunnel", Kind: "direct", Slot: 2} },
		func(d *Desired) { d.Selective.FailurePolicy = "closed" },
	}
	for i, change := range tests {
		d := selectiveFixture()
		change(&d)
		if _, err := Compile(d); err == nil {
			t.Fatalf("invalid intent %d accepted", i)
		}
	}
}

func TestSelectiveEmergencyAndMigration(t *testing.T) {
	d := selectiveFixture()
	s, err := EmergencyDirectNFT(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "tproxy") || strings.Contains(s, "redirect") ||
		!strings.Contains(s, "ip6 daddr fd66:6f70:656e::/48 drop") {
		t.Fatal(s)
	}
	old := Desired{Network: testNetwork(), Fallback: "closed"}
	if !reflect.DeepEqual(SafeRollback(d, &old), old) {
		t.Fatal("failed migration changed legacy semantics")
	}
	safe := SafeRollback(d, nil)
	if safe.Selective != nil || safe.Fallback != "closed" {
		t.Fatal("unconfirmed first apply granted emergency policy")
	}
}
