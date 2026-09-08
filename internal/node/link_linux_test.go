//go:build linux

package node

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLinuxVethNodeLinkTelemetry(t *testing.T) {
	if os.Getenv("OPENRHP_NODE_LINK_LAB") != "1" {
		t.Skip("requires the explicitly isolated Linux veth lab")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run := func(name string, args ...string) {
		t.Helper()
		if output, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
			t.Fatalf("lab command failed: %v %s", err, output)
		}
	}
	run("ip", "link", "add", "orhp-link0", "type", "veth", "peer", "name", "orhp-link1")
	defer func() {
		if err := exec.Command("ip", "link", "del", "orhp-link0").Run(); err != nil {
			t.Errorf("veth cleanup failed: %v", err)
		}
	}()
	run("ip", "link", "set", "orhp-link0", "up")
	run("ip", "link", "set", "orhp-link1", "up")
	b := &UCIBackend{}
	p := Plan{Mode: "ethernet", Uplink: "orhp-link0"}
	before, err := b.ReadLink(ctx, p)
	if err != nil || !before.Available || before.Carrier == nil || !*before.Carrier ||
		before.TXBytes == nil ||
		before.RXBytes == nil ||
		before.TXErrors == nil ||
		before.RXDropped == nil ||
		before.SignalDBM != nil {
		t.Fatalf("real veth observations missing: %+v %v", before, err)
	}
	run(
		"python3",
		"-c",
		"import socket; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(('orhp-link0',0)); s.send(bytes.fromhex('ffffffffffff02000000000188b5') + b'OpenRHP isolated link telemetry frame'.ljust(64,b' ')); s.close()",
	)
	after, err := b.ReadLink(ctx, p)
	if err != nil || after.TXBytes == nil || *after.TXBytes <= *before.TXBytes {
		t.Fatal("real transmitted Ethernet frame did not increase observed TX bytes")
	}
	run("ip", "link", "set", "orhp-link1", "down")
	down, err := b.ReadLink(ctx, p)
	if err != nil || down.Carrier == nil || *down.Carrier {
		t.Fatal("real peer link-down did not appear as carrier false")
	}
	t.Log(
		"Real Linux veth: carrier up/down and transmitted-frame counters passed; no WAN or Wi-Fi throughput claim.",
	)
}
