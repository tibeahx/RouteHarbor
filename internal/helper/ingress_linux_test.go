//go:build linux

package helper

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

func TestLinuxBridgeIngressGuard(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("ROUTEHARBOR_INGRESS_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(
			"/usr/bin/unshare",
			"--net",
			"--mount",
			binary,
			"-test.run=^TestLinuxBridgeIngressGuard$",
			"-test.v",
		)
		cmd.Env = append(os.Environ(), "ROUTEHARBOR_INGRESS_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("namespace: %v\n%s", err, out)
		}
		return
	}
	labCommand(t, "/usr/bin/mount", "-t", "sysfs", "sysfs", "/sys")
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "home0", "type", "bridge"},
		{"link", "add", "port0", "type", "dummy"},
		{"link", "set", "port0", "master", "home0"},
		{"link", "set", "port0", "up"},
		{"link", "set", "home0", "up"},
		{"address", "add", "10.44.0.1/24", "dev", "home0"},
		{"link", "add", "outside0", "type", "dummy"},
		{"link", "set", "outside0", "up"},
		{"address", "add", "198.18.0.2/24", "dev", "outside0"},
		{"route", "add", "default", "dev", "outside0"},
	} {
		labCommand(t, "/sbin/ip", args...)
	}
	b := labBackend()
	b.Ingress = discoverIngress
	m := testManager(t, b, &testWatchdog{})
	d := testDesired()
	d.Selected = ""
	transaction, err := m.Prepare(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	state, err := m.Status()
	if err != nil || !slices.Equal(state.Ingress, []string{"port0"}) {
		t.Fatal("ingress not durably discovered", state, err)
	}
	if _, err = m.Apply(context.Background(), transaction.ID, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(transaction.ID); err != nil {
		t.Fatal(err)
	}
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	labCommand(t, "/sbin/ip", "link", "set", "port0", "nomaster")
	labCommand(t, "/sbin/ip", "link", "delete", "home0")
	args := []string{"-4", "route", "get", "8.8.8.8", "from", "10.44.0.20", "iif", "port0"}
	if out, err := exec.Command("/sbin/ip", args...).CombinedOutput(); err == nil {
		t.Fatalf("detached ingress escaped after nft flush: %s", out)
	}
	if err := m.BootGuard(context.Background()); err != nil {
		t.Fatal("recovery with missing bridge", err)
	}
	// Guard ownership stays explicit; a new bridge membership cannot silently
	// reassign a previously confirmed ingress name/priority.
	if _, err := m.Prepare(context.Background(), d); err == nil {
		t.Fatal("changed ingress membership accepted")
	}
}
