//go:build linux

package helper

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func TestLinuxEarlyBootGuardBeforeNetworkDevices(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("OPENRHP_EARLY_GUARD_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(
			"/usr/bin/unshare",
			"--net",
			binary,
			"-test.run=^TestLinuxEarlyBootGuardBeforeNetworkDevices$",
			"-test.v",
		)
		cmd.Env = append(os.Environ(), "OPENRHP_EARLY_GUARD_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("early network namespace: %v\n%s", err, out)
		}
		return
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil || len(addresses) != 0 {
		t.Fatal("fixture already has addresses", addresses, err)
	}
	b := labBackend()
	m := testManager(t, b, nil)
	d := testDesired()
	if err = m.locked(func(s *State) error { s.Committed = &d; return m.save(s) }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = m.BootGuard(context.Background()); err != nil {
			t.Fatalf("early guard replay %d: %v", i, err)
		}
	}
	if _, err = withLocalAddresses(dataplane.Plan{}); err == nil {
		t.Fatal("ordinary apply discovery became permissive")
	}
	labCommand(t, "/sbin/ip", "link", "add", "home0", "type", "dummy")
	labCommand(t, "/sbin/ip", "link", "set", "home0", "up")
	labCommand(t, "/sbin/ip", "address", "add", "10.44.0.1/24", "dev", "home0")
	labCommand(t, "/sbin/ip", "-6", "address", "add", "fd44:1::1/64", "dev", "home0")
	labCommand(t, "/sbin/ip", "link", "add", "outside0", "type", "dummy")
	labCommand(t, "/sbin/ip", "link", "set", "outside0", "up")
	labCommand(t, "/sbin/ip", "route", "add", "default", "dev", "outside0")
	labCommand(t, "/sbin/ip", "-6", "route", "add", "default", "dev", "outside0")
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	for _, route := range [][]string{{"-4", "route", "get", "8.8.8.8", "from", "10.44.0.2", "iif", "home0"}, {"-6", "route", "get", "2001:4860:4860::8888", "from", "fd44:1::2", "iif", "home0"}} {
		if out, err := exec.Command("/sbin/ip", route...).CombinedOutput(); err == nil {
			t.Fatalf("early guard lost protection after device creation/nft flush: %s", out)
		}
	}
	local := labCommand(
		t,
		"/sbin/ip",
		"-4",
		"route",
		"get",
		"10.44.0.1",
		"from",
		"10.44.0.2",
		"iif",
		"home0",
	)
	if !strings.Contains(string(local), "local") {
		t.Fatal("router management was not retained", string(local))
	}
}
