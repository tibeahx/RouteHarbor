//go:build linux

package helper

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/dispatch"
)

func TestContinuityBridgeOpensOnlyPrivateInheritedListener(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	file, e := openContinuityBridgeListener(context.Background(), port)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = file.Close() }()
	listener, e := net.FileListener(file)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = listener.Close() }()
	bound, e := netip.ParseAddrPort(listener.Addr().String())
	if e != nil || !bound.Addr().IsLoopback() || int(bound.Port()) != port {
		t.Fatal("bridge escaped loopback", bound, e)
	}
}

func TestContinuityBridgeAndLegacyDescriptorsCoexist(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_CONTINUITY_NET_LAB") != "1" {
		t.Skip("requires isolated Linux transparent socket lab")
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	r := continuityFixture(t)
	r.Bridge = &dispatch.Bridge{
		Port:     port,
		Username: strings.Repeat("ab", 16),
		Password: strings.Repeat("cd", 32),
	}
	files, specs, e := openContinuityListeners(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	if len(files) != 3 || len(specs) != 3 || !specs[0].Bridge || specs[0].DNS ||
		specs[0].Network != "tcp4" ||
		specs[0].FD != 7 {
		t.Fatal("unexpected dual listeners", specs)
	}
	for i, spec := range specs[1:] {
		if spec.Bridge || spec.FD != 8+i {
			t.Fatal("legacy descriptors changed", spec)
		}
	}
}
