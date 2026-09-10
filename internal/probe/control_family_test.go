package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/adapter"
)

func TestControlTLSRequiresHealthyDirectCandidateFamilies(t *testing.T) {
	runner, server := testRunner(t, http.NotFoundHandler())
	runner.Resolver = fixedResolver{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	path := adapter.Path{Kind: "direct", SourceID: "direct"}
	ipv6Up := false
	runner.DialProbe = comparativeDial(
		func(ctx context.Context, source, address string) (net.Conn, error) {
			if strings.HasPrefix(address, "[") && !ipv6Up {
				return nil, errors.New("IPv6 WAN unavailable")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
	)
	if _, err := runner.ControlTLSForFamilies(
		context.Background(),
		target(),
		path,
		defaultSettings(),
		true,
		false,
	); err != nil {
		t.Fatal("working IPv4 must qualify IPv4 control", err)
	}
	if _, err := runner.ControlTLSForFamilies(
		context.Background(),
		target(),
		path,
		defaultSettings(),
		false,
		true,
	); err == nil {
		t.Fatal("IPv4 success disguised IPv6 outage")
	}
	if _, err := runner.ControlTLSForFamilies(
		context.Background(),
		target(),
		path,
		defaultSettings(),
		true,
		true,
	); err == nil {
		t.Fatal("dual-family control accepted incomplete WAN")
	}
	ipv6Up = true
	if _, err := runner.ControlTLSForFamilies(
		context.Background(),
		target(),
		path,
		defaultSettings(),
		true,
		true,
	); err != nil {
		t.Fatal("working dual-family WAN rejected", err)
	}
	runner.Resolver = fixedResolver{netip.MustParseAddr("93.184.216.34")}
	if _, err := runner.ControlTLSForFamilies(
		context.Background(),
		target(),
		path,
		defaultSettings(),
		false,
		true,
	); err == nil {
		t.Fatal("IPv4-only control proved unavailable IPv6 family")
	}
}
