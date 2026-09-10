package helper

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/routing"
)

// DNS children receive no engine API token, source credentials or routing rules.
type dnsFrontConfig struct {
	Port          int      `json:"port"`
	UpstreamPort  int      `json:"upstream_port"`
	LocalPrefixes []string `json:"local_prefixes"`
}

func (c dnsFrontConfig) valid() bool {
	return c.Port >= 1024 && c.Port <= 65535 && c.UpstreamPort >= 1024 && c.UpstreamPort <= 65535 &&
		c.Port != c.UpstreamPort &&
		len(c.LocalPrefixes) <= 1024
}

// RunDispatcherDNS is the sole unprivileged helper entry point. It has no network
// mutation or executable capability and receives only a private inherited spec.
func RunDispatcherDNS() error {
	if os.Geteuid() == 0 {
		return errors.New("dispatcher_dns_requires_unprivileged_identity")
	}
	input := os.NewFile(3, "dns-config")
	ready := os.NewFile(4, "dns-ready")
	events := os.NewFile(5, "dns-observations")
	if input == nil || ready == nil || events == nil {
		return errors.New("dispatcher_dns_descriptors_missing")
	}
	defer func() { _ = input.Close() }()
	defer func() { _ = ready.Close() }()
	defer func() { _ = events.Close() }()
	raw, e := io.ReadAll(io.LimitReader(input, MaxRequestBytes+1))
	if e != nil {
		return errors.New("dispatcher_dns_config_invalid")
	}
	var req dnsFrontConfig
	if DecodeStrict(raw, &req) != nil || !req.valid() {
		return errors.New("dispatcher_dns_config_invalid")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	for _, s := range req.LocalPrefixes {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return errors.New("dispatcher_dns_prefix_invalid")
		}
		prefixes = append(prefixes, p)
	}
	queue := make(chan string, 256)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case name := <-queue:
				_ = events.SetWriteDeadline(time.Now().Add(time.Second))
				if _, e := io.WriteString(events, name+"\n"); e != nil {
					return
				}
			}
		}
	}()
	p := &routing.DNSProxy{
		LocalDNS: "127.0.0.1:53",
		ExternalDNS: net.JoinHostPort(
			"127.0.0.1",
			strconv.Itoa(req.UpstreamPort),
		),
		AllowedClients: prefixes,
		Observe: func(name string) {
			select {
			case queue <- name:
			default:
			}
		},
		MaxConcurrent: 64,
		Timeout:       5 * time.Second,
	}
	address := net.JoinHostPort("", strconv.Itoa(req.Port))
	listener, e := net.Listen("tcp", address)
	if e != nil {
		return errors.New("dispatcher_dns_bind_failed")
	}
	defer func() { _ = listener.Close() }()
	packet, e := net.ListenPacket("udp", address)
	if e != nil {
		return errors.New("dispatcher_dns_bind_failed")
	}
	defer func() { _ = packet.Close() }()
	if _, e = io.WriteString(ready, "ready\n"); e != nil {
		return errors.New("dispatcher_owner_disconnected")
	}
	_ = ready.Close()
	return p.Serve(ctx, packet, listener)
}
