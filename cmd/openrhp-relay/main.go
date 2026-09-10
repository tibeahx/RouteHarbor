// openrhp-relay runs an explicitly paired private relay. It never configures
// host routing, downloads credentials, or prints destinations and key material.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/continuity"
	"github.com/tibeahx/OpenRHP/internal/node"
)

// Durations in the private disk configuration use explicit units. Zero/omitted
// fields use the core's bounded defaults; negative and excessive values fail.
type relayLimits struct {
	BufferBytes              int64 `json:"buffer_bytes,omitempty"`
	UDPReserveBytes          int64 `json:"udp_reserve_bytes,omitempty"`
	FlowBytes                int64 `json:"flow_bytes,omitempty"`
	ControlBytes             int64 `json:"control_bytes,omitempty"`
	MaxTCP                   int   `json:"max_tcp,omitempty"`
	MaxUDP                   int   `json:"max_udp,omitempty"`
	DisconnectedGraceSeconds int   `json:"disconnected_grace_seconds,omitempty"`
	UDPIdleSeconds           int   `json:"udp_idle_seconds,omitempty"`
	UDPReplayMS              int   `json:"udp_replay_ms,omitempty"`
}

type relayConfig struct {
	Listen             string      `json:"listen"`
	ClientFingerprints []string    `json:"client_fingerprints"`
	Limits             relayLimits `json:"limits,omitempty"`
	MaxClients         int         `json:"max_clients,omitempty"`
}

func (c relayConfig) coreLimits() (continuity.Limits, error) {
	l := c.Limits
	// Bound integer-to-duration conversion before handing validation to the core.
	if l.DisconnectedGraceSeconds < 0 || l.DisconnectedGraceSeconds > 300 || l.UDPIdleSeconds < 0 ||
		l.UDPIdleSeconds > 3600 ||
		l.UDPReplayMS < 0 ||
		l.UDPReplayMS > 1000 {
		return continuity.Limits{}, errors.New("invalid_relay_limits")
	}
	return continuity.Limits{
		BufferBytes:       l.BufferBytes,
		UDPReserveBytes:   l.UDPReserveBytes,
		FlowBytes:         l.FlowBytes,
		ControlBytes:      l.ControlBytes,
		MaxTCP:            l.MaxTCP,
		MaxUDP:            l.MaxUDP,
		DisconnectedGrace: time.Duration(l.DisconnectedGraceSeconds) * time.Second,
		UDPIdle:           time.Duration(l.UDPIdleSeconds) * time.Second,
		UDPReplay:         time.Duration(l.UDPReplayMS) * time.Millisecond,
	}.Normalize()
}

func decodeConfig(raw []byte) (relayConfig, error) {
	var c relayConfig
	if err := adapter.StrictDecode(raw, &c); err != nil {
		return c, errors.New("invalid_relay_config")
	}
	address, err := netip.ParseAddrPort(c.Listen)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() ||
		address.Addr().IsMulticast() ||
		address.Addr().Zone() != "" {
		return c, errors.New("relay_listener_requires_explicit_numeric_address_and_port")
	}
	if len(c.ClientFingerprints) < 1 || len(c.ClientFingerprints) > 256 || c.MaxClients < 0 ||
		c.MaxClients > 256 {
		return c, errors.New("invalid_relay_client_allowlist")
	}
	seen := map[string]bool{}
	for i, pin := range c.ClientFingerprints {
		pin = strings.ToLower(pin)
		b, err := hex.DecodeString(pin)
		if err != nil || len(b) != 32 || seen[pin] {
			return c, errors.New("invalid_relay_client_allowlist")
		}
		seen[pin] = true
		c.ClientFingerprints[i] = pin
	}
	if _, err = c.coreLimits(); err != nil {
		return c, errors.New("invalid_relay_limits")
	}
	return c, nil
}

func loadConfig(path string) (relayConfig, error) {
	var empty relayConfig
	if !filepath.IsAbs(path) {
		return empty, errors.New("relay_config_requires_absolute_private_file")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return empty, errors.New("relay_config_unavailable")
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil || !privateConfigFile(before) {
		return empty, errors.New("relay_config_requires_private_regular_file")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, errors.New("relay_config_unavailable")
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil || !privateConfigFile(after) || !os.SameFile(before, after) {
		return empty, errors.New("relay_config_changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return empty, errors.New("relay_config_size_invalid")
	}
	return decodeConfig(raw)
}

func privateConfigFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 1 ||
		info.Size() > 64<<10 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "identity" && args[0] != "serve" {
		return errors.New(
			"usage: openrhp-relay identity|serve --state /private/state [--config /private/config.json]",
		)
	}
	flags := flag.NewFlagSet("openrhp-relay", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	state := flags.String(
		"state",
		"/var/lib/openrhp-relay",
		"private persistent identity directory",
	)
	configPath := ""
	if args[0] == "serve" {
		flags.StringVar(
			&configPath,
			"config",
			"/etc/openrhp-relay/config.json",
			"private relay config file",
		)
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*state) {
		return errors.New("invalid_relay_arguments")
	}
	if args[0] == "identity" {
		identity, err := node.LoadIdentity(*state)
		if err != nil {
			return errors.New("relay_identity_unavailable")
		}
		_, err = fmt.Fprintln(out, identity.Fingerprint)
		return err
	}
	c, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	identity, err := node.LoadIdentity(*state)
	if err != nil {
		return errors.New("relay_identity_unavailable")
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errors.New("relay_listener_unavailable")
	}
	defer func() { _ = listener.Close() }()
	return serve(ctx, c, identity, listener)
}

func serve(
	ctx context.Context,
	c relayConfig,
	identity node.Identity,
	listener net.Listener,
) error {
	tlsConfig, err := continuity.ServerTLS(identity.Certificate, c.ClientFingerprints)
	if err != nil {
		return errors.New("relay_identity_policy_invalid")
	}
	limits, err := c.coreLimits()
	if err != nil {
		return errors.New("invalid_relay_limits")
	}
	relay, err := continuity.NewRelay(
		continuity.RelayConfig{TLSConfig: tlsConfig, Limits: limits, MaxClients: c.MaxClients},
	)
	if err != nil {
		return errors.New("relay_initialization_failed")
	}
	defer func() { _ = relay.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = relay.Close() })
	defer stop()
	err = relay.Serve(listener)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return errors.New("relay_stopped")
	}
	return nil
}
