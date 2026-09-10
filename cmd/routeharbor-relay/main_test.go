package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/continuity"
	"github.com/tibeahx/RouteHarbor/internal/node"
)

func validConfig() relayConfig {
	return relayConfig{
		Listen:             "127.0.0.1:8443",
		ClientFingerprints: []string{strings.Repeat("ab", 32)},
	}
}

func TestConfigRequiresExplicitListenerAndPinnedClients(t *testing.T) {
	for name, change := range map[string]func(*relayConfig){
		"hostname":      func(c *relayConfig) { c.Listen = "relay.example:8443" },
		"wildcard":      func(c *relayConfig) { c.Listen = "0.0.0.0:8443" },
		"missing-port":  func(c *relayConfig) { c.Listen = "127.0.0.1" },
		"zero-port":     func(c *relayConfig) { c.Listen = "127.0.0.1:0" },
		"missing-peers": func(c *relayConfig) { c.ClientFingerprints = nil },
		"bad-pin":       func(c *relayConfig) { c.ClientFingerprints = []string{"PIN-SECRET-CANARY"} },
		"duplicate-pin": func(c *relayConfig) {
			c.ClientFingerprints = append(c.ClientFingerprints, strings.ToUpper(c.ClientFingerprints[0]))
		},
		"unbounded-clients":    func(c *relayConfig) { c.MaxClients = 257 },
		"negative-buffer":      func(c *relayConfig) { c.Limits.BufferBytes = -1 },
		"duration-overflow":    func(c *relayConfig) { c.Limits.DisconnectedGraceSeconds = int(^uint(0) >> 1) },
		"excessive-udp-replay": func(c *relayConfig) { c.Limits.UDPReplayMS = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			change(&c)
			raw, _ := json.Marshal(c)
			if _, err := decodeConfig(raw); err == nil || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("unsafe config accepted or echoed", err)
			}
		})
	}
	c := validConfig()
	c.ClientFingerprints[0] = strings.ToUpper(c.ClientFingerprints[0])
	raw, _ := json.Marshal(c)
	parsed, err := decodeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := parsed.coreLimits()
	if err != nil || limits != continuity.DefaultLimits() {
		t.Fatal("omitted limits must use core defaults", limits, err)
	}
	if parsed.ClientFingerprints[0] != strings.Repeat("ab", 32) {
		t.Fatal("pin not canonicalized")
	}
	for _, raw := range []string{
		`{"listen":"127.0.0.1:8443","listen":"127.0.0.1:8444","client_fingerprints":["` + strings.Repeat("ab", 32) + `"]}`,
		`{"listen":"127.0.0.1:8443","client_fingerprints":["` + strings.Repeat("ab", 32) + `"],"private_key":"PRIVATE-KEY-CANARY"}`,
		`{"listen":"127.0.0.1:8443","client_fingerprints":["` + strings.Repeat("ab", 32) + `"],"limits":{"buffer_bytes":33554432,"buffer_bytes":67108864}}`,
		`{} {}`,
	} {
		if _, err := decodeConfig(
			[]byte(raw),
		); err == nil ||
			strings.Contains(err.Error(), "CANARY") {
			t.Fatal("ambiguous or secret-bearing config accepted", err)
		}
	}
}

func TestConfigPrivateFileAndIdentityOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw, _ := json.Marshal(validConfig())
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("readable config accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(link); err == nil {
		t.Fatal("symlink config accepted")
	}
	state := filepath.Join(dir, "state")
	var first, second bytes.Buffer
	if err := run(
		context.Background(),
		[]string{"identity", "--state", state},
		&first,
	); err != nil {
		t.Fatal(err)
	}
	if err := run(
		context.Background(),
		[]string{"identity", "--state", state},
		&second,
	); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || len(strings.TrimSpace(first.String())) != 64 ||
		strings.Contains(first.String(), "PRIVATE") {
		t.Fatal("identity did not expose only stable public pin")
	}
	info, err := os.Stat(filepath.Join(state, "identity.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("identity permissions", err)
	}
	for _, args := range [][]string{{"identity", "--private-key", "ARGUMENT-CANARY"}, {"identity", "--state", "relative"}, {"serve", "unexpected"}} {
		var out bytes.Buffer
		if err := run(
			context.Background(),
			args,
			&out,
		); err == nil || strings.Contains(err.Error(), "CANARY") ||
			out.Len() != 0 {
			t.Fatal("invalid arguments accepted or echoed", err)
		}
	}
}

type stoppedListener struct {
	once      sync.Once
	closed    chan struct{}
	accepting chan struct{}
}

func (l *stoppedListener) Accept() (net.Conn, error) {
	close(l.accepting)
	<-l.closed
	return nil, net.ErrClosed
}
func (l *stoppedListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

func (*stoppedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443} }

func TestServeClosesListenerOnCancellation(t *testing.T) {
	identity, err := node.LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	listener := &stoppedListener{closed: make(chan struct{}), accepting: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, validConfig(), identity, listener) }()
	select {
	case <-listener.accepting:
	case <-time.After(time.Second):
		t.Fatal("relay did not accept")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay shutdown blocked")
	}
	select {
	case <-listener.closed:
	default:
		t.Fatal("relay listener remains open")
	}
}
