package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func pairedContinuity() model.ContinuityConfig {
	p := ContinuityDefaults()
	p.Enabled = true
	p.RelayAddress = "8.8.8.8:443"
	p.RelayFingerprint = strings.Repeat("ab", 32)
	return p
}

func TestContinuityOptionalCompatibilityAndDetachedReads(t *testing.T) {
	c := Defaults()
	before, _ := json.Marshal(c)
	decoded, err := Decode(before)
	if err != nil || decoded.Continuity != nil {
		t.Fatal("old configuration acquired continuity", err)
	}
	after, _ := json.Marshal(decoded)
	if string(before) != string(after) || strings.Contains(string(after), "continuity") {
		t.Fatal("old configuration serialization changed")
	}
	p := pairedContinuity()
	c.Continuity = &p
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	public := Redact(c)
	public.Continuity.RelayFingerprint = "changed"
	if c.Continuity.RelayFingerprint != strings.Repeat("ab", 32) {
		t.Fatal("public read shares private configuration memory")
	}
}

func TestContinuityRejectsUnsafePairingAndConflictingPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*model.Config){
		"hostname":          func(c *model.Config) { c.Continuity.RelayAddress = "relay.example:443" },
		"loopback":          func(c *model.Config) { c.Continuity.RelayAddress = "127.0.0.1:443" },
		"private":           func(c *model.Config) { c.Continuity.RelayAddress = "192.168.1.1:443" },
		"mapped-private":    func(c *model.Config) { c.Continuity.RelayAddress = "[::ffff:192.168.1.1]:443" },
		"missing-port":      func(c *model.Config) { c.Continuity.RelayAddress = "8.8.8.8" },
		"zero-port":         func(c *model.Config) { c.Continuity.RelayAddress = "8.8.8.8:0" },
		"missing-pin":       func(c *model.Config) { c.Continuity.RelayFingerprint = "" },
		"bad-pin":           func(c *model.Config) { c.Continuity.RelayFingerprint = strings.Repeat("gg", 32) },
		"unbounded-buffer":  func(c *model.Config) { c.Continuity.BufferBytes = 1 << 40 },
		"no-tcp-budget":     func(c *model.Config) { c.Continuity.UDPReserveBytes = c.Continuity.BufferBytes },
		"no-worker-budget":  func(c *model.Config) { c.Continuity.UDPReserveBytes = c.Continuity.BufferBytes - (256 << 10) },
		"no-udp-budget":     func(c *model.Config) { c.Continuity.UDPReserveBytes = 0 },
		"unbounded-grace":   func(c *model.Config) { c.Continuity.DisconnectedGraceSeconds = 301 },
		"reset-connections": func(c *model.Config) { c.Policy.BreakExisting = true },
		"direct-fallback":   func(c *model.Config) { c.Policy.Fallback = "direct" },
		"node":              func(c *model.Config) { c.Role = "node" },
	} {
		t.Run(name, func(t *testing.T) {
			c := Defaults()
			p := pairedContinuity()
			c.Continuity = &p
			mutate(&c)
			if err := Validate(c); err == nil || !strings.HasPrefix(err.Error(), "continuity.") {
				t.Fatal("unsafe continuity accepted", err)
			}
		})
	}
	c := Defaults()
	p := pairedContinuity()
	p.RelayAddress = "[2606:4700:4700::1111]:443"
	c.Continuity = &p
	if err := Validate(c); err != nil {
		t.Fatal("public IPv6 pairing rejected", err)
	}
	p.Enabled = false
	p.RelayAddress, p.RelayFingerprint = "", ""
	c.Policy.BreakExisting = true
	c.Policy.Fallback = "direct"
	if err := Validate(c); err != nil {
		t.Fatal("disabled feature changed legacy policy", err)
	}
}

func TestContinuityRejectsPrivateIdentityFields(t *testing.T) {
	c := Defaults()
	p := pairedContinuity()
	c.Continuity = &p
	b, _ := json.Marshal(c)
	for _, field := range []string{"private_key", "certificate", "token"} {
		bad := strings.Replace(
			string(b),
			`"continuity":{`,
			`"continuity":{"`+field+`":"private-material",`,
			1,
		)
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatal("private identity accepted in normal config", field)
		}
	}
}

func TestContinuityVirtualSourceIDIsReservedInAllModes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		c := Defaults()
		c.Sources = []model.Source{
			{
				ID:       "__continuity",
				Name:     "Collision",
				Type:     "direct",
				Settings: json.RawMessage(`{}`),
			},
		}
		if enabled {
			p := pairedContinuity()
			c.Continuity = &p
		}
		if err := Validate(c); err == nil {
			t.Fatal("virtual allocation identifier accepted as user source", enabled)
		}
	}
}
