package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/probe"
)

// ContinuityDefaults does not add a continuity object to existing configuration.
// Pairing is explicit, and no relay or trust identity is supplied by the product.
func ContinuityDefaults() model.ContinuityConfig {
	return model.ContinuityConfig{
		BufferBytes: 32 << 20, UDPReserveBytes: 4 << 20, DisconnectedGraceSeconds: 30,
	}
}

func validateContinuity(c model.Config) error {
	p := c.Continuity
	if p == nil {
		return nil
	}
	bad := func(field, reason string) error { return fmt.Errorf("continuity.%s: %s", field, reason) }
	if p.BufferBytes < 2<<20 || p.BufferBytes > 64<<20 {
		return bad("buffer_bytes", "must be between 2 and 64 MiB")
	}
	if p.UDPReserveBytes < 512<<10 ||
		p.UDPReserveBytes >= p.BufferBytes-model.ContinuityFixedReserveBytes {
		return bad(
			"udp_reserve_bytes",
			"must be at least 512 KiB and leave more than 512 KiB for worker queues",
		)
	}
	if p.DisconnectedGraceSeconds < 1 || p.DisconnectedGraceSeconds > 300 {
		return bad("disconnected_grace_seconds", "must be between 1 and 300")
	}
	if p.RelayAddress != "" || p.Enabled {
		address, err := netip.ParseAddrPort(p.RelayAddress)
		if err != nil || address.Port() == 0 || !probe.PublicIP(address.Addr()) {
			return bad("relay_address", "must be an explicit public IP literal and port")
		}
	}
	if p.RelayFingerprint != "" || p.Enabled {
		fingerprint, err := hex.DecodeString(p.RelayFingerprint)
		if err != nil || len(fingerprint) != 32 {
			return bad(
				"relay_fingerprint",
				"must be a SHA256 certificate fingerprint with 64 hexadecimal characters",
			)
		}
	}
	if p.Enabled {
		if c.Role != "gateway" {
			return bad("enabled", "requires the gateway role")
		}
		if c.Policy.BreakExisting {
			return bad("enabled", "requires connection tracking reset to be disabled")
		}
		if c.Policy.Fallback != "closed" {
			return bad("enabled", "requires closed fallback")
		}
	}
	return nil
}

// RedactContinuity deliberately enumerates the public configuration fields so
// future additions cannot make a private identity visible in ordinary reads.
func RedactContinuity(c *model.ContinuityConfig) *model.ContinuityConfig {
	if c == nil {
		return nil
	}
	return &model.ContinuityConfig{
		Enabled: c.Enabled, RelayAddress: c.RelayAddress, RelayFingerprint: c.RelayFingerprint,
		BufferBytes: c.BufferBytes, UDPReserveBytes: c.UDPReserveBytes,
		DisconnectedGraceSeconds: c.DisconnectedGraceSeconds,
	}
}
