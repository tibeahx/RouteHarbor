// Package config validates the public schema and stores private configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/model"
	"github.com/tibeahx/OpenRHP/internal/probe"
)

const MaxConfigBytes = 1 << 20

var (
	identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	ifaceName  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$`)
)

func Defaults() model.Config {
	return model.Config{
		SchemaVersion: model.SchemaVersion,
		Revision:      1,
		Role:          "gateway",
		Sources:       []model.Source{},
		Targets:       []model.Target{},
		Policy: model.Policy{
			Mode: "off", Fallback: "closed", ImprovementPercent: 20,
			Confirmations: 3, FailureConfirmations: 3, RecoveryConfirmations: 3,
			MinDwellSeconds: 60, CooldownSeconds: 60, StaleAfterSeconds: 90,
		},
		Probes: model.ProbeSettings{
			ActiveIntervalSeconds: 10, OtherIntervalSeconds: 30,
			SpeedIntervalSeconds: 300, TimeoutSeconds: 8, Concurrency: 2, HistoryLimit: 32,
		},
		Network: model.Network{
			IPv6:          "block",
			DNS:           "block",
			LANInterfaces: []string{},
			LocalPrefixes: []string{},
		},
	}
}

// Decode accepts one complete schema-1 document. No speculative migrations are
// performed: a newer schema must never silently acquire older semantics.
func Decode(data []byte) (model.Config, error) {
	if len(data) > MaxConfigBytes {
		return model.Config{}, errors.New("configuration exceeds byte limit")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return model.Config{}, err
	}
	var c model.Config
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return model.Config{}, errors.New("invalid configuration document or unknown field")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return model.Config{}, errors.New("configuration must contain exactly one JSON object")
	}
	if err := Validate(c); err != nil {
		return model.Config{}, err
	}
	return c, nil
}

// Migrate is the explicit schema boundary, currently accepting only schema 1.
func Migrate(data []byte) (model.Config, error) {
	return Decode(data)
}

func Validate(c model.Config) error {
	bad := func(field, detail string) error { return fmt.Errorf("%s: %s", field, detail) }
	encoded, encodeErr := json.Marshal(c)
	if encodeErr != nil || len(encoded) > MaxConfigBytes {
		return bad("configuration", "invalid JSON or exceeds byte limit")
	}
	if c.SchemaVersion != model.SchemaVersion {
		return bad("schema_version", "unsupported schema version")
	}
	if c.Revision == 0 {
		return bad("revision", "must be positive")
	}
	if c.Role != "gateway" && c.Role != "node" {
		return bad("role", "must be gateway or node")
	}
	sources := make(map[string]model.Source)
	for i, s := range c.Sources {
		field := fmt.Sprintf("sources[%d]", i)
		if !identifier.MatchString(s.ID) {
			return bad(field+".id", "must be a safe identifier of 1 to 64 characters")
		}
		if _, ok := sources[s.ID]; ok {
			return bad(field+".id", "duplicate identifier")
		}
		if len(strings.TrimSpace(s.Name)) == 0 || len(s.Name) > 256 ||
			strings.IndexFunc(s.Name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return bad(field+".name", "must be 1 to 256 bytes without control characters")
		}
		if err := rejectDuplicateKeys(s.Settings); err != nil {
			return bad(field+".settings", "invalid object or duplicate key")
		}
		if err := adapter.ValidateSource(s); err != nil {
			return bad(field+".settings", "unsupported or unsafe adapter configuration")
		}
		sources[s.ID] = s
	}
	targets := map[string]bool{}
	for i, t := range c.Targets {
		field := fmt.Sprintf("targets[%d]", i)
		if err := probe.ValidateTarget(t); err != nil {
			return bad(field, "unsafe or unsupported probe target")
		}
		if !identifier.MatchString(t.ID) || targets[t.ID] {
			return bad(field+".id", "invalid or duplicate identifier")
		}
		targets[t.ID] = true
	}
	p := c.Policy
	if p.Mode != "off" && p.Mode != "auto" && p.Mode != "manual" {
		return bad("policy.mode", "must be off, auto, or manual")
	}
	if p.Fallback != "closed" && p.Fallback != "direct" {
		return bad("policy.fallback", "must be closed or direct")
	}
	if math.IsNaN(p.ImprovementPercent) || math.IsInf(p.ImprovementPercent, 0) ||
		p.ImprovementPercent < 1 ||
		p.ImprovementPercent > 1000 {
		return bad("policy.improvement_percent", "must be between 1 and 1000")
	}
	for field, value := range map[string]int{"confirmations": p.Confirmations, "failure_confirmations": p.FailureConfirmations, "recovery_confirmations": p.RecoveryConfirmations} {
		if value < 1 || value > 100 {
			return bad("policy."+field, "must be between 1 and 100")
		}
	}
	for field, value := range map[string]int{"min_dwell_seconds": p.MinDwellSeconds, "cooldown_seconds": p.CooldownSeconds} {
		if value < 0 || value > 86400 {
			return bad("policy."+field, "must be between 0 and 86400")
		}
	}
	if p.StaleAfterSeconds < 1 || p.StaleAfterSeconds > 86400 {
		return bad("policy.stale_after_seconds", "must be between 1 and 86400")
	}
	if p.Mode == "manual" {
		s, ok := sources[p.Pinned]
		if !ok || !s.Enabled {
			return bad("policy.pinned", "manual mode requires an enabled source")
		}
	} else if p.Pinned != "" {
		return bad("policy.pinned", "only valid in manual mode")
	}
	if p.Mode != "off" && len(c.Targets) == 0 {
		return bad("targets", "selection requires configured probe resources")
	}
	if c.Role == "node" && (p.Mode != "off" || c.Network.Enabled) {
		return bad("role", "a node cannot run a competing gateway selector")
	}
	r := c.Probes
	for field, value := range map[string]int{"active_interval_seconds": r.ActiveIntervalSeconds, "other_interval_seconds": r.OtherIntervalSeconds, "speed_interval_seconds": r.SpeedIntervalSeconds} {
		if value < 1 || value > 86400 {
			return bad("probes."+field, "must be between 1 and 86400")
		}
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > 120 {
		return bad("probes.timeout_seconds", "must be between 1 and 120")
	}
	if r.Concurrency < 1 || r.Concurrency > 64 {
		return bad("probes.concurrency", "must be between 1 and 64")
	}
	if r.HistoryLimit < 1 || r.HistoryLimit > 256 {
		return bad("probes.history_limit", "must be between 1 and 256")
	}
	if p.StaleAfterSeconds <= r.TimeoutSeconds || p.StaleAfterSeconds <= r.OtherIntervalSeconds ||
		p.StaleAfterSeconds <= r.ActiveIntervalSeconds {
		return bad("policy.stale_after_seconds", "must exceed probe timeout and regular intervals")
	}
	n := c.Network
	if n.IPv6 != "block" && n.IPv6 != "proxy" {
		return bad("network.ipv6", "must be block or proxy")
	}
	if n.DNS != "block" && n.DNS != "selected-path" {
		return bad("network.dns", "must be block or selected-path")
	}
	if n.DNSResolver != "" {
		resolver, err := netip.ParseAddr(n.DNSResolver)
		if err != nil || !probe.PublicIP(resolver) {
			return bad("network.dns_resolver", "must be a public resolver IP literal")
		}
	}
	if n.DNS == "selected-path" && n.DNSResolver == "" {
		return bad("network.dns_resolver", "selected-path DNS requires an explicit public resolver")
	}
	seenInterfaces := map[string]bool{}
	for _, name := range n.LANInterfaces {
		if !ifaceName.MatchString(name) || name == "lo" || name == n.WANInterface ||
			seenInterfaces[name] {
			return bad("network.lan_interfaces", "invalid, duplicate, loopback, or WAN interface")
		}
		seenInterfaces[name] = true
	}
	if n.WANInterface != "" && (!ifaceName.MatchString(n.WANInterface) || n.WANInterface == "lo") {
		return bad("network.wan_interface", "invalid interface")
	}
	seenPrefixes := map[string]bool{}
	for _, prefix := range n.LocalPrefixes {
		p, err := netip.ParsePrefix(prefix)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().IsUnspecified() ||
			p.Addr().IsMulticast() ||
			seenPrefixes[prefix] {
			return bad(
				"network.local_prefixes",
				"invalid, unbounded, noncanonical, or repeated prefix",
			)
		}
		seenPrefixes[prefix] = true
	}
	if n.Enabled &&
		(p.Mode == "off" || len(n.LANInterfaces) == 0 || n.WANInterface == "" || len(n.LocalPrefixes) == 0) {
		return bad(
			"network",
			"enabled interception requires selection and discovered LAN, WAN, and local prefixes",
		)
	}
	data, err := json.Marshal(c)
	if err != nil || len(data) > MaxConfigBytes {
		return bad("configuration", "invalid JSON or exceeds byte limit")
	}
	return nil
}

// Redact uses an allowlist: no engine settings survive an ordinary read. New
// adapter credential fields therefore remain private without a blacklist update.
func Redact(c model.Config) model.Config {
	c = clone(c)
	for i := range c.Sources {
		c.Sources[i].Settings = json.RawMessage(`{}`)
	}
	return c
}

func clone(c model.Config) model.Config {
	data, _ := json.Marshal(c)
	var out model.Config
	_ = json.Unmarshal(data, &out)
	return out
}

// Duplicate keys are ambiguous to consumers and are rejected at every depth,
// including raw adapter settings. Error text never includes imported values.
func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds limit")
		}
		tok, err := d.Token()
		if err != nil {
			return errors.New("invalid JSON document")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return errors.New("invalid JSON object")
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("duplicate JSON key")
				}
				seen[k] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		if err != nil {
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
