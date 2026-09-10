package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func direct(id string) model.Source {
	return model.Source{
		ID:       id,
		Name:     "Direct",
		Type:     "direct",
		Enabled:  true,
		Auto:     true,
		Settings: json.RawMessage(`{}`),
	}
}

func target() model.Target {
	return model.Target{
		ID:          "resource",
		URL:         "https://example.com/check",
		Required:    true,
		StatusCodes: []int{200},
		MaxBytes:    1024,
	}
}

func TestDefaultsAreInactiveAndRoundTrip(t *testing.T) {
	c := Defaults()
	if c.Policy.Mode != "off" || c.Network.Enabled || c.Policy.Fallback != "closed" ||
		c.Policy.BreakExisting {
		t.Fatal("defaults activate routing or bypass safety")
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Migrate(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.Revision != 1 || got.Probes.Concurrency != 2 {
		t.Fatalf("wrong defaults: %+v", got)
	}
}

func TestValidationSecurityBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Config)
	}{
		{"future schema", func(c *model.Config) { c.SchemaVersion = 2 }},
		{"missing schema", func(c *model.Config) { c.SchemaVersion = 0 }},
		{"missing revision", func(c *model.Config) { c.Revision = 0 }},
		{"unknown mode", func(c *model.Config) { c.Policy.Mode = "automatic" }},
		{"unknown fallback", func(c *model.Config) { c.Policy.Fallback = "best-effort" }},
		{"invalid role", func(c *model.Config) { c.Role = "router" }},
		{
			"node selector",
			func(c *model.Config) { c.Role = "node"; c.Policy.Mode = "auto"; c.Targets = []model.Target{target()} },
		},
		{
			"manual missing",
			func(c *model.Config) { c.Policy.Mode = "manual"; c.Policy.Pinned = "missing" },
		},
		{"auto without resources", func(c *model.Config) { c.Policy.Mode = "auto" }},
		{"unexpected pin", func(c *model.Config) { c.Policy.Pinned = "a" }},
		{"disabled manual source", func(c *model.Config) {
			s := direct("a")
			s.Enabled = false
			c.Sources = []model.Source{s}
			c.Targets = []model.Target{target()}
			c.Policy.Mode = "manual"
			c.Policy.Pinned = "a"
		}},
		{
			"source identifier injection",
			func(c *model.Config) { s := direct("$(id)"); c.Sources = []model.Source{s} },
		},
		{
			"duplicate source",
			func(c *model.Config) { c.Sources = []model.Source{direct("a"), direct("a")} },
		},
		{
			"unknown adapter",
			func(c *model.Config) { s := direct("a"); s.Type = "shell"; c.Sources = []model.Source{s} },
		},
		{"hidden listener", func(c *model.Config) {
			s := direct("a")
			s.Settings = json.RawMessage(`{"listeners":["0.0.0.0:80"]}`)
			c.Sources = []model.Source{s}
		}},
		{"duplicate adapter field", func(c *model.Config) {
			s := direct("a")
			s.Settings = json.RawMessage(`{"x":1,"x":2}`)
			c.Sources = []model.Source{s}
		}},
		{
			"plaintext target",
			func(c *model.Config) { v := target(); v.URL = "http://example.com"; c.Targets = []model.Target{v} },
		},
		{"target credentials", func(c *model.Config) {
			v := target()
			v.URL = "https://secret:password@example.com"
			c.Targets = []model.Target{v}
		}},
		{
			"loopback target",
			func(c *model.Config) { v := target(); v.URL = "https://127.0.0.1"; c.Targets = []model.Target{v} },
		},
		{
			"private IPv6 target",
			func(c *model.Config) { v := target(); v.URL = "https://[fd00::1]"; c.Targets = []model.Target{v} },
		},
		{
			"linklocal target",
			func(c *model.Config) { v := target(); v.URL = "https://169.254.169.254"; c.Targets = []model.Target{v} },
		},
		{
			"local hostname",
			func(c *model.Config) { v := target(); v.URL = "https://router.local"; c.Targets = []model.Target{v} },
		},
		{
			"unbounded download",
			func(c *model.Config) { v := target(); v.MaxBytes = 1 << 40; c.Targets = []model.Target{v} },
		},
		{"unknown ipv6", func(c *model.Config) { c.Network.IPv6 = "ignore" }},
		{"unknown dns", func(c *model.Config) { c.Network.DNS = "system" }},
		{
			"same interfaces",
			func(c *model.Config) { c.Network.WANInterface = "eth7"; c.Network.LANInterfaces = []string{"eth7"} },
		},
		{
			"global bypass",
			func(c *model.Config) { c.Network.LocalPrefixes = []string{"0.0.0.0/0"} },
		},
		{
			"uncanonical bypass",
			func(c *model.Config) { c.Network.LocalPrefixes = []string{"10.0.0.1/24"} },
		},
		{"routing without discovered network", func(c *model.Config) { c.Network.Enabled = true }},
		{"zero history", func(c *model.Config) { c.Probes.HistoryLimit = 0 }},
		{"unbounded concurrency", func(c *model.Config) { c.Probes.Concurrency = 100000 }},
		{"stale before regular probe", func(c *model.Config) { c.Policy.StaleAfterSeconds = 20 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Defaults()
			tc.mutate(&c)
			if err := Validate(c); err == nil {
				t.Fatal("unsafe configuration accepted")
			} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password@example") {
				t.Fatalf("secret in error: %s", err)
			}
		})
	}
}

func TestStrictDecode(t *testing.T) {
	base, _ := json.Marshal(Defaults())
	for name, data := range map[string][]byte{
		"unknown":   append([]byte(`{"unknown":1,`), base[1:]...),
		"duplicate": append([]byte(`{"role":"node",`), base[1:]...),
		"trailing":  append(append([]byte{}, base...), []byte(` {}`)...),
		"oversize":  bytes.Repeat([]byte(" "), MaxConfigBytes+1),
		"deep":      []byte(strings.Repeat("[", 1000) + strings.Repeat("]", 1000)),
		"null":      []byte(`null`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(data); err == nil {
				t.Fatal("invalid import accepted")
			}
		})
	}
}

func TestSourceCountHasByteBudgetNotArtificialCap(t *testing.T) {
	c := Defaults()
	for i := range 2000 {
		c.Sources = append(c.Sources, direct(fmt.Sprintf("source-%d", i)))
	}
	if err := Validate(c); err != nil {
		t.Fatalf("reasonable source count rejected: %v", err)
	}
}

func TestRedactionIsAllowlistedAndDetached(t *testing.T) {
	c := Defaults()
	c.Sources = []model.Source{
		{
			ID:   "proxy",
			Name: "Proxy",
			Type: "socks5",
			Settings: json.RawMessage(
				`{"server":"private-endpoint.example","password":"SECRET","future_private_field":"SECRET2"}`,
			),
		},
	}
	c.Targets = []model.Target{target()}
	r := Redact(c)
	data, _ := json.Marshal(r)
	for _, private := range []string{"private-endpoint", "SECRET", "future_private_field"} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatalf("redacted response contains %s", private)
		}
	}
	r.Sources[0].Name = "Changed"
	r.Targets[0].StatusCodes[0] = 404
	if c.Sources[0].Name != "Proxy" || c.Targets[0].StatusCodes[0] != 200 {
		t.Fatal("redaction mutated original")
	}
}

func TestStoreDurabilityCASAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for name, want := range map[string]os.FileMode{".": 0o700, "config.json": 0o600, ".lock": 0o600} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s permissions: %v %v", name, info, err)
		}
	}
	c := s.Get()
	c.Sources = []model.Source{direct("a")}
	updated, err := s.Replace(c.Revision, c)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 {
		t.Fatal("revision not advanced")
	}
	updated.Sources[0].Name = "mutated"
	if s.Get().Sources[0].Name == "mutated" {
		t.Fatal("returned object aliases store")
	}
	if _, err := s.Replace(c.Revision, c); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale write accepted: %v", err)
	}
	other, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if other.Get().Sources[0].ID != "a" || other.Get().Revision != 2 {
		t.Fatal("committed configuration not durable")
	}
	c = other.Get()
	c.Sources = append(c.Sources, direct("b"))
	if _, err := other.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	stale := s.Get()
	if _, err := s.Replace(stale.Revision, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-store CAS lost update: %v", err)
	}
	if s.Get().Revision != 3 {
		t.Fatal("conflicting store did not reload disk state")
	}
}

func TestConcurrentCASHasOneWinner(t *testing.T) {
	dir := t.TempDir()
	a, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	c := a.Get()
	var won atomic.Int64
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 0 {
				s = b
			}
			_, err := s.Replace(c.Revision, c)
			if err == nil {
				won.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected CAS error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("CAS winners: %d", won.Load())
	}
}

func TestStoreRejectsSymlinksHardlinksAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"directory-symlink", "config-symlink", "lock-symlink", "config-contained-symlink", "lock-contained-symlink", "config-hardlink", "public-mode"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(Defaults())
			outside := filepath.Join(base, "outside")
			if err := os.WriteFile(outside, data, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory-symlink":
				real := dir
				dir = filepath.Join(base, "linked")
				if err := os.Symlink(real, dir); err != nil {
					t.Fatal(err)
				}
			case "config-symlink":
				if err := os.Symlink(outside, filepath.Join(dir, configFile)); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				if err := os.Symlink(outside, filepath.Join(dir, ".lock")); err != nil {
					t.Fatal(err)
				}
			case "config-contained-symlink", "lock-contained-symlink":
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, data, 0o600); err != nil {
					t.Fatal(err)
				}
				name := configFile
				if kind == "lock-contained-symlink" {
					name = ".lock"
				}
				if err := os.Symlink("target", filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			case "config-hardlink":
				if err := os.Link(outside, filepath.Join(dir, configFile)); err != nil {
					t.Fatal(err)
				}
			case "public-mode":
				if err := os.WriteFile(filepath.Join(dir, configFile), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := NewStore(dir); err == nil {
				_ = s.Close()
				t.Fatal("unsafe store accepted")
			}
			got, _ := os.ReadFile(outside)
			if !bytes.Equal(got, data) {
				t.Fatal("outside file modified")
			}
		})
	}
}

func TestDirectoryRenameCannotRedirectWrites(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	c := s.Get()
	c.Sources = []model.Source{direct("new")}
	if _, err := s.Replace(c.Revision, c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, configFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("write escaped anchored directory")
	}
	data, err := os.ReadFile(filepath.Join(moved, configFile))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || got.Revision != 2 {
		t.Fatalf("anchored write not committed: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	data, _ := json.Marshal(Defaults())
	f.Add(data)
	f.Add([]byte(`{"schema_version":1,"role":"gateway","role":"node"}`))
	f.Add([]byte(`{"sources":[{"settings":{"exec":"/bin/sh"}}]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Decode(data)
		if err == nil {
			if err := Validate(c); err != nil {
				t.Fatalf("decoded invalid config: %v", err)
			}
			if len(data) > MaxConfigBytes {
				t.Fatal("oversized input decoded")
			}
		}
	})
}

func TestPrivateCheckpointRetainsSecretsWithoutPromotingCandidate(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	key := strings.Repeat("ab", 16)
	if _, found, err := s.Checkpoint(key); err != nil || found {
		t.Fatal("missing checkpoint not reported")
	}
	c := s.Get()
	c.Sources = []model.Source{
		{
			ID:      "private",
			Name:    "Private proxy",
			Type:    "socks5",
			Enabled: true,
			Auto:    true,
			Settings: json.RawMessage(
				`{"server":"private.example","server_port":1080,"username":"user","password":"PRIVATE-CHECKPOINT"}`,
			),
		},
	}
	if err = s.SaveCheckpoint(key, c); err != nil {
		t.Fatal(err)
	}
	if len(s.Get().Sources) != 0 {
		t.Fatal("checkpoint promoted unconfirmed user configuration")
	}
	got, found, err := s.Checkpoint(key)
	if err != nil || !found ||
		!bytes.Contains(got.Sources[0].Settings, []byte("PRIVATE-CHECKPOINT")) {
		t.Fatalf("private checkpoint lost source secrets: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "checkpoint-"+key+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("checkpoint not private")
	}
	public, _ := json.Marshal(Redact(got))
	if bytes.Contains(public, []byte("PRIVATE-CHECKPOINT")) {
		t.Fatal("checkpoint secret leaked through redaction")
	}
	if err = s.SaveConfirmed(c); err != nil {
		t.Fatal(err)
	}
	if _, found, err = s.Confirmed(); err != nil || !found {
		t.Fatal("confirmed snapshot not durable")
	}
	for _, invalid := range []string{"../escape", strings.Repeat("AB", 16), "short"} {
		if s.SaveCheckpoint(invalid, c) == nil {
			t.Fatal("invalid checkpoint key accepted")
		}
	}
	if err = s.RemoveCheckpoint(key); err != nil {
		t.Fatal(err)
	}
	if _, found, err = s.Checkpoint(key); err != nil || found {
		t.Fatal("checkpoint not removed")
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err = os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(dir, "checkpoint-"+key+".json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Checkpoint(key); err == nil {
		t.Fatal("symlink checkpoint read accepted")
	}
	if err = s.SaveCheckpoint(key, c); err == nil {
		t.Fatal("symlink checkpoint write accepted")
	}
}

func TestOptionalConnectionTrackingReset(t *testing.T) {
	c := Defaults()
	c.Routing = nil // Connection resets are a legacy all-traffic option.
	c.Policy.BreakExisting = true
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}
