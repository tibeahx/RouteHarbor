package adapter

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tibeahx/OpenRHP/internal/model"
)

func TestPinnedNativeEngineValidators(t *testing.T) {
	if os.Getenv("OPENRHP_ENGINE_LAB") != "1" || runtime.GOOS != "linux" {
		t.Skip("requires the isolated pinned native engine lab")
	}
	fixtures := []struct{ kind, raw string }{
		{
			"sing-box",
			`{"type":"vless","server":"1.1.1.1","server_port":443,"uuid":"11111111-1111-4111-8111-111111111111","tls":{"enabled":true,"server_name":"vpn.example"}}`,
		},
		{
			"sing-box",
			`{"type":"trojan","server":"1.1.1.1","server_port":443,"password":"public-test-fixture","tls":{"enabled":true,"server_name":"vpn.example"},"transport":{"type":"ws","path":"/tunnel"}}`,
		},
		{
			"sing-box",
			`{"type":"shadowsocks","server":"1.1.1.1","server_port":443,"method":"aes-128-gcm","password":"public-test-fixture"}`,
		},
		{"socks5", `{"server":"1.1.1.1","server_port":1080}`},
		{"http-connect", `{"server":"1.1.1.1","server_port":8080}`},
		{
			"xray",
			`{"link":"vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&type=ws&path=%2Fproxy&sni=vpn.example"}`,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.kind, func(t *testing.T) {
			s := source(fixture.kind, fixture.raw)
			p := Path{
				ProxyPort:       12345,
				TransparentPort: 12346,
				DNSPort:         12347,
				DNSResolver:     "8.8.8.8",
				UDP:             fixture.kind != "http-connect",
				IPv6:            true,
			}
			raw, e := EngineConfig(s, p)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "engine.json")
			if e = os.WriteFile(path, raw, 0o600); e != nil {
				t.Fatal(e)
			}
			engine := "sing-box"
			args := []string{"check", "-c", path}
			if fixture.kind == "xray" {
				engine = "xray"
				args = []string{"run", "-test", "-config", path}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e = verifyEngine(ctx, engine, "/usr/bin/"+engine); e != nil {
				t.Fatal(e)
			}
			cmd := exec.CommandContext(ctx, "/usr/bin/"+engine, args...)
			if output, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("native validator rejected %s: %v %s", fixture.kind, e, output)
			}
		})
	}
}

func TestPinnedNativeEnginesStartAndRecoverManagedInputs(t *testing.T) {
	if os.Getenv("OPENRHP_ENGINE_LAB") != "1" || runtime.GOOS != "linux" {
		t.Skip("requires the isolated pinned native engine lab")
	}
	for _, fixture := range []struct{ kind, raw string }{
		{"sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`},
		{"xray", `{"link":"vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&type=tcp&sni=vpn.example"}`},
	} {
		t.Run(fixture.kind, func(t *testing.T) {
			s := source(fixture.kind, fixture.raw)
			m := NewManager(filepath.Join(t.TempDir(), "engine"))
			m.DNSResolver = "8.8.8.8"
			m.EnableIPv6 = true
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			defer func() {
				if e := m.Close(context.Background()); e != nil {
					t.Error(e)
				}
			}()
			if e := m.Start(ctx, s); e != nil {
				t.Fatal("native engine startup", e)
			}
			before := m.Status(s.ID)
			m.mu.Lock()
			cmd, done := m.paths[s.ID].cmd, m.paths[s.ID].done
			m.mu.Unlock()
			if e := cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("native engine did not exit")
			}
			if e := m.Start(ctx, s); e != nil {
				t.Fatal("native engine recovery", e)
			}
			after := m.Status(s.ID)
			if after.State != "running" ||
				before.Path.TransparentPort != after.Path.TransparentPort ||
				before.Path.DNSPort != after.Path.DNSPort ||
				before.Path.Mark != after.Path.Mark {
				t.Fatal("native recovery changed committed allocation")
			}
		})
	}
}

func TestPinnedNativeEngineControllerFixture(t *testing.T) {
	if os.Getenv("OPENRHP_NATIVE_CONTROLLER_CHILD") != "1" {
		return
	}
	m := NewManager(os.Getenv("OPENRHP_NATIVE_CONTROLLER_RUNTIME"))
	m.DNSResolver = "8.8.8.8"
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	if e := m.Start(context.Background(), s); e != nil {
		os.Exit(4)
	}
	p, e := m.ProbePath(context.Background(), s)
	if e != nil {
		os.Exit(5)
	}
	raw, _ := json.Marshal(p)
	if os.WriteFile(os.Getenv("OPENRHP_NATIVE_CONTROLLER_READY"), raw, 0o600) != nil {
		os.Exit(6)
	}
	select {}
}

func TestPinnedNativeEngineControllerDeathReleasesCommittedInputs(t *testing.T) {
	if os.Getenv("OPENRHP_ENGINE_LAB") != "1" || runtime.GOOS != "linux" {
		t.Skip("requires the isolated pinned native engine lab")
	}
	root := t.TempDir()
	ready := filepath.Join(root, "ready.json")
	runtimeDir := filepath.Join(root, "engines")
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestPinnedNativeEngineControllerFixture$")
	cmd.Env = append(
		os.Environ(),
		"OPENRHP_NATIVE_CONTROLLER_CHILD=1",
		"OPENRHP_NATIVE_CONTROLLER_RUNTIME="+runtimeDir,
		"OPENRHP_NATIVE_CONTROLLER_READY="+ready,
	)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var old Path
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(ready)
		if err == nil && json.Unmarshal(raw, &old) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller child did not start native engine")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e = cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = cmd.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for {
		listeners, err := reserveFixedPorts([]int{old.ProxyPort, old.TransparentPort, old.DNSPort})
		if err == nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("orphan engine retained committed inputs after controller SIGKILL")
		}
		time.Sleep(20 * time.Millisecond)
	}
	m := NewManager(runtimeDir)
	m.DNSResolver = "8.8.8.8"
	defer func() {
		if e := m.Close(context.Background()); e != nil {
			t.Error(e)
		}
	}()
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	if e = m.RestoreAllocations(context.Background(), []model.Source{s}, []Path{old}); e != nil {
		t.Fatal(e)
	}
	if e = m.Start(context.Background(), s); e != nil {
		t.Fatal("restart after controller death", e)
	}
}
