package adapter

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The only substituted executable is this test binary. Production command
// construction remains fixed to verified /usr/bin/sing-box and /usr/bin/xray.
func TestEngineProcessFixture(t *testing.T) {
	if os.Getenv("OPENRHP_ENGINE_TEST_CHILD") != "1" {
		return
	}
	if os.Getenv("OPENRHP_ENGINE_TEST_EXIT") == "1" {
		os.Exit(3)
	}
	var ports []int
	if json.Unmarshal([]byte(os.Getenv("OPENRHP_ENGINE_TEST_PORTS")), &ports) != nil {
		os.Exit(4)
	}
	for _, port := range ports {
		l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if e != nil {
			os.Exit(5)
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	select {}
}

func fixtureBuilder(exit bool) func(context.Context, string, string) (*exec.Cmd, error) {
	return func(_ context.Context, _, config string) (*exec.Cmd, error) {
		raw, e := os.ReadFile(config)
		if e != nil {
			return nil, e
		}
		var generated struct {
			Inbounds []struct {
				ListenPort int `json:"listen_port"`
			} `json:"inbounds"`
		}
		if e = json.Unmarshal(raw, &generated); e != nil {
			return nil, e
		}
		ports := []int{}
		for _, in := range generated.Inbounds {
			ports = append(ports, in.ListenPort)
		}
		encoded, _ := json.Marshal(ports)
		exe, e := os.Executable()
		if e != nil {
			return nil, e
		}
		cmd := exec.Command(exe, "-test.run=^TestEngineProcessFixture$")
		cmd.Env = append(
			os.Environ(),
			"OPENRHP_ENGINE_TEST_CHILD=1",
			"OPENRHP_ENGINE_TEST_PORTS="+string(encoded),
		)
		if exit {
			cmd.Env = append(cmd.Env, "OPENRHP_ENGINE_TEST_EXIT=1")
		}
		return cmd, nil
	}
}

func TestEngineExitClearsGenerationAndRestartsSameInputs(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "engine"))
	m.buildCommand = fixtureBuilder(false)
	ctx := context.Background()
	defer func() {
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	if e := m.Start(ctx, s); e != nil {
		t.Fatal(e)
	}
	before := m.Status(s.ID)
	if before.State != "running" {
		t.Fatal(before)
	}
	m.mu.Lock()
	first := m.paths[s.ID].cmd
	done := m.paths[s.ID].done
	m.mu.Unlock()
	if e := first.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("process not reaped")
	}
	m.mu.Lock()
	cleared := m.paths[s.ID].cmd == nil
	m.mu.Unlock()
	if !cleared || m.Status(s.ID).State != "failed" {
		t.Fatal("dead process remained attached")
	}
	if e := m.Start(ctx, s); e != nil {
		t.Fatal(e)
	}
	after := m.Status(s.ID)
	m.mu.Lock()
	second := m.paths[s.ID].cmd
	m.mu.Unlock()
	if second == first || after.State != "running" ||
		after.Path.ProxyPort != before.Path.ProxyPort ||
		after.Path.TransparentPort != before.Path.TransparentPort ||
		after.Path.Mark != before.Path.Mark {
		t.Fatal("recovery changed source allocation", before, after)
	}
	if e := m.Stop(ctx, s.ID); e != nil {
		t.Fatal(e)
	}
	if m.Status(s.ID).State != "stopped" {
		t.Fatal("stop retained old generation")
	}
}

func TestEngineExitBeforeListenerNeverReportsRunning(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "engine"))
	m.buildCommand = fixtureBuilder(true)
	ctx := context.Background()
	defer func() {
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	if e := m.Start(ctx, s); e == nil {
		t.Fatal("early process exit reported startup success")
	}
	if m.Status(s.ID).State == "running" {
		t.Fatal("dead process reported ready")
	}
	// Recovery also works after failure during the first initialization.
	m.buildCommand = fixtureBuilder(false)
	if e := m.Start(ctx, s); e != nil {
		t.Fatal(e)
	}
}

func TestNetworkReconfigurationSerializesWithEngineStart(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "engine"))
	entered := make(chan struct{})
	release := make(chan struct{})
	build := fixtureBuilder(false)
	m.buildCommand = func(ctx context.Context, engine, config string) (*exec.Cmd, error) {
		close(entered)
		<-release
		return build(ctx, engine, config)
	}
	ctx := context.Background()
	defer func() {
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	}()
	s := source("sing-box", `{"type":"http","server":"1.1.1.1","server_port":8080}`)
	started := make(chan error, 1)
	go func() { started <- m.Start(ctx, s) }()
	<-entered
	configured := make(chan error, 1)
	go func() { configured <- m.ConfigureNetwork(ctx, "8.8.8.8", false) }()
	select {
	case e := <-configured:
		t.Fatal("configuration changed during engine startup", e)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if e := <-started; e != nil {
		t.Fatal(e)
	}
	if e := <-configured; e != nil {
		t.Fatal(e)
	}
	if m.Status(s.ID).State != "stopped" {
		t.Fatal("old engine survived reconfiguration")
	}
	p, e := m.ProbePath(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	if p.DNSResolver != "8.8.8.8" || p.DNSPort == 0 {
		t.Fatal("new preparation used stale DNS policy")
	}
}
