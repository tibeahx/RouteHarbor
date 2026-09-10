//go:build linux

package helper

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

func TestLinuxManagedEngineRPCClientFixture(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_ENGINE_RPC_CHILD") != "1" {
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("API fixture must be unprivileged")
	}
	client := &Client{SocketPath: os.Getenv("ROUTEHARBOR_ENGINE_RPC_SOCKET"), ExpectedUID: 0}
	manager := adapter.NewManager(os.Getenv("ROUTEHARBOR_ENGINE_RPC_RUNTIME"))
	manager.ManagedEngines = client
	manager.DNSResolver = "8.8.8.8"
	manager.EnableIPv6 = true
	source := model.Source{
		ID:       "rpc-engine",
		Name:     "RPC fixture",
		Type:     "sing-box",
		Enabled:  true,
		Settings: json.RawMessage(`{"type":"http","server":"1.1.1.1","server_port":8080}`),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if restore := os.Getenv("ROUTEHARBOR_ENGINE_RPC_RESTORE"); restore != "" {
		raw, e := os.ReadFile(restore)
		if e != nil {
			t.Fatal(e)
		}
		var p adapter.Path
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("invalid fixture")
		}
		if e = manager.RestoreAllocations(
			ctx,
			[]model.Source{source},
			[]adapter.Path{p},
		); e != nil {
			t.Fatal(e)
		}
	}
	if e := manager.Start(ctx, source); e != nil {
		t.Fatal("unprivileged API managed start", e)
	}
	// The long-lived engine must not consume the only ordinary RPC slot.
	if _, e := client.Status(ctx); e != nil {
		t.Fatal("engine blocked ordinary helper RPC admission", e)
	}
	p, e := manager.ProbePath(ctx, source)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(p)
	if e = os.WriteFile(os.Getenv("ROUTEHARBOR_ENGINE_RPC_READY"), raw, 0o644); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("ROUTEHARBOR_ENGINE_RPC_STOP") == "1" {
		if e = manager.Stop(context.Background(), source.ID); e != nil {
			t.Fatal("explicit managed stop", e)
		}
		for _, port := range []int{p.ProxyPort, p.TransparentPort, p.DNSPort} {
			l, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if e != nil {
				t.Fatal("stop returned before owned listener closed", e)
			}
			_ = l.Close()
		}
		return
	}
	select {}
}

func TestLinuxManagedEngineRPCUnprivilegedAPIAndCrashCleanup(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("ROUTEHARBOR_ENGINE_WORKER_LAB") != "1" {
		t.Skip("requires pinned engines plus privileged worker lab")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root, e := os.MkdirTemp("", "routeharbor-engine-rpc-")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if e = os.Chmod(root, 0o755); e != nil {
		t.Fatal(e)
	}
	runtimeDir := filepath.Join(root, "engines")
	if e = os.Mkdir(runtimeDir, 0o700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(runtimeDir, 65534, 65534); e != nil {
		t.Fatal(e)
	}
	outDir := filepath.Join(root, "client")
	if e = os.Mkdir(outDir, 0o700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(outDir, 65534, 65534); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(root, "helper.sock")
	s := &Server{
		Manager:        testManager(t, &memoryBackend{}, &testWatchdog{}),
		AllowedUID:     65534,
		SocketPath:     socket,
		MaxConnections: 1,
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, e := os.Stat(socket); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not serve")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ready := filepath.Join(outDir, "ready.json")
	start := func(stop bool, restore string) *exec.Cmd {
		cmd := exec.Command(
			os.Args[0],
			"-test.run=^TestLinuxManagedEngineRPCClientFixture$",
			"-test.v",
		)
		cmd.Env = append(
			os.Environ(),
			"ROUTEHARBOR_ENGINE_RPC_CHILD=1",
			"ROUTEHARBOR_ENGINE_RPC_SOCKET="+socket,
			"ROUTEHARBOR_ENGINE_RPC_RUNTIME="+runtimeDir,
			"ROUTEHARBOR_ENGINE_RPC_READY="+ready,
			"ROUTEHARBOR_ENGINE_RPC_RESTORE="+restore,
		)
		if stop {
			cmd.Env = append(cmd.Env, "ROUTEHARBOR_ENGINE_RPC_STOP=1")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}},
		}
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		return cmd
	}
	child := start(false, "")
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	var p adapter.Path
	deadline = time.Now().Add(15 * time.Second)
	for {
		raw, err := os.ReadFile(ready)
		if err == nil && json.Unmarshal(raw, &p) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unprivileged managed API did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, e := os.ReadFile("/proc/" + strconv.Itoa(child.Process.Pid) + "/status")
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"CapEff:\t0000000000000000", "CapPrm:\t0000000000000000", "CapAmb:\t0000000000000000"} {
		if !strings.Contains(string(status), field) {
			t.Fatal("HTTP API received engine capabilities", field)
		}
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
	deadline = time.Now().Add(4 * time.Second)
	for {
		s.probeMu.Lock()
		active := len(s.engines)
		s.probeMu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("API SIGKILL left helper engine registration alive")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Restore the original committed allocation after crash and prove explicit
	// Stop waits for the privileged worker's listeners to be released.
	restored := filepath.Join(outDir, "restore.json")
	raw, _ := json.Marshal(p)
	if e = os.WriteFile(restored, raw, 0o644); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(ready); e != nil {
		t.Fatal(e)
	}
	second := start(true, restored)
	if e = second.Wait(); e != nil {
		t.Fatal("restored API process failed", e)
	}
	raw, e = os.ReadFile(ready)
	if e != nil {
		t.Fatal(e)
	}
	var after adapter.Path
	if json.Unmarshal(raw, &after) != nil || after.TransparentPort != p.TransparentPort ||
		after.DNSPort != p.DNSPort ||
		after.Mark != p.Mark {
		t.Fatal("managed restart changed committed allocation")
	}
}
