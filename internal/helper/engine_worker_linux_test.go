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
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

func testEngineRequest(t *testing.T, kind string) EngineRequest {
	t.Helper()
	settings := json.RawMessage(`{"type":"socks","server":"8.8.8.8","server_port":1080}`)
	if kind == "xray" {
		settings = json.RawMessage(
			`{"outbound":{"protocol":"vless","settings":{"vnext":[{"address":"8.8.8.8","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}}`,
		)
	}
	ports := []int{}
	listeners := []net.Listener{}
	for range 3 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	p := adapter.AllocatePath("engine-source", kind, 91)
	p.ProxyPort = ports[0]
	p.TransparentPort = ports[1]
	p.DNSPort = ports[2]
	p.IPv6 = true
	p.UDP = true
	return EngineRequest{
		Source: model.Source{
			ID:       p.SourceID,
			Name:     "Engine source",
			Type:     kind,
			Enabled:  true,
			Settings: settings,
		},
		Path:        p,
		DNSResolver: "8.8.8.8",
	}
}

func engineChildPID(worker int, kind string) string {
	tasks, _ := filepath.Glob("/proc/" + strconv.Itoa(worker) + "/task/*/children")
	for _, task := range tasks {
		children, _ := os.ReadFile(task)
		for _, pid := range strings.Fields(string(children)) {
			exe, _ := os.Readlink("/proc/" + pid + "/exe")
			if exe == "/usr/bin/"+kind {
				return pid
			}
		}
	}
	return ""
}

func TestLinuxManagedEngineWorkerPrivilegesAndCleanup(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("ROUTEHARBOR_ENGINE_WORKER_LAB") != "1" {
		t.Skip("requires pinned native sing-box and Xray lab image")
	}
	for _, kind := range []string{"sing-box", "xray"} {
		t.Run(kind, func(t *testing.T) {
			req := testEngineRequest(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd, life, err := StartEngineWorker(ctx, req, 65534, 65534)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = life.Close(); _ = cmd.Wait() }()
			child := engineChildPID(cmd.Process.Pid, kind)
			if child == "" {
				t.Fatal("ready worker did not own the expected native child")
			}
			status, err := os.ReadFile("/proc/" + child + "/status")
			if err != nil {
				t.Fatal(err)
			}
			fields := map[string]string{}
			for _, line := range strings.Split(string(status), "\n") {
				key, value, ok := strings.Cut(line, ":")
				if ok {
					fields[key] = strings.TrimSpace(value)
				}
			}
			if fields["Uid"] != "65534\t65534\t65534\t65534" ||
				fields["Gid"] != "65534\t65534\t65534\t65534" ||
				fields["Groups"] != "" {
				t.Fatalf("engine did not drop service credentials/groups: %s", status)
			}
			for _, set := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
				if fields[set] != "0000000000002000" {
					t.Fatalf(
						"%s unexpectedly %q; only CAP_NET_RAW should be granted",
						set,
						fields[set],
					)
				}
			}
			if !engineInputsReady(mustPID(t, child), req.Path) {
				t.Fatal("native TCP/UDP/IPv6 inputs not owned by child")
			}
			// Parent API has no inherited capabilities; only the fork/exec child is
			// changed. Closing its liveness handle must terminate and reap that child.
			_ = life.Close()
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if _, err = os.Stat("/proc/" + child); os.IsNotExist(err) {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatal("native engine survived owner disconnection")
		})
	}
}

func mustPID(t *testing.T, raw string) int {
	t.Helper()
	v, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEngineWorkerRefusesRootIdentity(t *testing.T) {
	for _, ids := range [][2]uint32{{0, 65534}, {65534, 0}, {^uint32(0), 65534}, {65534, ^uint32(0)}} {
		if _, _, err := StartEngineWorker(
			context.Background(),
			EngineRequest{},
			ids[0],
			ids[1],
		); err == nil {
			t.Fatal("unsafe engine identity accepted")
		}
	}
}

func TestLinuxManagedEngineHelperCrashFixture(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_ENGINE_HELPER_CRASH") != "1" {
		t.Skip("subprocess fixture only")
	}
	requireNetLab(t)
	req := testEngineRequest(t, "sing-box")
	cmd, life, err := StartEngineWorker(context.Background(), req, 65534, 65534)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = life.Close(); _ = cmd.Wait() }()
	child := engineChildPID(cmd.Process.Pid, "sing-box")
	if child == "" {
		t.Fatal("native engine missing")
	}
	if err = os.WriteFile(
		os.Getenv("ROUTEHARBOR_ENGINE_CHILD_PID"),
		[]byte(child),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestLinuxManagedEngineAfterHelperSIGKILL(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("ROUTEHARBOR_ENGINE_WORKER_LAB") != "1" {
		t.Skip("requires pinned native engine lab")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	parent := exec.Command(
		os.Args[0],
		"-test.run=^TestLinuxManagedEngineHelperCrashFixture$",
		"-test.v",
	)
	parent.Env = append(
		os.Environ(),
		"ROUTEHARBOR_ENGINE_HELPER_CRASH=1",
		"ROUTEHARBOR_ENGINE_CHILD_PID="+pidFile,
	)
	parent.Stdout = os.Stderr
	parent.Stderr = os.Stderr
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Process.Kill(); _ = parent.Wait() }()
	var child string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(pidFile)
		child = strings.TrimSpace(string(data))
		if child != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if child == "" {
		t.Fatal("helper did not start native child")
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + child); os.IsNotExist(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("privileged helper SIGKILL left its native engine alive or unreaped")
}
