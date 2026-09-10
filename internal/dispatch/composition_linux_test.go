//go:build linux

package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

func labProcess(t *testing.T, config any, file, namespace, engine string) *exec.Cmd {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-c", file}
	if engine == "xray" {
		args = []string{"run", "-config", file}
	}
	cmd := exec.Command("/usr/bin/"+engine, args...)
	if namespace != "" {
		cmd = exec.Command(
			"/sbin/ip",
			append([]string{"netns", "exec", namespace, "/usr/bin/" + engine}, args...)...)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

func labSourceFixtures(t *testing.T, dir string, s *Spec) *exec.Cmd {
	t.Helper()
	cert, key := filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
	labExec(
		t,
		"/usr/bin/openssl",
		"req",
		"-x509",
		"-newkey",
		"rsa:2048",
		"-nodes",
		"-days",
		"1",
		"-keyout",
		key,
		"-out",
		cert,
		"-subj",
		"/CN=relay.example",
		"-addext",
		"subjectAltName=DNS:relay.example",
	)
	raw, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(
		"/usr/local/share/ca-certificates/routeharbor-selective-test.crt",
		raw,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	labExec(t, "/usr/sbin/update-ca-certificates")
	const uuid = "11111111-1111-4111-8111-111111111111"
	remote := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{
		map[string]any{"type": "socks", "listen": "11.0.0.99", "listen_port": 19080},
		map[string]any{"type": "http", "listen": "11.0.0.99", "listen_port": 19081},
		map[string]any{
			"type":        "vless",
			"listen":      "11.0.0.99",
			"listen_port": 19082,
			"users":       []any{map[string]any{"uuid": uuid}},
			"tls": map[string]any{
				"enabled":          true,
				"certificate_path": cert,
				"key_path":         key,
			},
		},
	}, "outbounds": []any{map[string]any{"type": "direct", "tag": "remote", "bind_interface": "server0"}}, "route": map[string]any{"final": "remote"}}
	labProcess(t, remote, filepath.Join(dir, "remote.json"), "dispatch-server", "sing-box")
	profiles := []struct{ kind, settings string }{
		{"socks5", `{"server":"11.0.0.99","server_port":19080}`},
		{"http-connect", `{"server":"11.0.0.99","server_port":19081}`},
		{"sing-box", `{"type":"socks","server":"11.0.0.99","server_port":19080}`},
		{
			"xray",
			`{"link":"vless://` + uuid + `@11.0.0.99:19082?security=tls&type=tcp&sni=relay.example"}`,
		},
	}
	for i, profile := range profiles {
		slot := 5 + i
		p := adapter.AllocatePath(profile.kind, profile.kind, slot)
		p.ProxyPort, p.TransparentPort, p.DNSPort, p.IPv6, p.UDP = 12000+slot, 13000+slot, 0, true, profile.kind != "http-connect"
		source := model.Source{
			ID:       profile.kind,
			Name:     profile.kind,
			Type:     profile.kind,
			Enabled:  true,
			Settings: json.RawMessage(profile.settings),
		}
		generated, err := adapter.EngineConfig(source, p)
		if err != nil {
			t.Fatal("source fixture", profile.kind, err)
		}
		var cfg map[string]any
		if err = json.Unmarshal(generated, &cfg); err != nil {
			t.Fatal(err)
		}
		engine := "sing-box"
		if profile.kind == "xray" {
			engine = "xray"
		}
		labProcess(t, cfg, filepath.Join(dir, profile.kind+".json"), "", engine)
		s.Sources = append(s.Sources, p)
	}
	p := adapter.AllocatePath("dpi", "packet-engine", 9)
	p.IPv6, p.UDP = true, true
	p.ProxyPort, p.TransparentPort, p.DNSPort = 0, 0, 0
	s.Sources = append(s.Sources, p)
	nfq := exec.Command(
		"/usr/bin/nfqws",
		"--qnum=21009",
		"--dpi-desync-fwmark=0x4f098000",
		"--filter-tcp=18080",
		"--dpi-desync=multisplit",
		"--dpi-desync-split-pos=1",
		"--user=nobody",
	)
	nfq.Stdout = io.Discard
	nfq.Stderr = io.Discard
	if err = nfq.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nfq.Process.Kill(); _ = nfq.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		all := true
		for _, p := range s.Sources {
			if p.ProxyPort == 0 {
				continue
			}
			c, e := net.DialTimeout(
				"tcp",
				fmt.Sprintf("127.0.0.1:%d", p.ProxyPort),
				100*time.Millisecond,
			)
			if e != nil {
				all = false
			} else {
				_ = c.Close()
			}
		}
		q, e := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
		all = all && e == nil && strings.Contains(string(q), "21009")
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native adapter or NFQUEUE fixture did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nfq
}

func labSelect(t *testing.T, slot int) {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		"PUT",
		"http://127.0.0.1:16250/proxies/bypass",
		strings.NewReader(fmt.Sprintf(`{"name":"source-%d"}`, slot)),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 204 {
		body, _ := io.ReadAll(response.Body)
		t.Fatal("selector failed", response.Status, string(body))
	}
}

func labPublish(t *testing.T, path string, learned bool) {
	t.Helper()
	domains := []string{"blocked.example", "blocked-v6.example"}
	if learned {
		domains = append(domains, "allowed.example")
	}
	raw, _ := json.Marshal(
		map[string]any{
			"version": 4,
			"rules": []any{
				map[string]any{"domain": domains},
				map[string]any{"ip_cidr": []string{"11.0.0.98/32", "2606:4700:100::98/128"}},
			},
		},
	)
	temp := path + ".new"
	if err := os.WriteFile(temp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temp, path); err != nil {
		t.Fatal(err)
	}
}
