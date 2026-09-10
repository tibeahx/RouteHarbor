package adapter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

func source(kind, settings string) model.Source {
	return model.Source{ID: "test", Type: kind, Settings: json.RawMessage(settings)}
}

func TestValidateRejectsExecutableOrUnownedConfiguration(t *testing.T) {
	tests := []model.Source{
		source(
			"direct",
			`{"inbounds":[]}`,
		),
		source(
			"sing-box",
			`{"type":"vless","server":"vpn.example","server_port":443,"uuid":"11111111-1111-4111-8111-111111111111","tls":{"enabled":true,"certificate_path":"/etc/shadow"}}`,
		),
		source(
			"sing-box",
			`{"type":"http","server":"vpn.example","server_port":443,"detour":"other"}`,
		),
		source(
			"sing-box",
			`{"type":"http","server":"vpn.example","server_port":443,"routing_mark":1}`,
		),
		source("packet-engine", `{"strategy":"multisplit-v1","args":["--lua-init=/tmp/evil.lua"]}`),
		source("packet-engine", `{"strategy":"https://attacker/evil.lua"}`),
		source("interface", `{"name":"../../etc/shadow"}`),
		source("socks5", `{"server":"first.example","server":"second.example","server_port":1080}`),
		source("direct", `{} {}`),
		source("direct", `null`),
		source("xray", `{"outbound":{"protocol":"freedom","settings":{}}}`),
		source(
			"xray",
			`{"link":"vless://11111111-1111-4111-8111-111111111111@vpn.example:443?security=tls&allowInsecure=1"}`,
		),
		source(
			"xray",
			`{"link":"vless://11111111-1111-4111-8111-111111111111@vpn.example:443?security=tls&security=none"}`,
		),
	}
	for _, s := range tests {
		if e := ValidateSource(s); e == nil {
			t.Errorf("accepted unsafe %s input", s.Type)
		}
	}
}

func TestEngineNativeFormatsRemainSeparate(t *testing.T) {
	sing := source(
		"sing-box",
		`{"type":"vless","server":"vpn.example","server_port":443,"uuid":"11111111-1111-4111-8111-111111111111","tls":{"enabled":true}}`,
	)
	xray := source(
		"xray",
		`{"link":"vless://11111111-1111-4111-8111-111111111111@vpn.example:443?security=tls&type=ws&path=%2Fproxy&sni=vpn.example"}`,
	)
	for _, s := range []model.Source{sing, xray} {
		if e := ValidateSource(s); e != nil {
			t.Fatal(e)
		}
		raw, e := EngineConfig(s, Path{ProxyPort: 1234, TransparentPort: 1235})
		if e != nil {
			t.Fatal(e)
		}
		var c map[string]any
		if e = json.Unmarshal(raw, &c); e != nil {
			t.Fatal(e)
		}
		ins := c["inbounds"].([]any)
		if len(ins) != 2 {
			t.Fatal("wrong listener count")
		}
		for _, i := range ins {
			if i.(map[string]any)["listen"] != "127.0.0.1" {
				t.Fatal("unowned listener")
			}
		}
		if s.Type == "xray" && strings.Contains(string(raw), `"type": "vless"`) {
			t.Fatal("Xray reinterpreted as sing-box")
		}
	}
	sing.Type = "xray"
	if ValidateSource(sing) == nil {
		t.Fatal("accepted sing-box config as Xray")
	}
}

func TestPrepareSeparateResourcesPrivateFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	m := NewManager(dir)
	s := source(
		"sing-box",
		`{"type":"http","server":"127.0.0.1","server_port":8080,"username":"fixture","password":"fixture-only"}`,
	)
	if e := m.Prepare(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	a, e := m.ProbePath(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	s.ID = "second"
	b, e := m.ProbePath(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	if a.Mark == b.Mark || a.Queue == b.Queue || a.ProxyPort == b.ProxyPort ||
		a.TransparentPort == b.TransparentPort {
		t.Fatal("sources share path resources")
	}
	info, e := os.Stat(filepath.Join(dir, "test.json"))
	if e != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("config not private")
	}
	info, e = os.Stat(dir)
	if e != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("directory not private")
	}
	raw, _ := json.Marshal(m.Status("test"))
	if strings.Contains(string(raw), "fixture-only") ||
		strings.Contains(string(raw), "proxy.example") {
		t.Fatal("status exposes credentials or endpoints")
	}
	if e = m.Stop(context.Background(), "test"); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "test.json")); !os.IsNotExist(e) {
		t.Fatal("stopped config retained")
	}
}

func TestNoImplicitDPI(t *testing.T) {
	m := NewManager(t.TempDir())
	s := source("packet-engine", `{"strategy":"multisplit-v1"}`)
	if e := m.Start(context.Background(), s); e == nil {
		t.Fatal("reported DPI ready without helper")
	}
	if m.Status(s.ID).ErrorCode != "privileged_packet_engine_required" {
		t.Fatal("missing truthful capability error")
	}
	args, e := PacketArgs(2)
	if e != nil {
		t.Fatal(e)
	}
	if args[0] != "--qnum=21002" {
		t.Fatal(args)
	}
}

func FuzzSourceImport(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"server":"proxy.example","server_port":1080}`))
	f.Add(
		[]byte(
			`{"link":"vless://11111111-1111-4111-8111-111111111111@vpn.example:443?security=tls&type=ws&path=%2Fproxy&sni=vpn.example"}`,
		),
	)
	f.Add([]byte(`{"name":"wg0"}`))
	f.Add([]byte(`{"strategy":"multisplit-v1"}`))
	f.Add([]byte(strings.Repeat("[", 65) + strings.Repeat("]", 65)))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, kind := range []string{"direct", "sing-box", "xray", "socks5", "http-connect", "interface", "packet-engine"} {
			_ = ValidateSource(source(kind, string(b)))
		}
	})
}

func TestEndpointPinPreservesTLSIdentityAndSelectedDNS(t *testing.T) {
	m := NewManager(t.TempDir())
	m.LookupHost = func(context.Context, string) ([]string, error) { return []string{"1.2.3.4"}, nil }
	s := source(
		"sing-box",
		`{"type":"vless","server":"vpn.example","server_port":443,"uuid":"11111111-1111-4111-8111-111111111111","tls":{"enabled":true}}`,
	)
	pinned, e := m.pinEndpoint(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	var o SingOutbound
	if e = json.Unmarshal(pinned.Settings, &o); e != nil {
		t.Fatal(e)
	}
	if o.Server != "1.2.3.4" || o.TLS.ServerName != "vpn.example" {
		t.Fatal("endpoint pin lost TLS identity")
	}
	raw, e := EngineConfig(
		pinned,
		Path{
			ProxyPort:       1234,
			TransparentPort: 1235,
			DNSPort:         1236,
			DNSResolver:     "8.8.8.8",
			UDP:             true,
		},
	)
	if e != nil {
		t.Fatal(e)
	}
	var config map[string]any
	if e = json.Unmarshal(raw, &config); e != nil {
		t.Fatal(e)
	}
	servers := config["dns"].(map[string]any)["servers"].([]any)
	if len(servers) != 1 {
		t.Fatal("hidden resolver")
	}
	dns := servers[0].(map[string]any)
	if dns["server"] != "8.8.8.8" || dns["detour"] != "source" || dns["type"] != "tcp" {
		t.Fatal("DNS does not use explicit resolver through same source")
	}
}

func TestOnlyPinnedEngineVersionsAccepted(t *testing.T) {
	if !supportedEngineVersion("sing-box", "sing-box version 1.14.0\nEnvironment:") ||
		!supportedEngineVersion("xray", "Xray 26.3.27 (Xray, Penetrates Everything.)") {
		t.Fatal("expected pinned versions")
	}
	if supportedEngineVersion("sing-box", "sing-box version 1.14.1") ||
		supportedEngineVersion("xray", "Xray 26.3.270 other") {
		t.Fatal("accepted untested engine version")
	}
}
