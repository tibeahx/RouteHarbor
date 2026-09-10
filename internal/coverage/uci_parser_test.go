package coverage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type realUCI struct {
	binary, dir, delta string
	commands           []string
	reloads            int
	secret             string
}

func (r *realUCI) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	r.commands = append(r.commands, binary+" "+strings.Join(args, " "))
	if strings.Contains(strings.Join(args, " "), r.secret) {
		return nil, errors.New("private_key_in_process_arguments")
	}
	if binary == "/sbin/wifi" {
		if len(args) != 1 || args[0] != "reload" || len(input) != 0 {
			return nil, errors.New("unexpected_wifi_command")
		}
		r.reloads++
		return nil, nil
	}
	if binary != "/sbin/uci" {
		return nil, errors.New("unexpected_command")
	}
	arguments := append([]string{"-c", r.dir, "-t", r.delta}, args...)
	cmd := exec.CommandContext(ctx, r.binary, arguments...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, errors.New("uci_command_failed")
	}
	if strings.Contains(stderr.String(), r.secret) {
		return nil, errors.New("uci_exposed_private_key")
	}
	return data, nil
}

func (r *realUCI) raw(t *testing.T, commands string) {
	t.Helper()
	if _, err := r.Run(
		context.Background(),
		"/sbin/uci",
		[]string{"-q", "batch"},
		[]byte(commands),
	); err != nil {
		t.Fatal(err)
	}
}

func (r *realUCI) value(t *testing.T, key string) string {
	t.Helper()
	data, err := r.Run(context.Background(), "/sbin/uci", []string{"-q", "get", key}, nil)
	if err != nil {
		t.Fatal("read fixture setting", key, err)
	}
	return strings.TrimSuffix(string(data), "\n")
}

func realBackend(t *testing.T, secret string) (*UCIBackend, *realUCI) {
	t.Helper()
	binary := os.Getenv("ROUTEHARBOR_UCI_TEST_BINARY")
	if binary == "" {
		t.Skip("scripts/lab-uci.sh runs the actual upstream UCI parser")
	}
	r := &realUCI{binary: binary, dir: t.TempDir(), delta: t.TempDir(), secret: secret}
	fixtures := map[string]string{
		"wireless": "config wifi-device 'radio0'\n option channel '6'\n config wifi-iface 'main_ap'\n option device 'radio0'\n option mode 'ap'\n option network 'lan'\n option ssid 'Home'\n option encryption 'psk2+ccmp'\n config wifi-iface 'guest_ap'\n option device 'radio0'\n option mode 'ap'\n option network 'guest'\n option ssid 'Guest original'\n option key 'foreign-private-key'\n option encryption 'psk2+ccmp'\n",
		"network":  "config device 'bridge_lan'\n option name 'br-lan'\n option type 'bridge'\n list ports 'lan1'\n config interface 'lan'\n option proto 'static'\n option device 'br-lan'\n option ipaddr '192.168.50.1'\n config interface 'wan'\n option proto 'dhcp'\n option device 'eth1'\n",
		"dhcp":     "config dhcp 'lan'\n option interface 'lan'\n option start '100'\n option limit '150'\n",
		"firewall": "config zone 'wan'\n option name 'wan'\n option masq '1'\n",
	}
	for name, data := range fixtures {
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.raw(
		t,
		"set wireless.main_ap.key="+quoteUCI(
			secret,
		)+"\nset wireless.main_ap.ssid="+quoteUCI(
			"Home ' quote \\ station",
		)+"\ncommit wireless\n",
	)
	r.commands = nil
	b := NewUCIBackend(func(context.Context, Plan) error { return nil })
	b.Runner = r
	return b, r
}

// The real parser executes all UCI reads, mutations, commits and narrow restore.
// The Wi-Fi reload boundary is recorded: this test makes no RF or driver claim.
func TestGatewayPreservesForeignStateThroughRealUCI(t *testing.T) {
	for _, mode := range []string{"wds", "mesh"} {
		for _, secret := range []string{"quote'canary\\key", `';set wireless.injected=evil;'`, `double"quote;#$(touch /tmp/never-gateway)`} {
			t.Run(mode+"-"+string(rune(len(secret)+65)), func(t *testing.T) {
				ctx := context.Background()
				b, r := realBackend(t, secret)
				p := validPlan()
				p.Mode = mode
				originals := map[string][]byte{}
				for _, name := range []string{"network", "dhcp", "firewall"} {
					data, err := os.ReadFile(filepath.Join(r.dir, name))
					if err != nil {
						t.Fatal(err)
					}
					originals[name] = data
				}
				beforeSSID, beforeKey := r.value(
					t,
					"wireless.main_ap.ssid",
				), r.value(
					t,
					"wireless.main_ap.key",
				)
				setup, err := b.Inspect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(setup.APs) != 2 {
					t.Fatal("existing AP discovery failed")
				}
				if radio, err := b.RadioForPlan(ctx, p); err != nil || radio != "radio0" {
					t.Fatal("receipt radio mapping failed", err)
				}
				snapshot, err := b.Snapshot(ctx, p)
				if err != nil {
					t.Fatal(err)
				}
				if err := b.Apply(ctx, p); err != nil {
					t.Fatal(err)
				}
				if mode == "wds" && r.value(t, "wireless.main_ap.wds") != "1" {
					t.Fatal("WDS not enabled")
				}
				if mode == "mesh" &&
					(r.value(t, "wireless."+meshSection+".key") != secret || r.value(t, "wireless."+meshSection+".encryption") != "sae") {
					t.Fatal("mesh credentials changed")
				}
				// Simulate an unrelated administrator edit after apply. Narrow rollback
				// must preserve it, including when using a snapshot from an earlier file.
				r.raw(
					t,
					"set wireless.guest_ap.ssid='Guest changed during window'\ncommit wireless\n",
				)
				if err := b.Restore(ctx, snapshot); err != nil {
					t.Fatal(err)
				}
				if r.value(t, "wireless.main_ap.ssid") != beforeSSID ||
					r.value(t, "wireless.main_ap.key") != beforeKey ||
					r.value(t, "wireless.radio0.channel") != "6" {
					t.Fatal("gateway AP identity or channel changed")
				}
				if r.value(t, "wireless.guest_ap.ssid") != "Guest changed during window" ||
					r.value(t, "wireless.guest_ap.key") != "foreign-private-key" {
					t.Fatal("rollback overwrote unrelated AP")
				}
				for name, before := range originals {
					after, err := os.ReadFile(filepath.Join(r.dir, name))
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("gateway modified unrelated network service", name)
					}
				}
				for _, key := range []string{"wireless.main_ap.wds", "wireless.main_ap.routeharbor_wds_owner", "wireless." + meshSection, "wireless.injected"} {
					if _, err := r.Run(
						ctx,
						"/sbin/uci",
						[]string{"-q", "get", key},
						nil,
					); err == nil {
						t.Fatal("rollback or quoting left unexpected state", key)
					}
				}
				if r.reloads != 2 {
					t.Fatal("expected apply and restore reload boundaries")
				}
				for _, command := range r.commands {
					if strings.Contains(command, secret) {
						t.Fatal("private key reached process arguments")
					}
				}
			})
		}
	}
}

func TestGatewayRealUCIRejectsForeignOrChangedScope(t *testing.T) {
	b, r := realBackend(t, "canary-immutable-key")
	ctx := context.Background()
	p := validPlan()
	for _, statement := range []string{
		"set wireless.rh_gw_mesh='wifi-iface'\n",
		"set wireless.main_ap.wds='1'\n",
		"set network.lan.gateway='192.168.50.2'\n",
		"set wireless.radio0.channel='auto'\n",
		"set wireless.main_ap.encryption='sae'\n",
	} {
		r.raw(t, statement)
		calls := len(r.commands)
		if _, err := b.Check(ctx, p); err == nil {
			t.Fatal("incompatible existing gateway state accepted")
		}
		for _, command := range r.commands[calls:] {
			if strings.Contains(command, " set ") || strings.Contains(command, " batch") ||
				strings.Contains(command, "commit") {
				t.Fatal("validation changed gateway")
			}
		}
		r.raw(t, "revert wireless\nrevert network\n")
	}
}
