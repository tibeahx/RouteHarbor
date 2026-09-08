package coverage

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

type Snapshot map[string][]byte

type Backend interface {
	Inspect(context.Context) (Setup, error)
	Check(context.Context, Plan) (WiFi, error)
	Snapshot(context.Context, Plan) (Snapshot, error)
	Apply(context.Context, Plan) error
	Restore(context.Context, Snapshot) error
}

type UCIBackend struct {
	Runner      platform.Runner
	Eligibility func(context.Context, Plan) error
}

const meshSection = "orhp_gw_mesh"

func NewUCIBackend(eligibility func(context.Context, Plan) error) *UCIBackend {
	if eligibility == nil {
		eligibility = func(ctx context.Context, p Plan) error {
			r := platform.Detect(ctx)
			if r.OS != "OpenWrt" || !r.Capabilities[p.Mode].Available ||
				!r.Capabilities["encrypted_backhaul"].Available ||
				!r.Capabilities["concurrent_radio"].Available {
				return errors.New("gateway_pair_compatibility_unverified")
			}
			return nil
		}
	}
	return &UCIBackend{Runner: gatewayRunner{}, Eligibility: eligibility}
}

type gatewayRunner struct{}

func (gatewayRunner) Available() bool {
	info, err := os.Stat("/sbin/wifi")
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func (gatewayRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	if binary != "/sbin/wifi" {
		return (platform.ProductionRunner{}).Run(ctx, binary, args, input)
	}
	if len(args) != 1 || args[0] != "reload" || len(input) != 0 {
		return nil, errors.New("gateway_service_command_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("gateway_wireless_reload_failed")
	}
	return nil, nil
}

func parseUCI(data []byte) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			out[key] = strings.Trim(value, "'")
		}
	}
	return out
}

func (b *UCIBackend) get(ctx context.Context, key string) (string, error) {
	data, err := b.Runner.Run(ctx, "/sbin/uci", []string{"-q", "get", key}, nil)
	if err != nil || len(data) > 1024 {
		return "", errors.New("gateway_ap_setting_unavailable")
	}
	// uci get writes the literal value followed by one newline, avoiding the
	// escaped display representation returned by uci show for quotes/backslashes.
	return strings.TrimSuffix(string(data), "\n"), nil
}

func cleanText(value string, min, max int) bool {
	return len(value) >= min && len(value) <= max &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func (b *UCIBackend) accessPoint(
	ctx context.Context,
	section string,
	wireless map[string]string,
) (AccessPoint, error) {
	a := AccessPoint{Section: section, CandidateModes: []string{}}
	key := "wireless." + section
	if !platform.ValidInterfaceName(section) || wireless[key] != "wifi-iface" ||
		wireless[key+".mode"] != "ap" ||
		wireless[key+".disabled"] == "1" {
		return a, errors.New("gateway_existing_enabled_ap_required")
	}
	a.Radio, a.Network, a.Encryption = wireless[key+".device"], wireless[key+".network"], wireless[key+".encryption"]
	if !platform.ValidInterfaceName(a.Radio) || !platform.ValidInterfaceName(a.Network) ||
		wireless["wireless."+a.Radio] != "wifi-device" {
		return a, errors.New("gateway_ap_scope_ambiguous")
	}
	var err error
	a.SSID, err = b.get(ctx, key+".ssid")
	if err != nil || !cleanText(a.SSID, 1, 32) {
		return a, errors.New("gateway_ap_ssid_invalid")
	}
	a.Channel, _ = strconv.Atoi(wireless["wireless."+a.Radio+".channel"])
	// Reusing a fixed channel preserves the original gateway radio settings.
	// Dynamic-channel coordination is not silently substituted with a guess.
	if a.Channel < 1 || a.Channel > 233 {
		a.Reason = "A fixed, verified channel is required before pairing the backhaul."
		return a, nil
	}
	if a.Encryption != "psk2+ccmp" && a.Encryption != "psk2+aes" {
		a.Reason = "This managed profile requires an existing WPA2-CCMP network; stronger or different authentication is never downgraded silently."
		return a, nil
	}
	a.CandidateModes = []string{"wds", "mesh"}
	a.Reason = "Encrypted configuration candidates only. The paired devices must separately verify radio and backhaul compatibility."
	return a, nil
}

func (b *UCIBackend) Inspect(ctx context.Context) (Setup, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := Setup{
		ObservedAt: time.Now().UTC(),
		APs:        []AccessPoint{},
		Managed:    true,
		Reason:     "Only explicitly adopted existing access points can supply settings; no routing or address services are changed.",
	}
	if checker, ok := b.Runner.(interface{ Available() bool }); ok && !checker.Available() {
		out.Managed = false
		out.Reason = "The OpenWrt Wi-Fi reload tool is unavailable."
	}
	data, err := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
	if err != nil {
		return out, errors.New("gateway_wireless_discovery_failed")
	}
	wireless := parseUCI(data)
	for key, kind := range wireless {
		if kind != "wifi-iface" {
			continue
		}
		section := strings.TrimPrefix(key, "wireless.")
		if a, err := b.accessPoint(ctx, section, wireless); err == nil {
			out.APs = append(out.APs, a)
		}
	}
	sort.Slice(out.APs, func(i, j int) bool { return out.APs[i].Section < out.APs[j].Section })
	return out, nil
}

// RadioForPlan resolves the existing AP selected by a typed plan without reading
// its key. Eligibility checks bind the root-owned receipt to this actual radio.
func (b *UCIBackend) RadioForPlan(ctx context.Context, p Plan) (string, error) {
	if err := ValidatePlan(p); err != nil {
		return "", err
	}
	setup, err := b.Inspect(ctx)
	if err != nil {
		return "", err
	}
	for _, ap := range setup.APs {
		if ap.Section == p.APSection && ap.Network == p.Network {
			return ap.Radio, nil
		}
	}
	return "", errors.New("gateway_adopted_ap_missing")
}

func (b *UCIBackend) Check(ctx context.Context, p Plan) (WiFi, error) {
	var out WiFi
	if err := ValidatePlan(p); err != nil {
		return out, err
	}
	if b.Eligibility == nil || b.Eligibility(ctx, p) != nil {
		return out, errors.New("gateway_pair_compatibility_unverified")
	}
	if checker, ok := b.Runner.(interface{ Available() bool }); ok && !checker.Available() {
		return out, errors.New("gateway_wifi_tool_missing")
	}
	data, err := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
	if err != nil {
		return out, errors.New("gateway_wireless_discovery_failed")
	}
	w := parseUCI(data)
	if w["wireless."+p.APSection+".wds"] == "1" &&
		w["wireless."+p.APSection+".openrhp_wds_owner"] != "1" {
		return out, errors.New("gateway_existing_wds_requires_separate_adoption")
	}
	a, err := b.accessPoint(ctx, p.APSection, w)
	if err != nil || a.Network != p.Network || len(a.CandidateModes) == 0 {
		return out, errors.New("gateway_ap_configuration_incompatible")
	}
	if w["wireless."+meshSection] != "" && w["wireless."+meshSection+".openrhp_owner"] != "1" {
		return out, errors.New("gateway_wireless_ownership_conflict")
	}
	if w["wireless."+meshSection+".openrhp_owner"] == "1" &&
		(w["wireless."+meshSection+".device"] != a.Radio || w["wireless."+meshSection+".network"] != p.Network) {
		return out, errors.New("gateway_backhaul_scope_conflict")
	}
	// A previously owned section may have been customized since prepare. Never
	// overwrite unknown fields during a mode change or its later rollback.
	if _, err := b.Snapshot(ctx, p); err != nil {
		return out, err
	}
	data, err = b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "network"}, nil)
	if err != nil {
		return out, errors.New("gateway_network_discovery_failed")
	}
	n := parseUCI(data)
	nkey := "network." + p.Network
	bridge := false
	for key, kind := range n {
		if kind == "device" && n[key+".type"] == "bridge" && n[key+".name"] == n[nkey+".device"] {
			bridge = true
		}
	}
	if n[nkey] != "interface" || n[nkey+".proto"] != "static" || n[nkey+".gateway"] != "" ||
		!bridge {
		return out, errors.New("gateway_existing_lan_bridge_required")
	}
	secret, err := b.get(ctx, "wireless."+p.APSection+".key")
	if err != nil || !cleanText(secret, 8, 63) {
		return out, errors.New("gateway_ap_credential_incompatible")
	}
	return WiFi{SSID: a.SSID, Passphrase: secret, Channel: a.Channel}, nil
}

func quoteUCI(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func (b *UCIBackend) Apply(ctx context.Context, p Plan) error {
	wifi, err := b.Check(ctx, p)
	if err != nil {
		return err
	}
	set := func(key, value string, secret bool) error {
		args, input := []string{"set", key + "=" + value}, []byte(nil)
		if secret {
			args, input = []string{"-q", "batch"}, []byte("set "+key+"="+quoteUCI(value)+"\n")
		}
		if _, err := b.Runner.Run(ctx, "/sbin/uci", args, input); err != nil {
			return errors.New("gateway_wireless_update_failed")
		}
		return nil
	}
	if p.Mode == "wds" {
		data, err := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
		if err != nil {
			return errors.New("gateway_wireless_discovery_failed")
		}
		if parseUCI(data)["wireless."+meshSection] != "" {
			if _, err := b.Runner.Run(
				ctx,
				"/sbin/uci",
				[]string{"delete", "wireless." + meshSection},
				nil,
			); err != nil {
				return errors.New("gateway_previous_backhaul_disable_failed")
			}
		}
		if err := set("wireless."+p.APSection+".openrhp_wds_owner", "1", false); err != nil {
			return err
		}
		if err := set("wireless."+p.APSection+".wds", "1", false); err != nil {
			return err
		}
	} else {
		if err := set("wireless."+p.APSection+".wds", "0", false); err != nil {
			return err
		}
		radio, err := b.get(ctx, "wireless."+p.APSection+".device")
		if err != nil || !platform.ValidInterfaceName(radio) {
			return errors.New("gateway_ap_radio_invalid")
		}
		key := "wireless." + meshSection
		values := [][2]string{
			{key, "wifi-iface"},
			{key + ".openrhp_owner", "1"},
			{key + ".device", radio},
			{key + ".mode", "mesh"},
			{key + ".network", p.Network},
			{key + ".mesh_id", wifi.SSID},
			{key + ".encryption", "sae"},
			{key + ".disabled", "0"},
		}
		for _, item := range values {
			if err := set(item[0], item[1], false); err != nil {
				return err
			}
		}
		if err := set(key+".key", wifi.Passphrase, true); err != nil {
			return err
		}
	}
	return b.reload(ctx)
}

func (b *UCIBackend) reload(ctx context.Context) error {
	if _, err := b.Runner.Run(ctx, "/sbin/uci", []string{"commit", "wireless"}, nil); err != nil {
		return errors.New("gateway_wireless_commit_failed")
	}
	if _, err := b.Runner.Run(ctx, "/sbin/wifi", []string{"reload"}, nil); err != nil {
		return errors.New("gateway_wireless_reload_failed")
	}
	return nil
}
