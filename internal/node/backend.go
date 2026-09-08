package node

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

type (
	Snapshot map[string][]byte
	Backend  interface {
		Check(context.Context, Plan) error
		Snapshot(context.Context) (Snapshot, error)
		Apply(context.Context, Plan) error
		Restore(context.Context, Snapshot, Plan) error
	}
)

type UCIBackend struct {
	Runner       platform.Runner
	Capabilities func(context.Context) Capabilities
	ReadFile     func(string) ([]byte, error)
}

func NewUCIBackend() *UCIBackend {
	return &UCIBackend{
		Runner:       nodeRunner{},
		Capabilities: func(ctx context.Context) Capabilities { return CapabilitiesFrom(platform.Detect(ctx)) },
	}
}

func (b *UCIBackend) ReportCapabilities(ctx context.Context) Capabilities {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return b.Capabilities(ctx)
}

var packages = []string{"network", "wireless", "dhcp", "firewall"}

func (b *UCIBackend) Check(ctx context.Context, p Plan) error {
	caps := b.Capabilities(ctx)
	// Gateway readiness is checked by the authenticated gateway service. This
	// local privileged boundary independently verifies the node capabilities.
	gateway := caps
	gateway.GatewayBackhaulReady = true
	if e := ValidatePlan(p, gateway, caps); e != nil {
		return e
	}
	network, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "network"}, nil)
	if e != nil {
		return errors.New("node_network_discovery_failed")
	}
	n := parseUCI(network)
	if n["network."+p.ManagementInterface] != "interface" ||
		n["network."+p.BridgeSection] != "device" ||
		n["network."+p.BridgeSection+".type"] != "bridge" ||
		n["network."+p.BridgeSection+".name"] != p.BridgeDevice ||
		n["network."+p.ManagementInterface+".device"] != p.BridgeDevice {
		return errors.New(
			"management_bridge_mismatch: only the discovered management bridge may be changed",
		)
	}
	if n["network."+p.ManagementInterface+".proto"] != "static" {
		return errors.New(
			"static_management_required: reserve the node management address before changing coverage",
		)
	}
	// Keep the verified management address throughout apply and rollback. Address
	// reassignment is intentionally separate from a backhaul transaction.
	address, _, _ := strings.Cut(p.ManagementAddress, "/")
	if n["network."+p.ManagementInterface+".ipaddr"] != p.ManagementAddress &&
		n["network."+p.ManagementInterface+".ipaddr"] != address {
		return errors.New(
			"management_address_mismatch: retain the currently verified management address",
		)
	}
	existingPorts := strings.Fields(
		strings.ReplaceAll(n["network."+p.BridgeSection+".ports"], "' '", " "),
	)
	ports := map[string]bool{}
	for _, port := range existingPorts {
		ports[strings.Trim(port, "'")] = true
	}
	if reserved := n["network."+p.BridgeSection+".openrhp_disabled_uplink"]; reserved != "" {
		ports[reserved] = true
	}
	for _, port := range p.LANPorts {
		if !ports[port] {
			return errors.New(
				"port_ownership_conflict: only ports already owned by the management bridge are supported",
			)
		}
	}
	if len(ports) != len(p.LANPorts) {
		return errors.New("management_port_removal: preserve every existing management bridge port")
	}
	dhcp, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "dhcp"}, nil)
	if e != nil {
		return errors.New("dhcp_discovery_failed")
	}
	d := parseUCI(dhcp)
	for key, value := range d {
		if value == "dhcp" && d[key+".interface"] != p.ManagementInterface &&
			d[key+".ignore"] != "1" {
			return errors.New(
				"competing_dhcp: disable or explicitly migrate unrelated DHCP scopes before node adoption",
			)
		}
	}
	firewall, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "firewall"}, nil)
	if e != nil {
		return errors.New("firewall_discovery_failed")
	}
	fw := parseUCI(firewall)
	for key, value := range fw {
		if strings.HasSuffix(key, ".masq") && value == "1" ||
			strings.HasSuffix(key, ".masq6") && value == "1" {
			return errors.New(
				"competing_nat: remove node masquerading during explicit preflight before adopting the bridge",
			)
		}
	}
	wireless, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
	if e != nil {
		return errors.New("wireless_discovery_failed")
	}
	w := parseUCI(wireless)
	for _, name := range []string{"wireless.openrhp_ap", "wireless.openrhp_backhaul"} {
		if w[name] != "" && w[name+".openrhp_owner"] != "1" {
			return errors.New("wireless_ownership_conflict")
		}
	}
	if p.Radio != "" {
		if w["wireless."+p.Radio] != "wifi-device" {
			return errors.New("wireless_radio_missing")
		}
		for key, value := range w {
			if value == "wifi-iface" && w[key+".device"] == p.Radio &&
				key != "wireless.openrhp_ap" &&
				key != "wireless.openrhp_backhaul" &&
				w[key+".disabled"] != "1" {
				return errors.New(
					"wireless_ownership_conflict: explicit adoption of existing radio settings is required",
				)
			}
		}
	}
	if checker, ok := b.Runner.(interface{ Available(string) error }); ok {
		for _, service := range []string{"/etc/init.d/dnsmasq", "/etc/init.d/odhcpd"} {
			if checker.Available(service) != nil {
				return errors.New(
					"node_service_tools_missing: bridge conversion requires the existing dnsmasq and odhcpd service tools",
				)
			}
		}
		if p.Radio != "" || w["wireless.openrhp_backhaul"] != "" {
			if checker.Available("/sbin/wifi") != nil {
				return errors.New(
					"node_wifi_tool_missing: radio changes require the existing OpenWrt wifi tool",
				)
			}
		}
	}
	return nil
}

func parseUCI(data []byte) map[string]string {
	values := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "'")
		}
	}
	return values
}

func (b *UCIBackend) Snapshot(ctx context.Context) (Snapshot, error) {
	out := Snapshot{}
	for _, name := range packages {
		data, e := b.Runner.Run(ctx, "/sbin/uci", []string{"export", name}, nil)
		if e != nil || len(data) == 0 || len(data) > 256<<10 {
			return nil, errors.New("node_snapshot_failed")
		}
		out[name] = data
	}
	return out, nil
}

// All commands use fixed executables. Secret assignments enter a strictly
// quoted UCI stdin record; passphrases never become process arguments.
func (b *UCIBackend) Apply(ctx context.Context, p Plan) error {
	if e := b.Check(ctx, p); e != nil {
		return e
	}
	wirelessChanged := p.Radio != ""
	set := func(key, value string) error {
		args := []string{"set", key + "=" + value}
		var input []byte
		if key == "wireless.openrhp_ap.key" || key == "wireless.openrhp_backhaul.key" {
			args = []string{"-q", "batch"}
			input = []byte("set " + key + "=" + uciQuote(value) + "\n")
		}
		_, e := b.Runner.Run(ctx, "/sbin/uci", args, input)
		if e != nil {
			return errors.New("node_uci_set_failed")
		}
		return nil
	}
	values := [][2]string{
		{"network." + p.ManagementInterface + ".gateway", p.GatewayAddress},
		{"network." + p.ManagementInterface + ".dns", p.GatewayAddress},
	}
	// Disable the other uplink before enabling the new one. For Wi-Fi the
	// explicitly designated Ethernet backhaul port leaves the bridge; clients on
	// every other port remain bridged. Returning to Ethernet removes owned Wi-Fi.
	if _, e := b.Runner.Run(
		ctx,
		"/sbin/uci",
		[]string{"delete", "network." + p.BridgeSection + ".ports"},
		nil,
	); e != nil {
		return errors.New("node_bridge_update_failed")
	}
	for _, port := range p.LANPorts {
		if p.Mode != "ethernet" && port == p.EthernetUplink {
			continue
		}
		if _, e := b.Runner.Run(
			ctx,
			"/sbin/uci",
			[]string{"add_list", "network." + p.BridgeSection + ".ports=" + port},
			nil,
		); e != nil {
			return errors.New("node_bridge_update_failed")
		}
	}
	reserved := ""
	if p.Mode != "ethernet" {
		reserved = p.EthernetUplink
	}
	values = append(
		values,
		[2]string{"network." + p.BridgeSection + ".openrhp_disabled_uplink", reserved},
	)
	if p.Mode == "ethernet" {
		wireless, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
		if e != nil {
			return errors.New("wireless_discovery_failed")
		}
		if parseUCI(wireless)["wireless.openrhp_backhaul"] != "" {
			wirelessChanged = true
			if _, e = b.Runner.Run(
				ctx,
				"/sbin/uci",
				[]string{"delete", "wireless.openrhp_backhaul"},
				nil,
			); e != nil {
				return errors.New("node_backhaul_disable_failed")
			}
		}
	}
	dhcp, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "dhcp"}, nil)
	if e != nil {
		return errors.New("dhcp_discovery_failed")
	}
	d := parseUCI(dhcp)
	for key, value := range d {
		if value == "dhcp" && d[key+".interface"] == p.ManagementInterface {
			values = append(
				values,
				[2]string{key + ".ignore", "1"},
				[2]string{key + ".ra", "disabled"},
				[2]string{key + ".dhcpv6", "disabled"},
				[2]string{key + ".ndp", "disabled"},
			)
		}
	}
	if p.Radio != "" {
		values = append(
			values,
			[2]string{"wireless." + p.Radio + ".channel", fmt.Sprint(p.Channel)},
			[2]string{"wireless.openrhp_ap", "wifi-iface"},
			[2]string{"wireless.openrhp_ap.openrhp_owner", "1"},
			[2]string{"wireless.openrhp_ap.device", p.Radio},
			[2]string{"wireless.openrhp_ap.mode", "ap"},
			[2]string{"wireless.openrhp_ap.network", p.ManagementInterface},
			[2]string{"wireless.openrhp_ap.ssid", p.SSID},
			[2]string{"wireless.openrhp_ap.encryption", "psk2+ccmp"},
			[2]string{"wireless.openrhp_ap.key", p.Passphrase},
			[2]string{"wireless.openrhp_ap.disabled", "0"},
		)
		if p.Mode == "wds" || p.Mode == "mesh" {
			mode, encryption := "sta", "psk2+ccmp"
			if p.Mode == "mesh" {
				mode = "mesh"
				encryption = "sae"
			}
			values = append(
				values,
				[2]string{"wireless.openrhp_backhaul", "wifi-iface"},
				[2]string{"wireless.openrhp_backhaul.openrhp_owner", "1"},
				[2]string{"wireless.openrhp_backhaul.device", p.Radio},
				[2]string{"wireless.openrhp_backhaul.mode", mode},
				[2]string{"wireless.openrhp_backhaul.network", p.ManagementInterface},
				[2]string{"wireless.openrhp_backhaul.encryption", encryption},
				[2]string{"wireless.openrhp_backhaul.key", p.Passphrase},
				[2]string{"wireless.openrhp_backhaul.disabled", "0"},
			)
			if p.Mode == "wds" {
				values = append(
					values,
					[2]string{"wireless.openrhp_backhaul.wds", "1"},
					[2]string{"wireless.openrhp_backhaul.ssid", p.SSID},
				)
			} else {
				values = append(values, [2]string{"wireless.openrhp_backhaul.mesh_id", p.SSID})
			}
		}
	}
	for _, v := range values {
		if e = set(v[0], v[1]); e != nil {
			return e
		}
	}
	return b.commitReload(ctx, wirelessChanged)
}

// UCI's own exporter uses the same single-quote escape sequence. Quoted
// backslashes and metacharacters remain data. Validation rejects controls; the
// passphrase enters UCI only through stdin and never appears in process argv.
func uciQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (b *UCIBackend) Restore(ctx context.Context, s Snapshot, p Plan) error {
	if len(s) != len(packages) {
		return errors.New("invalid_node_snapshot")
	}
	for _, name := range packages {
		data, ok := s[name]
		if !ok || len(data) == 0 || len(data) > 256<<10 {
			return errors.New("invalid_node_snapshot")
		}
	}
	for _, name := range packages {
		data := s[name]
		if _, e := b.Runner.Run(ctx, "/sbin/uci", []string{"import", name}, data); e != nil {
			return errors.New("node_restore_import_failed")
		}
	}
	wireless := p.Radio != ""
	for line := range strings.SplitSeq(string(s["wireless"]), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "config" &&
			strings.Trim(fields[1], "'\"") == "wifi-iface" &&
			strings.Trim(fields[2], "'\"") == "openrhp_backhaul" {
			wireless = true
		}
	}
	return b.commitReload(ctx, wireless)
}

func (b *UCIBackend) commitReload(ctx context.Context, wireless bool) error {
	for _, name := range packages {
		if _, e := b.Runner.Run(ctx, "/sbin/uci", []string{"commit", name}, nil); e != nil {
			return errors.New("node_uci_commit_failed")
		}
	}
	commands := []struct {
		path string
		args []string
	}{{platform.UBusBinary(), []string{"call", "network", "reload"}}, {"/etc/init.d/dnsmasq", []string{"restart"}}, {"/etc/init.d/odhcpd", []string{"restart"}}}
	if wireless {
		commands = append(commands, struct {
			path string
			args []string
		}{"/sbin/wifi", []string{"reload"}})
	}
	for _, command := range commands {
		if _, e := b.Runner.Run(ctx, command.path, command.args, nil); e != nil {
			return errors.New("node_network_reload_failed")
		}
	}
	return nil
}
