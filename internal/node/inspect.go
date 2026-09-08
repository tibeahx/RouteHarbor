package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

type BridgeSetup struct {
	Interface              string   `json:"interface"`
	Section                string   `json:"section"`
	Device                 string   `json:"device"`
	Address                string   `json:"address"`
	Gateway                string   `json:"gateway"`
	Ports                  []string `json:"ports"`
	InactiveEthernetUplink string   `json:"inactive_ethernet_uplink,omitempty"`
}
type RadioSetup struct {
	Name          string `json:"name"`
	Channel       int    `json:"channel"`
	ForeignActive bool   `json:"foreign_active"`
}
type Setup struct {
	ObservedAt       time.Time          `json:"observed_at"`
	Bridges          []BridgeSetup      `json:"bridges"`
	Radios           []RadioSetup       `json:"radios"`
	Issues           []string           `json:"issues"`
	WirelessEvidence []WirelessEvidence `json:"wireless_evidence"`
}

type WirelessEvidence struct {
	PHY             string   `json:"phy"`
	AdvertisedModes []string `json:"advertised_modes"`
	PeerVerified    bool     `json:"peer_verified"`
	Reason          string   `json:"reason"`
}

// iw reports driver advertisements, not successful encrypted bridging between
// two routers. These observations never set WDS/mesh readiness capabilities.
func ParseWirelessEvidence(data []byte) []WirelessEvidence {
	out := []WirelessEvidence{}
	current := -1
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Wiphy ") {
			phy := strings.TrimPrefix(line, "Wiphy ")
			if !platform.ValidInterfaceName(phy) {
				current = -1
				continue
			}
			out = append(
				out,
				WirelessEvidence{
					PHY:             phy,
					AdvertisedModes: []string{},
					Reason:          "Driver advertisement only. Encrypted peer interoperability, a ready gateway backhaul, and safe concurrent AP/backhaul operation remain unverified.",
				},
			)
			current = len(out) - 1
			seen = map[string]bool{}
			continue
		}
		if current < 0 {
			continue
		}
		mode := ""
		switch line {
		case "* AP":
			mode = "AP"
		case "* managed":
			mode = "station"
		case "* mesh point":
			mode = "mesh"
		}
		if mode != "" && !seen[mode] {
			out[current].AdvertisedModes = append(out[current].AdvertisedModes, mode)
			seen[mode] = true
		}
	}
	return out
}

// Inspect exposes an allowlist of discovered settings, never the UCI export,
// Wi-Fi keys, API tokens, or unrelated configuration values.
func (b *UCIBackend) Inspect(ctx context.Context) (Setup, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	setup := Setup{
		ObservedAt: time.Now().UTC(),
		Bridges:    []BridgeSetup{},
		Radios:     []RadioSetup{},
		Issues:     []string{},
	}
	setup.WirelessEvidence = []WirelessEvidence{}
	if checker, ok := b.Runner.(interface{ Available(string) error }); ok {
		for _, service := range []string{"/etc/init.d/dnsmasq", "/etc/init.d/odhcpd"} {
			if checker.Available(service) != nil {
				setup.Issues = append(
					setup.Issues,
					"Bridge conversion requires the existing dnsmasq and odhcpd service tools. Pairing and read-only status remain available.",
				)
				break
			}
		}
	}
	data, e := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "network"}, nil)
	if e != nil {
		return setup, errors.New("node_network_discovery_failed")
	}
	network := parseUCI(data)
	for key, kind := range network {
		if kind != "interface" || network[key+".proto"] != "static" {
			continue
		}
		logical := strings.TrimPrefix(key, "network.")
		if !platform.ValidInterfaceName(logical) {
			continue
		}
		device := network[key+".device"]
		section := ""
		for name, kind := range network {
			if kind == "device" && network[name+".type"] == "bridge" &&
				network[name+".name"] == device {
				section = strings.TrimPrefix(name, "network.")
			}
		}
		if !platform.ValidInterfaceName(section) || !platform.ValidInterfaceName(device) {
			continue
		}
		address := network[key+".ipaddr"]
		if !strings.Contains(address, "/") {
			mask := net.ParseIP(network[key+".netmask"]).To4()
			if mask != nil {
				ones, bits := net.IPMask(mask).Size()
				if bits == 32 {
					address += "/" + strconv.Itoa(ones)
				}
			}
		}
		if _, e := netip.ParsePrefix(address); e != nil {
			continue
		}
		ports := []string{}
		seen := map[string]bool{}
		for _, port := range strings.Fields(strings.ReplaceAll(network["network."+section+".ports"], "' '", " ")) {
			port = strings.Trim(port, "'")
			if platform.ValidInterfaceName(port) && !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
		reserved := network["network."+section+".openrhp_disabled_uplink"]
		if reserved != "" && platform.ValidInterfaceName(reserved) && !seen[reserved] {
			ports = append(ports, reserved)
		}
		setup.Bridges = append(
			setup.Bridges,
			BridgeSetup{
				Interface:              logical,
				Section:                section,
				Device:                 device,
				Address:                address,
				Gateway:                network[key+".gateway"],
				Ports:                  ports,
				InactiveEthernetUplink: reserved,
			},
		)
	}
	if len(setup.Bridges) == 0 {
		setup.Issues = append(
			setup.Issues,
			"Reserve a static management address on an existing LAN bridge through trusted administrator access before applying coverage.",
		)
	}
	data, e = b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
	if e == nil {
		wireless := parseUCI(data)
		for key, kind := range wireless {
			if kind != "wifi-device" {
				continue
			}
			name := strings.TrimPrefix(key, "wireless.")
			if !platform.ValidInterfaceName(name) {
				continue
			}
			channel, _ := strconv.Atoi(wireless[key+".channel"])
			radio := RadioSetup{Name: name, Channel: channel}
			for iface, kind := range wireless {
				if kind == "wifi-iface" && wireless[iface+".device"] == name &&
					wireless[iface+".disabled"] != "1" &&
					wireless[iface+".openrhp_owner"] != "1" {
					radio.ForeignActive = true
				}
			}
			setup.Radios = append(setup.Radios, radio)
		}
	} else {
		setup.Issues = append(
			setup.Issues,
			"Wireless settings could not be inspected; keep the existing radio configuration.",
		)
	}
	data, e = b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "firewall"}, nil)
	if e != nil {
		return setup, errors.New("node_firewall_discovery_failed")
	}
	for key, value := range parseUCI(data) {
		if (strings.HasSuffix(key, ".masq") || strings.HasSuffix(key, ".masq6")) && value == "1" {
			setup.Issues = append(
				setup.Issues,
				"This device still performs NAT. Resolve the router-to-access-point conversion during explicit preflight before applying coverage.",
			)
			break
		}
	}
	sort.Slice(
		setup.Bridges,
		func(i, j int) bool { return setup.Bridges[i].Interface < setup.Bridges[j].Interface },
	)
	sort.Slice(
		setup.Radios,
		func(i, j int) bool { return setup.Radios[i].Name < setup.Radios[j].Name },
	)
	if radioData, radioErr := b.Runner.Run(
		ctx,
		"/usr/sbin/iw",
		[]string{"phy"},
		nil,
	); radioErr == nil {
		setup.WirelessEvidence = ParseWirelessEvidence(radioData)
	}
	return setup, nil
}

func (m *Manager) Inspect(ctx context.Context) (map[string]any, error) {
	var setup Setup
	e := m.locked(func(*journal) error {
		backend, ok := m.backend.(interface {
			Inspect(context.Context) (Setup, error)
		})
		if !ok {
			return errors.New("node_setup_discovery_unavailable")
		}
		var err error
		setup, err = backend.Inspect(ctx)
		return err
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"setup": setup}, nil
}
