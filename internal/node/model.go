// Package node owns authenticated coverage enrollment and node-local rollback.
// Coverage measurements are intentionally independent from WAN path selection.
package node

import (
	"errors"
	"net/netip"
	"strings"
	"unicode"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

type Capabilities struct {
	OpenWrt                 bool   `json:"openwrt"`
	Ethernet                bool   `json:"ethernet"`
	AP                      bool   `json:"ap"`
	WDS                     bool   `json:"wds"`
	Mesh                    bool   `json:"mesh"`
	EncryptedBackhaul       bool   `json:"encrypted_backhaul"`
	ConcurrentRadio         bool   `json:"concurrent_radio"`
	GatewayBackhaulReady    bool   `json:"gateway_backhaul_ready"`
	GatewayBackhaulManaged  bool   `json:"gateway_backhaul_managed"`
	VerifiedPeerFingerprint string `json:"verified_peer_fingerprint,omitempty"`
	VerifiedRadio           string `json:"verified_radio,omitempty"`
	VerifiedMode            string `json:"verified_mode,omitempty"`
	Reason                  string `json:"reason"`
}

func CapabilitiesFrom(r platform.Report) Capabilities {
	return Capabilities{
		OpenWrt:                 r.OS == "OpenWrt",
		Ethernet:                r.OS == "OpenWrt" && r.Init == "procd",
		AP:                      r.Capabilities["wireless_ap"].Available,
		WDS:                     r.Capabilities["wds"].Available,
		Mesh:                    r.Capabilities["mesh"].Available,
		EncryptedBackhaul:       r.Capabilities["encrypted_backhaul"].Available,
		ConcurrentRadio:         r.Capabilities["concurrent_radio"].Available,
		VerifiedPeerFingerprint: r.VerifiedPeerFingerprint,
		VerifiedRadio:           r.VerifiedRadio,
		VerifiedMode:            r.VerifiedMode,
		Reason:                  "Wireless modes require verified peer compatibility and encrypted backhaul support; an advertised radio feature is insufficient",
	}
}

type Plan struct {
	Name                   string   `json:"name"`
	Mode                   string   `json:"mode"`
	ManagementInterface    string   `json:"management_interface"`
	BridgeSection          string   `json:"bridge_section"`
	BridgeDevice           string   `json:"bridge_device"`
	LANPorts               []string `json:"lan_ports"`
	Uplink                 string   `json:"uplink"`
	EthernetUplink         string   `json:"ethernet_uplink,omitempty"`
	ManagementAddress      string   `json:"management_address"`
	GatewayAddress         string   `json:"gateway_address"`
	Radio                  string   `json:"radio,omitempty"`
	SSID                   string   `json:"ssid,omitempty"`
	Passphrase             string   `json:"passphrase,omitempty"`
	Channel                int      `json:"channel,omitempty"`
	ShareRadio             bool     `json:"share_radio"`
	DHCPServer             bool     `json:"dhcp_server"`
	NAT                    bool     `json:"nat"`
	RouterAdvertisements   bool     `json:"router_advertisements"`
	PreserveManagementPath bool     `json:"preserve_management_path"`
}

// CompatibleModes orders Wi-Fi before Ethernet only after both devices prove
// support. Stock firmware never receives a claim of automatic management.
func CompatibleModes(gateway, peer Capabilities) []string {
	modes := []string{}
	if !gateway.OpenWrt || !peer.OpenWrt {
		return modes
	}
	if gateway.EncryptedBackhaul && peer.EncryptedBackhaul && gateway.AP && peer.AP &&
		gateway.GatewayBackhaulReady {
		if gateway.WDS && peer.WDS {
			modes = append(modes, "wds")
		}
		if gateway.Mesh && peer.Mesh {
			modes = append(modes, "mesh")
		}
	}
	if gateway.Ethernet && peer.Ethernet {
		modes = append(modes, "ethernet")
	}
	return modes
}

func ValidatePlan(p Plan, gateway, peer Capabilities) error {
	if p.Mode != "ethernet" && peer.VerifiedRadio != "" &&
		(p.Radio != peer.VerifiedRadio || p.Mode != peer.VerifiedMode) {
		return errors.New("wireless_verification_radio_or_mode_mismatch")
	}
	allowed := false
	for _, mode := range CompatibleModes(gateway, peer) {
		if p.Mode == mode {
			allowed = true
		}
	}
	if !allowed {
		return errors.New(
			"unsupported_mode: both OpenWrt devices must verify the requested link mode",
		)
	}
	if p.DHCPServer || p.NAT || p.RouterAdvertisements {
		return errors.New(
			"competing_gateway: a coverage node must not provide DHCP, NAT, or router advertisements",
		)
	}
	if !p.PreserveManagementPath {
		return errors.New(
			"management_path_required: retain an independent management path while applying backhaul changes",
		)
	}
	if len(p.Name) == 0 || len(p.Name) > 128 || strings.IndexFunc(p.Name, unicode.IsControl) >= 0 {
		return errors.New("invalid_name")
	}
	for _, name := range []string{p.ManagementInterface, p.BridgeSection, p.BridgeDevice, p.Uplink} {
		if !platform.ValidInterfaceName(name) {
			return errors.New("invalid_interface")
		}
	}
	if len(p.LANPorts) == 0 || len(p.LANPorts) > 64 {
		return errors.New("invalid_lan_ports")
	}
	ports := map[string]bool{}
	for _, port := range p.LANPorts {
		if !platform.ValidInterfaceName(port) || ports[port] || port == "lo" {
			return errors.New("invalid_lan_port")
		}
		ports[port] = true
	}
	if p.Mode == "ethernet" && !ports[p.Uplink] {
		return errors.New("uplink_missing: Ethernet uplink must be one of the bridge ports")
	}
	if p.Mode != "ethernet" && ports[p.Uplink] {
		return errors.New("uplink_loop: only one active uplink is allowed")
	}
	if p.Mode != "ethernet" &&
		(!platform.ValidInterfaceName(p.EthernetUplink) || !ports[p.EthernetUplink]) {
		return errors.New(
			"ethernet_uplink_required: identify the physical uplink port to remove from the bridge before activating Wi-Fi backhaul",
		)
	}
	if p.Mode == "ethernet" && p.EthernetUplink != "" && p.EthernetUplink != p.Uplink {
		return errors.New("uplink_conflict")
	}
	address, e := netip.ParsePrefix(p.ManagementAddress)
	if e != nil || !address.Addr().Is4() || address.Bits() < 8 || address.Bits() > 30 ||
		address.Addr().IsUnspecified() ||
		address.Addr().IsLoopback() ||
		address.Addr().IsMulticast() {
		return errors.New(
			"invalid_management_address: an explicit IPv4 LAN host prefix is required",
		)
	}
	gw, e := netip.ParseAddr(p.GatewayAddress)
	if e != nil || !gw.Is4() || gw == address.Addr() || !address.Contains(gw) ||
		gw == address.Masked().Addr() {
		return errors.New(
			"invalid_gateway_address: gateway must be a different host in the management LAN",
		)
	}
	if p.Radio != "" || p.Mode != "ethernet" {
		if p.Mode != "ethernet" && !p.ShareRadio {
			return errors.New(
				"shared_radio_required: the current single-radio plan serves AP clients and backhaul together",
			)
		}
		if !gateway.AP || !peer.AP || !platform.ValidInterfaceName(p.Radio) || len(p.SSID) < 1 ||
			len(p.SSID) > 32 ||
			len(p.Passphrase) < 8 ||
			len(p.Passphrase) > 63 ||
			strings.IndexFunc(p.SSID+p.Passphrase, unicode.IsControl) >= 0 {
			return errors.New(
				"invalid_wireless_settings: verified AP support and WPA2/WPA3 credentials are required",
			)
		}
		if p.Channel < 1 || p.Channel > 233 {
			return errors.New("invalid_wireless_channel")
		}
		if p.ShareRadio && (!gateway.ConcurrentRadio || !peer.ConcurrentRadio) {
			return errors.New("concurrent_radio_unverified")
		}
	} else if p.SSID != "" || p.Passphrase != "" || p.ShareRadio {
		return errors.New("wireless_radio_required")
	}
	return nil
}

func RedactPlan(p Plan) Plan {
	p.Passphrase = ""
	return p
}
