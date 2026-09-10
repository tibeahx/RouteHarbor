package wireless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

type interfaceState struct {
	Name   string `json:"ifname"`
	Config struct {
		Mode       string `json:"mode"`
		Encryption string `json:"encryption"`
		WDS        any    `json:"wds"`
	} `json:"config"`
}

type radioState struct {
	Up       bool `json:"up"`
	Disabled bool `json:"disabled"`
	Config   struct {
		Path string `json:"path"`
		PHY  string `json:"phy"`
	} `json:"config"`
	Interfaces []interfaceState `json:"interfaces"`
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("wireless_platform_evidence_unavailable")
	}
	return data, nil
}

func inspectRadio(ctx context.Context, radio string) (radioState, error) {
	if !platform.ValidInterfaceName(radio) {
		return radioState{}, errors.New("invalid_wireless_radio")
	}
	data, err := (platform.ProductionRunner{}).Run(
		ctx,
		platform.UBusBinary(),
		[]string{"call", "network.wireless", "status"},
		nil,
	)
	if err != nil {
		return radioState{}, errors.New("wireless_status_unavailable")
	}
	var radios map[string]radioState
	if json.Unmarshal(data, &radios) != nil {
		return radioState{}, errors.New("wireless_status_invalid")
	}
	state, ok := radios[radio]
	if !ok || !state.Up || state.Disabled || len(state.Interfaces) == 0 ||
		len(state.Interfaces) > 64 {
		return radioState{}, errors.New("wireless_radio_not_active")
	}
	return state, nil
}

var wiphyPattern = regexp.MustCompile(`(?m)^\s*wiphy ([0-9]{1,4})\s*$`)

func interfaceInfo(ctx context.Context, iface string) ([]byte, error) {
	if !platform.ValidInterfaceName(iface) {
		return nil, errors.New("invalid_wireless_interface")
	}
	return (platform.ProductionRunner{}).Run(
		ctx,
		"/usr/sbin/iw",
		[]string{"dev", iface, "info"},
		nil,
	)
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CollectBinding only collects local, nonsecret version and radio information.
// It deliberately does not treat an advertised mode as verified interoperability.
func CollectBinding(ctx context.Context, radio string) (Binding, error) {
	var binding Binding
	release, err := readBounded("/etc/openwrt_release")
	if err != nil || !strings.Contains(string(release), "OpenWrt") {
		return binding, errors.New("wireless_verification_requires_openwrt")
	}
	kernel, err := readBounded("/proc/sys/kernel/osrelease")
	if err != nil {
		return binding, errors.New("kernel_identity_unavailable")
	}
	board, err := readBounded("/tmp/sysinfo/board_name")
	if err != nil || len(strings.TrimSpace(string(board))) == 0 {
		return binding, errors.New("board_identity_unavailable")
	}
	radioState, err := inspectRadio(ctx, radio)
	if err != nil {
		return binding, err
	}
	var phy string
	for _, iface := range radioState.Interfaces {
		info, infoErr := interfaceInfo(ctx, iface.Name)
		if infoErr != nil {
			continue
		}
		match := wiphyPattern.FindSubmatch(info)
		if len(match) == 2 {
			phy = "phy" + string(match[1])
			break
		}
	}
	if phy == "" {
		return binding, errors.New("radio_phy_binding_unavailable")
	}
	capabilities, err := (platform.ProductionRunner{}).Run(
		ctx,
		"/usr/sbin/iw",
		[]string{"phy", phy, "info"},
		nil,
	)
	if err != nil || len(capabilities) == 0 {
		return binding, errors.New("radio_capabilities_unavailable")
	}
	driver, err := os.Readlink("/sys/class/ieee80211/" + phy + "/device/driver")
	if err != nil || driver == "" {
		return binding, errors.New("radio_driver_identity_unavailable")
	}
	radioPath := radioState.Config.Path
	if radioPath == "" {
		radioPath = radioState.Config.PHY
	}
	if radioPath == "" {
		return binding, errors.New("radio_device_path_unavailable")
	}
	return Binding{
		OpenWrtDigest: digest(
			release,
		),
		Kernel:                strings.TrimSpace(string(kernel)),
		Board:                 strings.TrimSpace(string(board)),
		PHY:                   phy,
		Driver:                driver,
		RadioPath:             radioPath,
		PHYCapabilitiesDigest: digest(capabilities),
	}, nil
}

func enabled(value any) bool {
	return value == true || value == "1" || value == float64(1)
}

func encrypted(value string) bool {
	switch value {
	case "psk2", "psk2+ccmp", "sae", "sae-mixed", "sae-mixed+ccmp":
		return true
	}
	return false
}

// collectLiveProof confirms the specified radio/interface has an encrypted
// configuration and the named live peer. Client DHCP/bridging/recovery still
// require the separately explicit operator attestations recorded in Checks.
func collectLiveProof(
	ctx context.Context,
	role, radio, iface, mode, peerMAC string,
) (string, error) {
	mac, err := net.ParseMAC(peerMAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return "", errors.New("a_unicast_peer_mac_is_required")
	}
	state, err := inspectRadio(ctx, radio)
	if err != nil {
		return "", err
	}
	var selected *interfaceState
	hasAP := false
	for i := range state.Interfaces {
		candidate := &state.Interfaces[i]
		if candidate.Name == iface {
			selected = candidate
		}
		if candidate.Config.Mode == "ap" && encrypted(candidate.Config.Encryption) {
			hasAP = true
		}
	}
	if selected == nil || !encrypted(selected.Config.Encryption) || !hasAP {
		return "", errors.New("active_encrypted_peer_interface_and_client_ap_required")
	}
	if mode == "mesh" && (selected.Config.Mode != "mesh" || selected.Config.Encryption != "sae") {
		return "", errors.New("active_sae_mesh_interface_required")
	}
	if mode == "wds" {
		expected := "ap"
		if role == "node" {
			expected = "sta"
		}
		if selected.Config.Mode != expected || !enabled(selected.Config.WDS) {
			return "", errors.New("active_wds_interface_required")
		}
	}
	info, err := interfaceInfo(ctx, iface)
	if err != nil {
		return "", errors.New("wireless_live_interface_unavailable")
	}
	if role == "node" && mode == "wds" {
		fourAddress, commandErr := (platform.ProductionRunner{}).Run(
			ctx,
			"/usr/sbin/iw",
			[]string{"dev", iface, "get", "4addr"},
			nil,
		)
		if commandErr != nil || !strings.Contains(string(fourAddress), "4addr: on") {
			return "", errors.New("active_four_address_station_required")
		}
	}
	station, err := (platform.ProductionRunner{}).Run(
		ctx,
		"/usr/sbin/iw",
		[]string{"dev", iface, "station", "get", mac.String()},
		nil,
	)
	if err != nil ||
		!strings.Contains(strings.ToLower(string(station)), "station "+mac.String()+" ") {
		return "", errors.New("named_wireless_peer_is_not_connected")
	}
	if mode == "mesh" && !strings.Contains(string(station), "ESTAB") {
		return "", errors.New("mesh_peer_link_is_not_established")
	}
	if mode == "wds" && !regexp.MustCompile(`(?m)^\s*authorized:\s*yes\s*$`).Match(station) {
		return "", errors.New("wireless_peer_is_not_authorized")
	}
	return digest([]byte(fmt.Sprintf("%s\n%s\n%s", mode, info, station))), nil
}
