// Package platform discovers OpenWrt capabilities without changing the network.
package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type Capability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}
type Interface struct {
	Name     string   `json:"name"`
	Device   string   `json:"device"`
	Protocol string   `json:"protocol"`
	Up       bool     `json:"up"`
	Role     string   `json:"role"`
	Prefixes []string `json:"prefixes"`
}
type Report struct {
	Supported            bool                  `json:"supported"`
	OS                   string                `json:"os"`
	Version              string                `json:"version"`
	PackageArch          string                `json:"package_arch"`
	GoArch               string                `json:"go_arch"`
	PackageManager       string                `json:"package_manager"`
	Firewall             string                `json:"firewall"`
	Init                 string                `json:"init"`
	MemoryAvailableBytes uint64                `json:"memory_available_bytes"`
	FlashAvailableBytes  uint64                `json:"flash_available_bytes"`
	Interfaces           []Interface           `json:"interfaces"`
	Capabilities         map[string]Capability `json:"capabilities"`
	Issues               []string              `json:"issues"`
}
type Detector struct {
	OS        string
	ReadFile  func(string) ([]byte, error)
	Runner    Runner
	Exists    func(string) bool
	FreeSpace func(string) uint64
}

func Detect(ctx context.Context) Report {
	d := Detector{
		OS:        runtime.GOOS,
		ReadFile:  os.ReadFile,
		Runner:    ProductionRunner{},
		Exists:    func(p string) bool { _, e := os.Stat(p); return e == nil },
		FreeSpace: freeSpace,
	}
	return d.Detect(ctx)
}

func (d Detector) Detect(ctx context.Context) Report {
	r := Report{
		OS:           d.OS,
		GoArch:       runtime.GOARCH,
		Interfaces:   []Interface{},
		Capabilities: map[string]Capability{},
		Issues:       []string{},
	}
	for _, name := range []string{"transparent_tcp", "transparent_udp", "ipv6", "nfqueue", "tproxy", "proxy_engine", "xray", "wireless_ap", "wds", "mesh", "concurrent_radio", "flow_offload_safe", "lifecycle_guard"} {
		r.Capabilities[name] = Capability{
			Reason: "Not detected; capability must be verified before use",
		}
	}
	if d.OS != "linux" {
		r.Issues = append(
			r.Issues,
			"Network management requires Linux with OpenWrt; control-plane development is available on this host",
		)
		return r
	}
	release, err := d.ReadFile("/etc/openwrt_release")
	if err != nil {
		r.Issues = append(r.Issues, "OpenWrt release metadata is missing")
		return r
	}
	values := parseRelease(string(release))
	r.OS = "OpenWrt"
	r.Version = values["DISTRIB_RELEASE"]
	r.PackageArch = values["DISTRIB_ARCH"]
	if r.Version == "" || r.PackageArch == "" {
		r.Issues = append(r.Issues, "OpenWrt version or package architecture is missing")
	}
	if d.Exists("/sbin/procd") {
		r.Init = "procd"
	} else {
		r.Issues = append(r.Issues, "procd is required")
	}
	if d.Exists("/usr/bin/apk") || d.Exists("/sbin/apk") {
		r.PackageManager = "apk"
	} else if d.Exists("/bin/opkg") {
		r.PackageManager = "opkg"
	}
	if d.Exists("/sbin/fw4") && (d.Exists("/usr/sbin/nft") || d.Exists("/sbin/nft")) {
		r.Firewall = "fw4/nftables"
	} else {
		r.Issues = append(r.Issues, "Only the fw4/nftables firewall backend is implemented")
	}
	dump, err := d.Runner.Run(
		ctx,
		ubusBinary(d.Exists),
		[]string{"call", "network.interface", "dump"},
		nil,
	)
	if err != nil {
		r.Issues = append(r.Issues, "netifd interface discovery failed")
	} else if r.Interfaces, err = ParseInterfaces(dump); err != nil {
		r.Issues = append(r.Issues, "netifd returned invalid interface metadata")
	}
	if len(r.Interfaces) == 0 {
		r.Issues = append(r.Issues, "No netifd interfaces were discovered")
	}
	mem, _ := d.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(mem), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			f := strings.Fields(line)
			if len(f) > 1 {
				v, _ := strconv.ParseUint(f[1], 10, 64)
				r.MemoryAvailableBytes = v * 1024
			}
		}
	}
	if d.FreeSpace != nil {
		r.FlashAvailableBytes = d.FreeSpace("/overlay")
	}
	modules, _ := d.ReadFile("/proc/modules")
	has := func(name string) bool { return strings.Contains("\n"+string(modules), "\n"+name+" ") }
	if has("nft_tproxy") && has("nf_tproxy_ipv4") {
		r.Capabilities["tproxy"] = Capability{
			true,
			"Loaded nft_tproxy and IPv4 transparent-proxy modules detected; nft check is still required",
		}
		r.Capabilities["transparent_tcp"] = r.Capabilities["tproxy"]
		r.Capabilities["transparent_udp"] = r.Capabilities["tproxy"]
	}
	if has("nft_queue") && has("nfnetlink_queue") {
		r.Capabilities["nfqueue"] = Capability{
			true,
			"Loaded NFQUEUE modules detected; per-profile isolation still requires validation",
		}
	}
	if has("nf_tproxy_ipv6") && r.Capabilities["tproxy"].Available {
		r.Capabilities["ipv6"] = Capability{
			true,
			"IPv6 TPROXY kernel support detected; source and DNS support are checked separately",
		}
	}
	for name, path := range map[string]string{"proxy_engine": "/usr/bin/sing-box", "xray": "/usr/bin/xray"} {
		if d.Exists(path) {
			r.Capabilities[name] = Capability{
				true,
				"Installed engine detected; adapter version and configuration checks remain required",
			}
		}
	}
	uci, uciErr := d.Runner.Run(ctx, "/sbin/uci", []string{"-q", "show", "firewall"}, nil)
	if uciErr != nil {
		r.Issues = append(r.Issues, "Cannot verify firewall flow offload settings")
	} else {
		offload := false
		for _, line := range strings.Split(string(uci), "\n") {
			if (strings.Contains(line, ".flow_offloading=") || strings.Contains(line, ".flow_offloading_hw=")) &&
				strings.Trim(strings.SplitN(line, "=", 2)[1], "'\" ") == "1" {
				offload = true
			}
		}
		if offload {
			r.Issues = append(
				r.Issues,
				"Flow offloading must be disabled explicitly before enabling protected traffic",
			)
		} else {
			r.Capabilities["flow_offload_safe"] = Capability{
				true,
				"No enabled UCI software or hardware flow offload option detected",
			}
		}
	}
	if d.Exists("/usr/sbin/iw") {
		phy, e := d.Runner.Run(ctx, "/usr/sbin/iw", []string{"phy"}, nil)
		if e == nil && strings.Contains(string(phy), "* AP") {
			r.Capabilities["wireless_ap"] = Capability{
				true,
				"Driver advertises AP mode; channel and device pairing validation still required",
			}
		}
	}
	r.Capabilities["wds"] = Capability{
		false,
		"Four-address operation must be verified with the paired device",
	}
	r.Capabilities["mesh"] = Capability{
		false,
		"Encrypted mesh and peer compatibility require a validated device pair",
	}
	r.Capabilities["concurrent_radio"] = Capability{
		false,
		"Combined client and backhaul operation requires device-specific validation",
	}
	include, _ := d.ReadFile("/usr/share/nftables.d/ruleset-pre/90-openrhp-guard.nft")
	printed, printErr := d.Runner.Run(ctx, "/sbin/fw4", []string{"print"}, nil)
	autoIncludes := printErr == nil &&
		strings.Contains(
			string(printed),
			`include "/usr/share/nftables.d/ruleset-pre/90-openrhp-guard.nft"`,
		)
	if strings.Contains(string(include), `include "/etc/openrhp-helper/guard.nft"`) &&
		autoIncludes {
		r.Capabilities["lifecycle_guard"] = Capability{
			true,
			"Persistent fw4 guard include installed; independent RPDB guards protect fw4 flush",
		}
	}
	r.Supported = len(r.Issues) == 0
	return r
}

func parseRelease(input string) map[string]string {
	r := map[string]string{}
	for _, line := range strings.Split(input, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.HasPrefix(k, "DISTRIB_") {
			r[k] = strings.Trim(v, "'\"")
		}
	}
	return r
}

// ParseInterfaces discovers physical devices and default-route roles from netifd,
// never from conventional interface names. Users select LAN membership explicitly.
func ParseInterfaces(data []byte) ([]Interface, error) {
	var dump struct {
		Interfaces []struct {
			Name     string `json:"interface"`
			Device   string `json:"device"`
			L3Device string `json:"l3_device"`
			Proto    string `json:"proto"`
			Up       bool   `json:"up"`
			V4       []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv4-address"`
			V6 []struct {
				Address string `json:"address"`
				Mask    int    `json:"mask"`
			} `json:"ipv6-address"`
			Routes []struct {
				Target string `json:"target"`
				Mask   int    `json:"mask"`
			} `json:"route"`
		} `json:"interface"`
	}
	if len(data) > MaxCommandOutput {
		return nil, fmt.Errorf("interface dump too large")
	}
	if err := json.Unmarshal(data, &dump); err != nil {
		return nil, err
	}
	if len(dump.Interfaces) > 256 {
		return nil, fmt.Errorf("too many network interfaces")
	}
	result := []Interface{}
	for _, v := range dump.Interfaces {
		device := v.L3Device
		if device == "" {
			device = v.Device
		}
		if !ValidInterfaceName(device) {
			continue
		}
		i := Interface{
			Name:     v.Name,
			Device:   device,
			Protocol: v.Proto,
			Up:       v.Up,
			Role:     "local",
			Prefixes: []string{},
		}
		for _, route := range v.Routes {
			if route.Mask == 0 && (route.Target == "0.0.0.0" || route.Target == "::") {
				i.Role = "uplink"
			}
		}
		for _, a := range v.V4 {
			if p, e := netip.ParsePrefix(fmt.Sprintf("%s/%d", a.Address, a.Mask)); e == nil {
				i.Prefixes = append(i.Prefixes, p.Masked().String())
			}
		}
		for _, a := range v.V6 {
			if p, e := netip.ParsePrefix(fmt.Sprintf("%s/%d", a.Address, a.Mask)); e == nil {
				i.Prefixes = append(i.Prefixes, p.Masked().String())
			}
		}
		result = append(result, i)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func ValidInterfaceName(s string) bool {
	if len(s) == 0 || len(s) > 15 || s == "." || s == ".." || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' &&
			r != '-' &&
			r != '.' {
			return false
		}
	}
	return true
}
