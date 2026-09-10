package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

const maxWANIdentityBytes = 128 << 10

// inspectDispatcherWANIdentity uses fixed read-only ip commands. Only a digest of
// normalized identity escapes this boundary; raw local addresses and gateways do
// not enter API responses, errors, command arguments or diagnostics.
func inspectDispatcherWANIdentity(
	ctx context.Context,
	runner platform.Runner,
	iface string,
) (string, error) {
	if !platform.ValidInterfaceName(iface) || iface == "lo" {
		return "", errors.New("wan_identity_unavailable")
	}
	commands := [][]string{
		{"-j", "address", "show", "dev", iface},
		{"-4", "-j", "route", "show", "table", "main", "default", "dev", iface},
		{"-6", "-j", "route", "show", "table", "main", "default", "dev", iface},
	}
	values := make([][]byte, 0, len(commands))
	for _, args := range commands {
		data, err := runner.Run(ctx, "/sbin/ip", args, nil)
		if err != nil || len(data) > maxWANIdentityBytes {
			return "", errors.New("wan_identity_unavailable")
		}
		values = append(values, data)
	}
	return hashDispatcherWANIdentity(iface, values[0], values[1], values[2])
}

func decodeWANIdentity(data []byte, out any) error {
	if len(data) > maxWANIdentityBytes {
		return errors.New("wan_identity_unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("wan_identity_unavailable")
	}
	return nil
}

func hashDispatcherWANIdentity(iface string, addresses, routes4, routes6 []byte) (string, error) {
	fail := func() (string, error) { return "", errors.New("wan_identity_unavailable") }
	if !platform.ValidInterfaceName(iface) || iface == "lo" {
		return fail()
	}
	var links []struct {
		Index     int      `json:"ifindex"`
		Name      string   `json:"ifname"`
		Flags     []string `json:"flags"`
		State     string   `json:"operstate"`
		Addresses []struct {
			Family string   `json:"family"`
			Local  string   `json:"local"`
			Prefix int      `json:"prefixlen"`
			Scope  string   `json:"scope"`
			Flags  []string `json:"flags"`
		} `json:"addr_info"`
	}
	if decodeWANIdentity(addresses, &links) != nil || len(links) != 1 {
		return fail()
	}
	link := links[0]
	up := false
	if link.Index <= 0 || link.Name != iface || len(link.Flags) > 64 || len(link.Addresses) == 0 ||
		len(link.Addresses) > 64 {
		return fail()
	}
	for _, flag := range link.Flags {
		if flag == "UP" {
			up = true
		}
	}
	if !up || link.State == "DOWN" || link.State == "LOWERLAYERDOWN" || link.State == "NOTPRESENT" {
		return fail()
	}
	components := []string{
		"interface:" + iface,
		"index:" + strconv.Itoa(link.Index),
		"state:" + link.State,
	}
	for _, a := range link.Addresses {
		ip, err := netip.ParseAddr(a.Local)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || a.Prefix < 0 || a.Prefix > ip.BitLen() ||
			len(a.Flags) > 64 {
			return fail()
		}
		if (a.Family == "inet") != ip.Is4() || (a.Family != "inet" && a.Family != "inet6") {
			return fail()
		}
		flags := append([]string{}, a.Flags...)
		sort.Strings(flags)
		components = append(
			components,
			"address:"+netip.PrefixFrom(ip, a.Prefix).
				String()+
				":"+a.Scope+":"+strings.Join(
				flags,
				",",
			),
		)
	}
	type nextHop struct {
		Gateway string `json:"gateway"`
		Device  string `json:"dev"`
		Weight  int    `json:"weight"`
	}
	type route struct {
		Destination     string    `json:"dst"`
		Gateway         string    `json:"gateway"`
		Device          string    `json:"dev"`
		Metric          int       `json:"metric"`
		PreferredSource string    `json:"prefsrc"`
		Type            string    `json:"type"`
		Scope           string    `json:"scope"`
		NextHops        []nextHop `json:"nexthops"`
	}
	count := 0
	for index, data := range [][]byte{routes4, routes6} {
		var routes []route
		if decodeWANIdentity(data, &routes) != nil || len(routes) > 256 {
			return fail()
		}
		for _, r := range routes {
			if r.Destination != "default" && r.Destination != "0.0.0.0/0" &&
				r.Destination != "::/0" {
				return fail()
			}
			if r.Device != "" && r.Device != iface || r.Metric < 0 || len(r.NextHops) > 64 {
				return fail()
			}
			addresses := []string{r.Gateway, r.PreferredSource}
			for _, n := range r.NextHops {
				if !platform.ValidInterfaceName(n.Device) || n.Weight < 0 {
					return fail()
				}
				addresses = append(addresses, n.Gateway)
			}
			for _, address := range addresses {
				if address == "" {
					continue
				}
				ip, err := netip.ParseAddr(address)
				if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.Is4() != (index == 0) {
					return fail()
				}
			}
			sort.Slice(r.NextHops, func(a, b int) bool {
				x, _ := json.Marshal(r.NextHops[a])
				y, _ := json.Marshal(r.NextHops[b])
				return string(x) < string(y)
			})
			encoded, _ := json.Marshal(r)
			components = append(components, "route"+strconv.Itoa(index)+":"+string(encoded))
			count++
		}
	}
	if count == 0 {
		return fail()
	}
	sort.Strings(components)
	digest := sha256.Sum256([]byte(strings.Join(components, "\n")))
	return hex.EncodeToString(digest[:]), nil
}
