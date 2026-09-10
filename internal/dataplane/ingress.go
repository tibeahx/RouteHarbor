package dataplane

import (
	"errors"
	"slices"
	"strings"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

// WithIngressDevices widens only generated LAN ingress selectors using private
// helper-derived bridge membership. It does not alter public desired intent.
func WithIngressDevices(p Plan) (Plan, error) {
	if len(p.IngressDevices) > 64 {
		return p, errors.New("invalid_ingress_guard")
	}
	devices := append([]string{}, p.Desired.Network.LANInterfaces...)
	for _, dev := range p.IngressDevices {
		if !platform.ValidInterfaceName(dev) || dev == "lo" ||
			dev == p.Desired.Network.WANInterface ||
			slices.Contains(devices, dev) {
			return p, errors.New("invalid_ingress_guard")
		}
		devices = append(devices, dev)
	}
	if len(p.IngressDevices) == 0 {
		return p, nil
	}
	old := "iifname " + quotedSet(p.Desired.Network.LANInterfaces)
	replacement := "iifname " + quotedSet(devices)
	p.NFT = strings.ReplaceAll(p.NFT, old, replacement)
	p.GuardNFT = strings.ReplaceAll(p.GuardNFT, old, replacement)
	return p, nil
}
