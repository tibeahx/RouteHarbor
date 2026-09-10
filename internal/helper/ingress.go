package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/tibeahx/RouteHarbor/internal/dataplane"
	"github.com/tibeahx/RouteHarbor/internal/model"
	"github.com/tibeahx/RouteHarbor/internal/platform"
)

// discoverIngress derives only direct bridge membership from the kernel. VLAN
// lower links are deliberately not widened onto potentially shared WAN trunks.
func discoverIngress(_ context.Context, network model.Network) ([]string, error) {
	seen := map[string]bool{}
	selected := map[string]bool{}
	for _, dev := range network.LANInterfaces {
		selected[dev] = true
	}
	var visit func(string) error
	visit = func(bridge string) error {
		if len(seen) > 64 {
			return errors.New("ingress_guard_unavailable: too many bridge ingress devices")
		}
		ports, err := os.ReadDir(filepath.Join("/sys/class/net", bridge, "brif"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return errors.New("ingress_guard_unavailable: cannot inspect bridge membership")
		}
		for _, port := range ports {
			dev := port.Name()
			if !platform.ValidInterfaceName(dev) || dev == network.WANInterface || dev == "lo" {
				return errors.New(
					"ingress_guard_conflict: a LAN bridge contains a WAN or invalid device",
				)
			}
			master, err := os.Readlink(filepath.Join("/sys/class/net", dev, "master"))
			if err != nil || filepath.Base(master) != bridge {
				return errors.New(
					"ingress_guard_unavailable: bridge membership changed during inspection",
				)
			}
			if seen[dev] {
				continue
			}
			seen[dev] = true
			if err := visit(dev); err != nil {
				return err
			}
		}
		return nil
	}
	for _, dev := range network.LANInterfaces {
		if err := visit(dev); err != nil {
			return nil, err
		}
	}
	devices := []string{}
	for dev := range seen {
		if !selected[dev] {
			devices = append(devices, dev)
		}
	}
	sort.Strings(devices)
	return devices, nil
}

func validIngress(devices []string) bool {
	if len(devices) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, dev := range devices {
		if !platform.ValidInterfaceName(dev) || dev == "lo" || seen[dev] {
			return false
		}
		seen[dev] = true
	}
	return true
}

func (m *Manager) prepareIngress(ctx context.Context, s *State, d dataplane.Desired) error {
	b, ok := m.backend.(*NetworkBackend)
	if !ok || b.Ingress == nil {
		return nil
	}
	devices, err := b.Ingress(ctx, d.Network)
	if err != nil {
		return err
	}
	if !validIngress(devices) {
		return errors.New("ingress_guard_unavailable")
	}
	if (s.IngressBound || s.Ingress != nil) && !slices.Equal(s.Ingress, devices) {
		return errors.New(
			"ingress_guard_changed: explicitly decommission before changing protected LAN bridge membership",
		)
	}
	if !s.IngressBound {
		s.IngressBound = true
		s.Ingress = devices
		return m.save(s)
	}
	return nil
}

func ingressInterfaces(p dataplane.Plan) []string {
	devices := append([]string{}, p.Desired.Network.LANInterfaces...)
	for _, dev := range p.IngressDevices {
		if !slices.Contains(devices, dev) {
			devices = append(devices, dev)
		}
	}
	return devices
}
