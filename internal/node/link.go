package node

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tibeahx/OpenRHP/internal/platform"
)

// LinkHealth describes the local node-to-gateway link only. Kernel counters are
// cumulative observations, never inferred packet-loss rates or useful speed.
type LinkHealth struct {
	Available     bool      `json:"available"`
	Interface     string    `json:"interface,omitempty"`
	Kind          string    `json:"kind"`
	ObservedAt    time.Time `json:"observed_at"`
	Carrier       *bool     `json:"carrier"`
	RXBytes       *uint64   `json:"rx_bytes"`
	TXBytes       *uint64   `json:"tx_bytes"`
	RXErrors      *uint64   `json:"rx_errors"`
	TXErrors      *uint64   `json:"tx_errors"`
	RXDropped     *uint64   `json:"rx_dropped"`
	TXDropped     *uint64   `json:"tx_dropped"`
	SignalDBM     *float64  `json:"signal_dbm"`
	RXBitrateMbps *float64  `json:"rx_bitrate_mbps"`
	TXBitrateMbps *float64  `json:"tx_bitrate_mbps"`
	Reason        string    `json:"reason"`
}

func boundedKernelRead(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	data, e := io.ReadAll(io.LimitReader(f, 1025))
	if len(data) > 1024 {
		return nil, errors.New("kernel counter exceeds limit")
	}
	return data, e
}

func counter(data []byte) *uint64 {
	v, e := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if e != nil {
		return nil
	}
	return &v
}

func ResolveWirelessInterface(data []byte) (string, error) {
	if len(data) > 1<<20 {
		return "", errors.New("wireless status exceeds limit")
	}
	var radios map[string]struct {
		Interfaces []struct {
			Section string `json:"section"`
			Name    string `json:"ifname"`
		} `json:"interfaces"`
	}
	if json.Unmarshal(data, &radios) != nil {
		return "", errors.New("wireless status unavailable")
	}
	found := ""
	for _, radio := range radios {
		for _, iface := range radio.Interfaces {
			if iface.Section == "openrhp_backhaul" {
				if !platform.ValidInterfaceName(iface.Name) || found != "" {
					return "", errors.New("wireless backhaul identity is absent or ambiguous")
				}
				found = iface.Name
			}
		}
	}
	if found == "" {
		return "", errors.New("wireless backhaul is not active")
	}
	return found, nil
}

func ParseStationMetrics(data []byte) (signal, rx, tx *float64) {
	if len(data) > 64<<10 {
		return nil, nil, nil
	}
	stations := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Station" {
			stations++
			continue
		}
		if fields[0] == "signal:" && len(fields) >= 2 {
			v, e := strconv.ParseFloat(fields[1], 64)
			if e == nil && !math.IsNaN(v) && !math.IsInf(v, 0) && v <= 0 && v >= -150 {
				signal = &v
			}
		}
		if len(fields) >= 4 && (fields[0] == "rx" || fields[0] == "tx") && fields[1] == "bitrate:" {
			v, e := strconv.ParseFloat(fields[2], 64)
			if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				continue
			}
			switch fields[3] {
			case "MBit/s":
			case "KBit/s":
				v /= 1000
			default:
				continue
			}
			if fields[0] == "rx" {
				rx = &v
			} else {
				tx = &v
			}
		}
	}
	if stations != 1 {
		return nil, nil, nil
	}
	return signal, rx, tx
}

func (b *UCIBackend) ReadLink(ctx context.Context, p Plan) (LinkHealth, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	h := LinkHealth{
		Kind:       p.Mode,
		ObservedAt: time.Now().UTC(),
		Reason:     "Local carrier and cumulative counters do not prove client connectivity or useful WAN speed.",
	}
	if p.Mode != "ethernet" && p.Mode != "wds" && p.Mode != "mesh" {
		return h, errors.New("unknown uplink mode")
	}
	if runtime.GOOS != "linux" && b.ReadFile == nil {
		h.Reason = "Kernel link telemetry requires Linux."
		return h, nil
	}
	iface := p.Uplink
	if p.Mode != "ethernet" {
		if b.Runner == nil {
			h.Reason = "Wireless link discovery is unavailable."
			return h, nil
		}
		data, e := b.Runner.Run(
			ctx,
			platform.UBusBinary(),
			[]string{"call", "network.wireless", "status"},
			nil,
		)
		if e != nil {
			h.Reason = "The active wireless backhaul interface could not be discovered."
			return h, nil
		}
		iface, e = ResolveWirelessInterface(data)
		if e != nil {
			h.Reason = "The wireless backhaul is inactive or cannot be identified uniquely."
			return h, nil
		}
	}
	if !platform.ValidInterfaceName(iface) || iface == "lo" {
		return h, errors.New("invalid uplink interface")
	}
	h.Interface = iface
	read := b.ReadFile
	if read == nil {
		read = boundedKernelRead
	}
	base := filepath.Join("/sys/class/net", iface)
	if data, e := read(filepath.Join(base, "carrier")); e == nil {
		switch strings.TrimSpace(string(data)) {
		case "1":
			v := true
			h.Carrier = &v
		case "0":
			v := false
			h.Carrier = &v
		}
	}
	for file, dest := range map[string]**uint64{"rx_bytes": &h.RXBytes, "tx_bytes": &h.TXBytes, "rx_errors": &h.RXErrors, "tx_errors": &h.TXErrors, "rx_dropped": &h.RXDropped, "tx_dropped": &h.TXDropped} {
		if data, e := read(filepath.Join(base, "statistics", file)); e == nil {
			*dest = counter(data)
		}
	}
	if p.Mode != "ethernet" {
		if data, e := b.Runner.Run(
			ctx,
			"/usr/sbin/iw",
			[]string{"dev", iface, "station", "dump"},
			nil,
		); e == nil {
			h.SignalDBM, h.RXBitrateMbps, h.TXBitrateMbps = ParseStationMetrics(data)
		}
	}
	h.Available = h.Carrier != nil || h.RXBytes != nil || h.TXBytes != nil || h.RXErrors != nil ||
		h.TXErrors != nil ||
		h.RXDropped != nil ||
		h.TXDropped != nil ||
		h.SignalDBM != nil ||
		h.RXBitrateMbps != nil ||
		h.TXBitrateMbps != nil
	if !h.Available {
		h.Reason = "No link telemetry is available for the identified uplink. Unknown measurements are not treated as healthy."
	}
	return h, nil
}

func (m *Manager) Link(ctx context.Context) (map[string]any, error) {
	h := LinkHealth{
		Kind:       "unknown",
		ObservedAt: time.Now().UTC(),
		Reason:     "No applied or confirmed node plan identifies the current uplink.",
	}
	e := m.locked(func(s *journal) error {
		t := s.Transaction
		if t == nil || (t.State != "applied" && t.State != "confirmed") {
			return nil
		}
		backend, ok := m.backend.(interface {
			ReadLink(context.Context, Plan) (LinkHealth, error)
		})
		if !ok {
			return nil
		}
		var e error
		h, e = backend.ReadLink(ctx, t.Plan)
		return e
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"node_link": h}, nil
}
