package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/platform"
)

func TestStationMetricsPreserveUnknownAndRejectAmbiguousPeers(t *testing.T) {
	signal, rx, tx := ParseStationMetrics(
		[]byte(
			"Station 02:00:00:00:00:01 (on phy0-sta0)\n\tsignal: -61 [-64, -62] dBm\n\trx bitrate: 6500.0 KBit/s\n\ttx bitrate: 144.4 MBit/s MCS 15\n",
		),
	)
	if signal == nil || *signal != -61 || rx == nil || *rx != 6.5 || tx == nil || *tx != 144.4 {
		t.Fatal("valid station metrics were not parsed")
	}
	for _, input := range []string{"", "signal: -20 dBm", "Station peer1\nStation peer2\n signal: -40 dBm", "Station peer1\n signal: NaN dBm\n rx bitrate: +Inf MBit/s\n tx bitrate: -1 MBit/s", "Station peer1\n signal: -151 dBm\n rx bitrate: 3 GB/s", strings.Repeat("x", (64<<10)+1)} {
		a, b, c := ParseStationMetrics([]byte(input))
		if a != nil || b != nil || c != nil {
			t.Fatal("missing, invalid, oversized or ambiguous telemetry became a value")
		}
	}
}

func TestWirelessInterfaceResolutionUsesOnlyOwnedActiveSection(t *testing.T) {
	name, err := ResolveWirelessInterface(
		[]byte(
			`{"radio0":{"interfaces":[{"section":"private_ap","ifname":"phy0-ap0","config":{"key":"PRIVATE-KEY"}},{"section":"routeharbor_backhaul","ifname":"phy0-sta0"}]}}`,
		),
	)
	if err != nil || name != "phy0-sta0" {
		t.Fatalf("wrong backhaul identity: %q %v", name, err)
	}
	for _, input := range []string{`{}`, `{"radio0":{"interfaces":[{"section":"routeharbor_backhaul"}]}}`, `{"radio0":{"interfaces":[{"section":"routeharbor_backhaul","ifname":"../secret"}]}}`, `{"radio0":{"interfaces":[{"section":"routeharbor_backhaul","ifname":"wlan0"},{"section":"routeharbor_backhaul","ifname":"wlan1"}]}}`, "null", strings.Repeat("x", (1<<20)+1)} {
		if _, err := ResolveWirelessInterface([]byte(input)); err == nil {
			t.Fatal("invalid or ambiguous interface was accepted")
		}
	}
}

type linkRunner func(context.Context, string, []string, []byte) ([]byte, error)

func (r linkRunner) Run(
	ctx context.Context,
	path string,
	args []string,
	input []byte,
) ([]byte, error) {
	return r(ctx, path, args, input)
}

func TestReadLinkSeparatesCountersAndUnavailableFields(t *testing.T) {
	files := map[string]string{
		"/sys/class/net/port2/carrier":              "0\n",
		"/sys/class/net/port2/statistics/rx_bytes":  "42\n",
		"/sys/class/net/port2/statistics/rx_errors": "0\n",
		"/sys/class/net/port2/statistics/tx_bytes":  "-1\n",
		"/sys/class/net/port2/statistics/tx_errors": "18446744073709551616\n",
	}
	backend := &UCIBackend{ReadFile: func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, os.ErrNotExist
	}}
	p := plan()
	p.Uplink = "port2"
	h, err := backend.ReadLink(context.Background(), p)
	if err != nil || !h.Available || h.Carrier == nil || *h.Carrier || h.RXBytes == nil ||
		*h.RXBytes != 42 ||
		h.RXErrors == nil ||
		*h.RXErrors != 0 ||
		h.TXBytes != nil ||
		h.TXErrors != nil ||
		h.RXDropped != nil ||
		h.SignalDBM != nil {
		t.Fatalf("counter validity or unknown semantics failed: %+v %v", h, err)
	}
	files = map[string]string{}
	h, err = backend.ReadLink(context.Background(), p)
	if err != nil || h.Available || h.Carrier != nil || h.RXErrors != nil {
		t.Fatal("missing kernel measurements inferred a healthy link")
	}
	data, _ := json.Marshal(h)
	if !strings.Contains(string(data), `"carrier":null`) ||
		!strings.Contains(string(data), `"rx_errors":null`) {
		t.Fatal("unknown values lost their explicit null representation")
	}
	p.Uplink = "../../etc"
	if _, err = backend.ReadLink(context.Background(), p); err == nil {
		t.Fatal("unsafe interface allowed filesystem traversal")
	}
}

func TestWirelessLinkCommandsAreReadOnlyAndDoNotExposePeerIdentity(t *testing.T) {
	commands := 0
	backend := &UCIBackend{
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Runner: linkRunner(
			func(_ context.Context, path string, args []string, input []byte) ([]byte, error) {
				commands++
				if len(input) > 0 {
					t.Fatal("read-only telemetry sent command input")
				}
				switch path + " " + strings.Join(args, " ") {
				case platform.UBusBinary() + " call network.wireless status":
					return []byte(
						`{"radio0":{"interfaces":[{"section":"routeharbor_backhaul","ifname":"phy0-sta0"}]}}`,
					), nil
				case "/usr/sbin/iw dev phy0-sta0 station dump":
					return []byte(
						"Station 02:11:22:33:44:55 (on phy0-sta0)\n signal: -58 dBm\n tx bitrate: 72.2 MBit/s\n",
					), nil
				default:
					return nil, errors.New("unexpected telemetry command")
				}
			},
		),
	}
	p := plan()
	p.Mode = "wds"
	h, err := backend.ReadLink(context.Background(), p)
	if err != nil || !h.Available || h.SignalDBM == nil || *h.SignalDBM != -58 ||
		h.RXBitrateMbps != nil ||
		commands != 2 {
		t.Fatalf("wireless metrics unavailable: %+v %v", h, err)
	}
	data, _ := json.Marshal(h)
	if strings.Contains(string(data), "02:11:22:33:44:55") {
		t.Fatal("raw peer identity escaped telemetry allowlist")
	}
}

func TestLinkWithoutAppliedPlanIsExplicitlyUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), &fakeBackend{}, &fakeWatchdog{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	status, err := m.Link(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h := status["node_link"].(LinkHealth)
	if h.Available || h.Kind != "unknown" || h.Carrier != nil {
		t.Fatal("unconfigured node was reported healthy")
	}
}

func FuzzStationMetrics(f *testing.F) {
	f.Add([]byte("Station 00:11:22:33:44:55\n signal: -65 dBm\n tx bitrate: 72.2 MBit/s\n"))
	f.Add([]byte("Station a\nStation b\n"))
	f.Fuzz(func(t *testing.T, data []byte) { ParseStationMetrics(data) })
}
