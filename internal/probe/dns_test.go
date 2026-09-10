package probe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
)

// This is a DNS wire-format server behind distinct source-specific TCP sockets.
// It answers A records with different public addresses and returns no AAAA records.
type dnsPaths struct {
	mu    sync.Mutex
	calls map[string]int
}

func (d *dnsPaths) DialProbe(ctx context.Context, id, address string) (net.Conn, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.calls[id]++
	d.mu.Unlock()
	go func() {
		defer func() { _ = server.Close() }()
		if e := server.SetDeadline(time.Now().Add(2 * time.Second)); e != nil {
			return
		}
		var size [2]byte
		if _, e := io.ReadFull(server, size[:]); e != nil {
			return
		}
		packet := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, e := io.ReadFull(server, packet); e != nil || len(packet) < 17 {
			return
		}
		end := 12
		for end < len(packet) && packet[end] != 0 {
			end += int(packet[end]) + 1
		}
		end++
		if end+4 > len(packet) {
			return
		}
		typ := binary.BigEndian.Uint16(packet[end : end+2])
		questionEnd := end + 4
		response := append([]byte(nil), packet[:questionEnd]...)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		binary.BigEndian.PutUint16(response[6:8], 0)
		binary.BigEndian.PutUint16(response[8:10], 0)
		binary.BigEndian.PutUint16(response[10:12], 0)
		if typ == 1 {
			binary.BigEndian.PutUint16(response[6:8], 1)
			ip := []byte{93, 184, 216, 34}
			if id == "b" {
				ip = []byte{1, 1, 1, 1}
			}
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			response = append(response, ip...)
		}
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
		frame = append(frame, response...)
		if _, e := server.Write(frame); e != nil {
			return
		}
	}()
	return client, nil
}

func TestManagedTargetDNSUsesEachSourcePath(t *testing.T) {
	d := &dnsPaths{calls: map[string]int{}}
	r := NewRunner(nil)
	r.DialProbe = d
	r.ConfigureDNS(true, "8.8.8.8")
	r.Resolver = fixedResolver{netip.MustParseAddr("127.0.0.1")}
	u, _ := url.Parse("https://example.com/")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, id := range []string{"a", "b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			r.dnsMu.RLock()
			policy := r.dnsPolicy
			r.dnsMu.RUnlock()
			ip, e := r.resolve(ctx, u, adapter.Path{SourceID: id, Kind: "interface"}, policy)
			expected := "93.184.216.34"
			if id == "b" {
				expected = "1.1.1.1"
			}
			if e != nil || ip.String() != expected {
				t.Errorf("source %s DNS escaped its own path: %s %v", id, ip, e)
			}
		}(id)
	}
	wg.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.calls["a"] == 0 || d.calls["b"] == 0 {
		t.Fatal("both source-specific DNS paths were not exercised")
	}
}

func TestManagedHostnameProbeCannotFallBackToSystemDNS(t *testing.T) {
	r := NewRunner(nil)
	r.Resolver = fixedResolver{netip.MustParseAddr("1.1.1.1")}
	u, _ := url.Parse("https://example.com/")
	if _, e := r.resolve(
		context.Background(),
		u,
		adapter.Path{Kind: "direct"},
		dnsPolicy{managed: true},
	); e == nil {
		t.Fatal("missing explicit resolver fell back to system DNS")
	}
	u, _ = url.Parse("https://1.1.1.1/")
	if ip, e := r.resolve(
		context.Background(),
		u,
		adapter.Path{Kind: "direct"},
		dnsPolicy{managed: true},
	); e != nil ||
		ip.String() != "1.1.1.1" {
		t.Fatal("public literal target unnecessarily required DNS", e)
	}
}
