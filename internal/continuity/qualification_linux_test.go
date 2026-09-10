package continuity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This opt-in lab requires a disposable Linux network namespace with NET_ADMIN.
// scripts/lab-continuity.sh supplies one with Docker network=none. The firewall
// rules match only this test's carrier sockets, never a physical router or WAN.
const labTable = "openrhp_continuity_test"

type distribution struct {
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

func summarize(values []float64) distribution {
	if len(values) == 0 {
		return distribution{}
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	at := func(q float64) float64 { return v[int(float64(len(v)-1)*q)] }
	return distribution{at(.5), at(.95), at(.99), v[len(v)-1]}
}

type loadResult struct {
	Mode            string       `json:"mode"`
	UDPSize         int          `json:"udp_payload_bytes"`
	Fault           bool         `json:"fault"`
	RequestedMbps   float64      `json:"requested_mbps"`
	DeliveredMbps   float64      `json:"delivered_mbps"`
	DeliveryGaps    distribution `json:"delivery_gaps"`
	AddedMaxPauseMS float64      `json:"added_max_pause_ms"`
	Bytes           int64        `json:"bytes"`
	UDPReceived     int64        `json:"udp_received"`
	UDPSent         int64        `json:"udp_sent"`
	UDPLoss         int64        `json:"udp_loss"`
	UDPDuplicates   int64        `json:"udp_duplicates"`
	Hashes          []string     `json:"sha256"`
	QueuePeak       int64        `json:"queue_peak_bytes"`
	HeapPeak        uint64       `json:"go_heap_peak_bytes"`
	CPUSecs         float64      `json:"cpu_seconds"`
	Passed          bool         `json:"passed"`
}
type labReport struct {
	Environment       string         `json:"environment"`
	Switches          int            `json:"switches"`
	FailureModes      map[string]int `json:"failure_modes"`
	AddedPause        distribution   `json:"switch_added_pause"`
	StressUDPReceived int            `json:"stress_udp_received"`
	StableTCPTarget   bool           `json:"stable_tcp_target"`
	StableUDPMapping  bool           `json:"stable_udp_mapping"`
	Loads             []loadResult   `json:"loads"`
	Qualified         bool           `json:"qualified"`
	Limitations       []string       `json:"limitations"`
}

func nft(t *testing.T, script string) {
	t.Helper()
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated nft operation failed: %v: %s", err, output)
	}
}

func initFaultTable(t *testing.T) {
	t.Helper()
	nft(
		t,
		"add table inet "+labTable+"\nadd chain inet "+labTable+" faults { type filter hook output priority 0; policy accept; }\n",
	)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", labTable).Run() })
}

func kernelFault(t *testing.T, f *fixture, index int, mode string) {
	t.Helper()
	f.paths[index].dead.Store(true)
	name := []string{"alpha", "beta"}[index]
	f.g.p.mu.Lock()
	cs := f.g.p.paths[name]
	dataLane := 1
	firstFlow := ^uint64(0)
	for id, flow := range f.g.p.flows {
		if id < firstFlow {
			firstFlow = id
			dataLane = laneFor(flow)
		}
	}
	f.g.p.mu.Unlock()
	ports := []string{}
	relayPort := ""
	for lane, c := range cs {
		if c == nil {
			t.Fatal("fault path has missing carrier")
		}
		if mode == "data_only" && lane != dataLane {
			continue
		}
		_, port, err := net.SplitHostPort(c.conn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, port)
		_, relayPort, _ = net.SplitHostPort(c.conn.RemoteAddr().String())
		if mode == "reset" {
			f.paths[index].mu.Lock()
			for _, raw := range f.paths[index].conns {
				if raw.LocalAddr().String() == c.conn.LocalAddr().String() {
					if tcp, ok := raw.Conn.(*net.TCPConn); ok {
						_ = tcp.SetLinger(0)
					}
					_ = raw.Close()
				}
			}
			f.paths[index].mu.Unlock()
		}
	}
	if mode == "reset" {
		return
	}
	script := "flush chain inet " + labTable + " faults\nadd rule inet " + labTable + " faults ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport { " + strings.Join(
		ports,
		", ",
	) + " } tcp dport " + relayPort + " drop\n"
	if mode == "blackhole" {
		script += "add rule inet " + labTable + " faults ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport " + relayPort + " tcp dport { " + strings.Join(
			ports,
			", ",
		) + " } drop\n"
	}
	nft(t, script)
}

func recoverKernelPath(t *testing.T, f *fixture, index int) {
	t.Helper()
	nft(t, "flush chain inet "+labTable+" faults\n")
	f.paths[index].dead.Store(false)
	eventually(
		t,
		func() bool { s := f.g.Snapshot(); return len(s.Paths) == 2 && s.Paths[0].Ready && s.Paths[1].Ready },
	)
}

func udpEcho(t *testing.T) string {
	t.Helper()
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, e := target.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = target.WriteTo(b[:n], addr)
		}
	}()
	return target.LocalAddr().String()
}

func TestLinuxContinuityQualification(t *testing.T) {
	if os.Getenv("OPENRHP_CONTINUITY_LAB") != "1" {
		t.Skip("opt-in isolated Linux qualification; run scripts/lab-continuity.sh")
	}
	count := 1000
	if value := os.Getenv("OPENRHP_CONTINUITY_SWITCHES"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 10000 {
			t.Fatal("invalid switch count")
		}
		count = n
	}
	report := labReport{
		Environment:  "Linux isolated Docker namespace; real nft packet drops on independent TLS carrier tuples; loopback targets",
		FailureModes: map[string]int{},
		Limitations: []string{
			"This is a relay-protocol Linux lab, not OpenWrt boot or physical router evidence.",
			"100 Mbit/s profiles are paced offered useful payload; achieved delivery rate is reported separately.",
			"SSH and QUIC application sessions, physical CPU/RAM, and non-loopback WAN latency are not qualified by this harness.",
		},
	}
	t.Run("kernel_switches", func(t *testing.T) {
		initFaultTable(t)
		f := newFixture(t, Limits{})
		gateway, client := tcpPair(t)
		destination := tcpEcho(t)
		go func() { _ = f.g.ServeTCP(context.Background(), gateway, destination) }()
		udpDestination := udpEcho(t)
		replies := make(chan []byte, 8)
		deliver := func(b []byte) error { replies <- append([]byte(nil), b...); return nil }
		payload := bytes.Repeat([]byte("retained socket"), 1000)
		exchange(t, client, payload)
		var pauses []float64
		for i := 0; i < count; i++ {
			active := i % 2
			next := 1 - active
			reserve := []string{"alpha", "beta"}[next]
			if err := f.g.SetPreferred(reserve); err != nil {
				t.Fatal(err)
			}
			eventually(
				t,
				func() bool { s := f.r.Snapshots(); return len(s) == 1 && s[0].ActivePath == reserve },
			)
			start := time.Now()
			exchange(t, client, payload)
			baseline := time.Since(start)
			if err := f.g.SetPreferred([]string{"alpha", "beta"}[active]); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				s := f.r.Snapshots()
				return len(s) == 1 && s[0].ActivePath == []string{"alpha", "beta"}[active]
			})
			mode := []string{"reset", "blackhole", "oneway", "data_only"}[i%4]
			kernelFault(t, f, active, mode)
			body := make([]byte, 1200)
			binary.BigEndian.PutUint64(body, uint64(i+1))
			start = time.Now()
			if err := f.g.SendUDP(
				context.Background(),
				"stress",
				udpDestination,
				body,
				deliver,
			); err != nil {
				t.Fatal(err)
			}
			exchange(t, client, payload)
			pause := time.Since(start) - baseline
			if pause < 0 {
				pause = 0
			}
			pauses = append(pauses, float64(pause)/float64(time.Millisecond))
			select {
			case got := <-replies:
				if !bytes.Equal(got, body) {
					t.Fatal("UDP lost order or duplicated during sequential switching")
				}
				report.StressUDPReceived++
			case <-time.After(time.Second):
				t.Fatal("UDP lost during single-path kernel failure")
			}
			eventually(t, func() bool { return f.g.Snapshot().ActivePath == reserve })
			recoverKernelPath(t, f, active)
			report.Switches++
			report.FailureModes[mode]++
			if (i+1)%100 == 0 {
				t.Logf("completed %d/%d kernel switch cycles", i+1, count)
			}
		}
		report.AddedPause = summarize(pauses)
		report.StableTCPTarget = f.dialed.Load() == 2
		f.udpMu.Lock()
		report.StableUDPMapping = len(f.udpPorts) == 1
		f.udpMu.Unlock()
		if !report.StableTCPTarget || !report.StableUDPMapping {
			t.Fatal("target sockets recreated during switches")
		}
	})
	for _, mode := range []string{"download", "upload", "mixed"} {
		for _, size := range []int{1200, 64} {
			var baseline loadResult
			for _, fault := range []bool{false, true} {
				t.Run(fmt.Sprintf("load_%s_udp%d_fault%t", mode, size, fault), func(t *testing.T) {
					initFaultTable(t)
					r := runLoad(t, mode, size, fault)
					if !fault {
						baseline = r
					} else {
						r.AddedMaxPauseMS = r.DeliveryGaps.Max - baseline.DeliveryGaps.Max
						if r.AddedMaxPauseMS < 0 {
							r.AddedMaxPauseMS = 0
						}
						r.Passed = r.Passed && r.AddedMaxPauseMS <= 100
					}
					report.Loads = append(report.Loads, r)
				})
			}
		}
	}
	// Qualification also requires real SSH/QUIC application and hardware evidence.
	report.Qualified = false
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("CONTINUITY_LAB_JSON " + string(b))
}

type transferResult struct {
	bytes int64
	hash  string
	gaps  []float64
	err   error
}

func writePacedRecords(c net.Conn, rate int64, duration time.Duration) (string, error) {
	const size = 16 << 10
	records := int(rate * int64(duration) / int64(time.Second) / size)
	hash := sha256.New()
	start := time.Now()
	b := make([]byte, size)
	for i := 0; i < records; i++ {
		for j := range b {
			b[j] = byte(i + j)
		}
		binary.BigEndian.PutUint64(b, uint64(i))
		if err := writeAll(c, b); err != nil {
			return "", err
		}
		_, _ = hash.Write(b)
		due := start.Add(time.Duration(int64(i+1) * size * int64(time.Second) / rate))
		if delay := time.Until(due); delay > 0 {
			time.Sleep(delay)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readRecords(c net.Conn) transferResult {
	var result transferResult
	hash := sha256.New()
	b := make([]byte, 16<<10)
	last := time.Now()
	sequence := uint64(0)
	for {
		n, err := io.ReadFull(c, b)
		now := time.Now()
		if n > 0 {
			result.bytes += int64(n)
			_, _ = hash.Write(b[:n])
			result.gaps = append(result.gaps, float64(now.Sub(last))/float64(time.Millisecond))
			last = now
			if n == len(b) {
				if binary.BigEndian.Uint64(b) != sequence {
					result.err = fmt.Errorf("record duplicated or missing")
					break
				}
				sequence++
			}
		}
		if err != nil {
			if err != io.EOF {
				result.err = err
			}
			break
		}
	}
	result.hash = hex.EncodeToString(hash.Sum(nil))
	return result
}

func runLoad(t *testing.T, mode string, udpSize int, fault bool) loadResult {
	t.Helper()
	f := newFixture(t, Limits{})
	result := loadResult{
		Mode:          mode,
		UDPSize:       udpSize,
		Fault:         fault,
		RequestedMbps: 100,
		Passed:        true,
	}
	if !fault {
		if err := f.g.SetPreferred("beta"); err != nil {
			t.Fatal(err)
		}
		eventually(
			t,
			func() bool { s := f.r.Snapshots(); return len(s) == 1 && s[0].ActivePath == "beta" },
		)
	}
	const duration = 3 * time.Second
	start := time.Now()
	var cpuStart, cpuEnd syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &cpuStart)
	var metricsMu sync.Mutex
	var gaps []float64
	var queuePeak int64
	var heapPeak uint64
	stopMetrics := make(chan struct{})
	var metricsWG sync.WaitGroup
	metricsWG.Add(1)
	go func() {
		defer metricsWG.Done()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMetrics:
				return
			case <-ticker.C:
				s := f.g.Snapshot()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				metricsMu.Lock()
				if s.QueueBytes > queuePeak {
					queuePeak = s.QueueBytes
				}
				if m.HeapAlloc > heapPeak {
					heapPeak = m.HeapAlloc
				}
				metricsMu.Unlock()
			}
		}
	}()
	udpDestination := udpEcho(t)
	var udpSent, udpReceived, udpDuplicates atomic.Int64
	var udpMu sync.Mutex
	seen := map[uint64]bool{}
	lastUDP := time.Now()
	deliver := func(b []byte) error {
		n := binary.BigEndian.Uint64(b)
		udpMu.Lock()
		defer udpMu.Unlock()
		if seen[n] {
			udpDuplicates.Add(1)
		} else {
			seen[n] = true
			udpReceived.Add(1)
		}
		now := time.Now()
		metricsMu.Lock()
		gaps = append(gaps, float64(now.Sub(lastUDP))/float64(time.Millisecond))
		metricsMu.Unlock()
		lastUDP = now
		return nil
	}
	udpDone := make(chan error, 1)
	go func() {
		rate := int64(5_000_000 / 8 / 2)
		count := int(rate * int64(duration) / int64(time.Second) / int64(udpSize))
		epoch := time.Now()
		for i := 0; i < count; i++ {
			b := make([]byte, udpSize)
			binary.BigEndian.PutUint64(b, uint64(i))
			if err := f.g.SendUDP(
				context.Background(),
				"load",
				udpDestination,
				b,
				deliver,
			); err != nil {
				udpDone <- err
				return
			}
			udpSent.Add(1)
			due := epoch.Add(time.Duration(int64(i+1) * int64(udpSize) * int64(time.Second) / rate))
			if delay := time.Until(due); delay > 0 {
				time.Sleep(delay)
			}
		}
		udpDone <- nil
	}()
	var transfers sync.WaitGroup
	transferDone := make(chan transferResult, 2)
	directions := []string{mode}
	if mode == "mixed" {
		directions = []string{"download", "upload"}
	}
	for _, direction := range directions {
		rate := int64(95_000_000 / 8 / len(directions))
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		accepted := make(chan net.Conn, 1)
		go func() {
			c, e := listener.Accept()
			if e == nil {
				accepted <- c
			}
		}()
		gateway, client := tcpPair(t)
		go func() { _ = f.g.ServeTCP(context.Background(), gateway, listener.Addr().String()) }()
		_ = client.SetDeadline(time.Now().Add(15 * time.Second))
		transfers.Add(1)
		go func(direction string, rate int64) {
			defer transfers.Done()
			var server net.Conn
			select {
			case server = <-accepted:
			case <-time.After(5 * time.Second):
				transferDone <- transferResult{err: fmt.Errorf("target not opened")}
				return
			}
			defer func() { _ = server.Close() }()
			_ = server.SetDeadline(time.Now().Add(15 * time.Second))
			writer, reader := net.Conn(client), server
			if direction == "download" {
				writer, reader = server, client
			}
			written := make(chan string, 1)
			writeErr := make(chan error, 1)
			go func() {
				hash, e := writePacedRecords(writer, rate, duration)
				written <- hash
				writeErr <- e
				if tcp, ok := writer.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
			}()
			r := readRecords(reader)
			expected := <-written
			if e := <-writeErr; e != nil {
				r.err = e
			}
			if expected != r.hash {
				r.err = fmt.Errorf("end-to-end TCP hash mismatch")
			}
			transferDone <- r
		}(direction, rate)
	}
	if fault {
		time.Sleep(750 * time.Millisecond)
		kernelFault(t, f, 0, "blackhole")
	}
	transfers.Wait()
	close(transferDone)
	for r := range transferDone {
		if r.err != nil {
			t.Error(r.err)
			result.Passed = false
		}
		result.Bytes += r.bytes
		result.Hashes = append(result.Hashes, r.hash)
		metricsMu.Lock()
		gaps = append(gaps, r.gaps...)
		metricsMu.Unlock()
	}
	if err := <-udpDone; err != nil {
		t.Error(err)
		result.Passed = false
	}
	trafficDuration := time.Since(start)
	time.Sleep(150 * time.Millisecond)
	result.UDPSent = udpSent.Load()
	result.UDPReceived = udpReceived.Load()
	result.UDPDuplicates = udpDuplicates.Load()
	result.UDPLoss = result.UDPSent - result.UDPReceived
	result.Bytes += result.UDPReceived * int64(udpSize) * 2
	result.DeliveredMbps = float64(result.Bytes) * 8 / trafficDuration.Seconds() / 1e6
	if result.UDPLoss != 0 || result.UDPDuplicates != 0 {
		result.Passed = false
		t.Errorf("UDP loss=%d duplicates=%d", result.UDPLoss, result.UDPDuplicates)
	}
	if result.DeliveredMbps < 97 {
		result.Passed = false
	}
	close(stopMetrics)
	metricsWG.Wait()
	metricsMu.Lock()
	result.DeliveryGaps = summarize(gaps)
	result.QueuePeak = queuePeak
	result.HeapPeak = heapPeak
	metricsMu.Unlock()
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &cpuEnd)
	cpu := func(r syscall.Rusage) float64 {
		return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
	}
	result.CPUSecs = cpu(cpuEnd) - cpu(cpuStart)
	if fault {
		recoverKernelPath(t, f, 0)
	}
	return result
}
