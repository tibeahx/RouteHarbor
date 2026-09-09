//go:build linux

package continuityrun

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

// Gated kernel socket evidence: real original-destination control messages and
// datagram boundaries on isolated loopback. This is not a TPROXY or hardware test.
func TestLinuxOriginalDestinationAndUDPDatagramBoundaries(t *testing.T) {
	if os.Getenv("OPENRHP_CONTINUITY_NET_LAB") != "1" {
		t.Skip("requires isolated Linux continuity socket lab")
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			level, option := syscall.SOL_IP, 20
			if network == "udp6" {
				address = "[::1]:0"
				level, option = syscall.SOL_IPV6, 74
			}
			lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				var socketErr error
				err := raw.Control(
					func(fd uintptr) { socketErr = syscall.SetsockoptInt(int(fd), level, option, 1) },
				)
				if err != nil {
					return err
				}
				return socketErr
			}}
			packet, err := lc.ListenPacket(context.Background(), network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = packet.Close() }()
			listener := packet.(*net.UDPConn)
			target := listener.LocalAddr().(*net.UDPAddr)
			client, err := net.DialUDP(network, nil, target)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			expected := netip.MustParseAddrPort(target.String())
			for _, payload := range [][]byte{{0, 1, 0xff}, {}, bytes.Repeat([]byte{0x42}, 1400)} {
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				data, oob := make([]byte, 65535), make([]byte, 256)
				n, on, flags, remote, err := listener.ReadMsgUDPAddrPort(data, oob)
				if err != nil || flags != 0 || !bytes.Equal(data[:n], payload) {
					t.Fatal("kernel datagram boundary changed", n, len(payload), flags, err)
				}
				original, err := originalDestination(oob[:on])
				if err != nil || original != expected {
					t.Fatal("original destination changed", original, expected, err)
				}
				if remote.String() != client.LocalAddr().String() {
					t.Fatal("source tuple changed", remote, client.LocalAddr())
				}
			}
		})
	}
}

func TestLinuxMissingOrMalformedOriginalDestinationFailsClosed(t *testing.T) {
	for _, oob := range [][]byte{nil, {1, 2, 3}, make([]byte, 16)} {
		if _, err := originalDestination(oob); err == nil {
			t.Fatal("missing/malformed original destination accepted")
		}
	}
}
