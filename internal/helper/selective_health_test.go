package helper

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

func TestSelectiveHealthImmediateResetStillRequiresDNSAndListener(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			_ = connection.SetLinger(0)
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var failed atomic.Bool
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		for {
			buffer := make([]byte, 512)
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			buffer[2] |= 0x80
			buffer[7] = 1
			if failed.Load() {
				buffer[3] |= 2
			}
			answer := append(buffer[:n], 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 1)
			_, _ = dns.WriteTo(answer, peer)
		}
	}()
	t.Cleanup(func() { _ = dns.Close(); <-dnsDone })
	desired := selectiveDesired()
	desired.Selective.Path.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	desired.Selective.DNSFrontPort = uint16(dns.LocalAddr().(*net.UDPAddr).Port)
	for range 25 {
		if err := SelectiveHealth(context.Background(), desired); err != nil {
			t.Fatal("early listener reset falsely declared classifier dead", err)
		}
	}
	failed.Store(true)
	if err := SelectiveHealth(context.Background(), desired); err == nil {
		t.Fatal("reset masked failed DNS")
	}
	failed.Store(false)
	_ = listener.Close()
	if err := SelectiveHealth(context.Background(), desired); err == nil {
		t.Fatal("healthy DNS masked missing classifier listener")
	}
}
