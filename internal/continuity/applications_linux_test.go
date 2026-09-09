package continuity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type lockedOutput struct {
	sync.Mutex
	data bytes.Buffer
}

func (b *lockedOutput) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.data.Write(p)
}
func (b *lockedOutput) String() string { b.Lock(); defer b.Unlock(); return b.data.String() }
func freePort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return port
}

func execute(t *testing.T, args ...string) {
	t.Helper()
	if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("fixture command %s failed: %v %s", args[0], err, output)
	}
}

func tcpBridge(t *testing.T, g *Gateway, destination string) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { _ = g.ServeTCP(context.Background(), c, destination) }()
		}
	}()
	return l.Addr().String()
}

func udpBridge(t *testing.T, g *Gateway, destination string) string {
	t.Helper()
	l, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, e := l.ReadFrom(b)
			if e != nil {
				return
			}
			payload := append([]byte(nil), b[:n]...)
			client := addr
			_ = g.SendUDP(
				context.Background(),
				addr.String(),
				destination,
				payload,
				func(reply []byte) error { _, e := l.WriteTo(reply, client); return e },
			)
		}
	}()
	return l.LocalAddr().String()
}

func startApp(
	t *testing.T,
	args ...string,
) (*exec.Cmd, io.WriteCloser, *bufio.Reader, *lockedOutput) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	errlog := &lockedOutput{}
	cmd.Stderr = errlog
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd, in, bufio.NewReader(out), errlog
}

func appReady(t *testing.T, out *bufio.Reader, log *lockedOutput) {
	t.Helper()
	done := make(chan string, 1)
	go func() { line, _ := out.ReadString('\n'); done <- line }()
	select {
	case line := <-done:
		if line != "READY\n" {
			t.Fatalf("fixture not ready: %q %s", line, log.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("application handshake timed out: %s", log.String())
	}
}

func roundtripApp(t *testing.T, in io.Writer, out io.Reader, payload []byte, framed bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if framed {
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], uint32(len(payload)))
			if e := writeAll(in, h[:]); e != nil {
				done <- e
				return
			}
		}
		if e := writeAll(in, payload); e != nil {
			done <- e
			return
		}
		if framed {
			var h [4]byte
			if _, e := io.ReadFull(out, h[:]); e != nil {
				done <- e
				return
			}
			if int(binary.BigEndian.Uint32(h[:])) != len(payload) {
				done <- fmt.Errorf("application message boundary changed")
				return
			}
		}
		got := make([]byte, len(payload))
		_, e := io.ReadFull(out, got)
		if e == nil && !bytes.Equal(got, payload) {
			e = fmt.Errorf("application payload changed")
		}
		done <- e
	}()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("application session stalled across switch")
	}
}

func applicationFaults(t *testing.T, f *fixture, exchange func()) {
	t.Helper()
	exchange()
	for i, mode := range []string{"reset", "blackhole", "oneway", "data_only"} {
		kernelFault(t, f, i%2, mode)
		exchange()
		next := []string{"alpha", "beta"}[1-i%2]
		eventually(t, func() bool { return f.g.Snapshot().ActivePath == next })
		recoverKernelPath(t, f, i%2)
	}
	if f.dialed.Load() != 1 {
		t.Fatalf("application connection was recreated %d times", f.dialed.Load())
	}
}

func TestLinuxContinuityApplications(t *testing.T) {
	if os.Getenv("OPENRHP_CONTINUITY_APP_LAB") != "1" {
		t.Skip("run scripts/lab-continuity-apps.sh for actual SSH, QUIC, WebSocket and DNS clients")
	}
	t.Run("SSH", func(t *testing.T) {
		initFaultTable(t)
		f := newFixture(t, Limits{})
		dir := t.TempDir()
		hostKey := filepath.Join(dir, "host")
		clientKey := filepath.Join(dir, "client")
		execute(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey)
		execute(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", clientKey)
		port := freePort(t)
		if e := os.MkdirAll("/run/sshd", 0o755); e != nil {
			t.Fatal(e)
		}
		config := fmt.Sprintf(
			"Port %s\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s.pub\nPermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile %s\nLogLevel ERROR\n",
			port,
			hostKey,
			clientKey,
			filepath.Join(dir, "pid"),
		)
		configPath := filepath.Join(dir, "sshd_config")
		if e := os.WriteFile(configPath, []byte(config), 0o600); e != nil {
			t.Fatal(e)
		}
		_, _, _, serverLog := startApp(t, "/usr/sbin/sshd", "-D", "-e", "-f", configPath)
		eventually(t, func() bool {
			c, e := net.DialTimeout("tcp", "127.0.0.1:"+port, 50*time.Millisecond)
			if e != nil {
				return false
			}
			_ = c.Close()
			return true
		})
		bridge := tcpBridge(t, f.g, "127.0.0.1:"+port)
		_, bridgePort, _ := net.SplitHostPort(bridge)
		pub, e := os.ReadFile(hostKey + ".pub")
		if e != nil {
			t.Fatal(e)
		}
		known := filepath.Join(dir, "known_hosts")
		if e = os.WriteFile(
			known,
			[]byte("[127.0.0.1]:"+bridgePort+" "+string(pub)),
			0o600,
		); e != nil {
			t.Fatal(e)
		}
		cmd, in, out, log := startApp(
			t,
			"ssh",
			"-T",
			"-o",
			"BatchMode=yes",
			"-o",
			"StrictHostKeyChecking=yes",
			"-o",
			"UserKnownHostsFile="+known,
			"-i",
			clientKey,
			"-p",
			bridgePort,
			"root@127.0.0.1",
			"cat",
		)
		defer func() {
			if t.Failed() {
				t.Log(log.String(), serverLog.String())
			}
		}()
		applicationFaults(
			t,
			f,
			func() { roundtripApp(t, in, out, bytes.Repeat([]byte("SSH retained remote cat\x00"), 1000), false) },
		)
		_ = in.Close()
		if e = cmd.Wait(); e != nil {
			t.Fatalf("SSH process failed: %v %s", e, log.String())
		}
		t.Log(
			"actual SSH: one authenticated SSH connection and one remote cat process survived all four kernel fault modes",
		)
	})
	t.Run("QUIC", func(t *testing.T) {
		initFaultTable(t)
		f := newFixture(t, Limits{})
		dir := t.TempDir()
		cert := testCert(t)
		key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if e != nil {
			t.Fatal(e)
		}
		certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		if e = os.WriteFile(
			certPath,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
			0o600,
		); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(
			keyPath,
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
			0o600,
		); e != nil {
			t.Fatal(e)
		}
		port := freePort(t)
		_, _, serverOut, serverLog := startApp(
			t,
			"python3",
			"-u",
			"-c",
			quicServer,
			port,
			certPath,
			keyPath,
		)
		appReady(t, serverOut, serverLog)
		bridge := udpBridge(t, f.g, "127.0.0.1:"+port)
		_, bridgePort, _ := net.SplitHostPort(bridge)
		cmd, in, out, log := startApp(t, "python3", "-u", "-c", quicClient, bridgePort)
		appReady(t, out, log)
		applicationFaults(
			t,
			f,
			func() { roundtripApp(t, in, out, bytes.Repeat([]byte("QUIC retained stream\x00"), 1000), true) },
		)
		_ = in.Close()
		if e = cmd.Wait(); e != nil {
			t.Fatalf("QUIC failed: %v %s", e, log.String())
		}
		f.udpMu.Lock()
		count := len(f.udpPorts)
		f.udpMu.Unlock()
		if count != 1 {
			t.Fatal("QUIC server-side UDP port changed")
		}
		t.Log(
			"actual aioquic: one QUIC connection, one stream, and stable external UDP socket survived all four kernel fault modes",
		)
	})
	t.Run("WebSocket", func(t *testing.T) {
		initFaultTable(t)
		f := newFixture(t, Limits{})
		port := freePort(t)
		_, _, serverOut, serverLog := startApp(t, "python3", "-u", "-c", websocketServer, port)
		appReady(t, serverOut, serverLog)
		bridge := tcpBridge(t, f.g, "127.0.0.1:"+port)
		cmd, in, out, log := startApp(t, "python3", "-u", "-c", websocketClient, bridge)
		appReady(t, out, log)
		applicationFaults(
			t,
			f,
			func() { roundtripApp(t, in, out, bytes.Repeat([]byte("WebSocket binary frame\x00"), 1000), true) },
		)
		_ = in.Close()
		if e := cmd.Wait(); e != nil {
			t.Fatalf("WebSocket failed: %v %s", e, log.String())
		}
		t.Log(
			"actual WebSocket: one HTTP-upgraded connection retained binary message boundaries across all four kernel fault modes",
		)
	})
	t.Run("DNS", func(t *testing.T) {
		initFaultTable(t)
		f := newFixture(t, Limits{})
		server, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = server.Close() }()
		go func() {
			b := make([]byte, 4096)
			for {
				n, a, e := server.ReadFrom(b)
				if e != nil {
					return
				}
				if n < 12 {
					continue
				}
				reply := append([]byte(nil), b[:n]...)
				reply[2], reply[3], reply[6], reply[7] = 0x81, 0x80, 0, 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 8)
				_, _ = server.WriteTo(reply, a)
			}
		}()
		bridge := udpBridge(t, f.g, server.LocalAddr().String())
		client, e := net.Dial("udp", bridge)
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = client.Close() }()
		id := uint16(0)
		applicationFaults(t, f, func() {
			id++
			query := []byte{
				0,
				0,
				1,
				0,
				0,
				1,
				0,
				0,
				0,
				0,
				0,
				0,
				7,
				'e',
				'x',
				'a',
				'm',
				'p',
				'l',
				'e',
				3,
				'c',
				'o',
				'm',
				0,
				0,
				1,
				0,
				1,
			}
			binary.BigEndian.PutUint16(query, id)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e := client.Write(query); e != nil {
				t.Fatal(e)
			}
			reply := make([]byte, 4096)
			n, e := client.Read(reply)
			if e != nil {
				t.Fatal(e)
			}
			if n != len(query)+16 || binary.BigEndian.Uint16(reply) != id || reply[7] != 1 ||
				!bytes.Equal(reply[n-4:n], []byte{203, 0, 113, 8}) {
				t.Fatal("DNS transaction or A answer corrupted")
			}
		})
		t.Log(
			"DNS: five valid wire queries retained transaction IDs and one mapping through four kernel fault modes",
		)
	})
}

const framedPythonIO = `
def read_input():
    header = sys.stdin.buffer.read(4)
    if not header: return None
    if len(header) != 4: raise RuntimeError('short fixture input')
    size = struct.unpack('!I', header)[0]
    body = sys.stdin.buffer.read(size)
    if len(body) != size: raise RuntimeError('short fixture body')
    return body
def write_output(body):
    sys.stdout.buffer.write(struct.pack('!I', len(body)) + body)
    sys.stdout.buffer.flush()
`

const quicServer = `
import asyncio, sys
from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
class Echo(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self._quic.send_stream_data(event.stream_id,event.data,end_stream=event.end_stream)
            self.transmit()
async def main():
    config=QuicConfiguration(is_client=False,alpn_protocols=['openrhp-test'])
    config.load_cert_chain(sys.argv[2],sys.argv[3])
    server=await serve('127.0.0.1',int(sys.argv[1]),configuration=config,create_protocol=Echo)
    print('READY',flush=True)
    await asyncio.Future()
asyncio.run(main())
`

const quicClient = `
import asyncio, sys, struct, ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
` + framedPythonIO + `
async def main():
    config=QuicConfiguration(is_client=True,alpn_protocols=['openrhp-test'])
    config.verify_mode=ssl.CERT_NONE # ephemeral test-only certificate inside offline namespace
    async with connect('127.0.0.1',int(sys.argv[1]),configuration=config) as connection:
        reader,writer=await connection.create_stream()
        print('READY',flush=True)
        while True:
            body=await asyncio.get_running_loop().run_in_executor(None,read_input)
            if body is None: break
            writer.write(body)
            await writer.drain()
            write_output(await reader.readexactly(len(body)))
        writer.write_eof()
asyncio.run(main())
`

const websocketServer = `
import asyncio, sys, websockets
async def echo(connection,path):
    async for message in connection:
        await connection.send(message)
async def main():
    async with websockets.serve(echo,'127.0.0.1',int(sys.argv[1])):
        print('READY',flush=True)
        await asyncio.Future()
asyncio.run(main())
`

const websocketClient = `
import asyncio, sys, struct, websockets
` + framedPythonIO + `
async def main():
    async with websockets.connect('ws://'+sys.argv[1]) as connection:
        print('READY',flush=True)
        while True:
            body=await asyncio.get_running_loop().run_in_executor(None,read_input)
            if body is None: break
            await connection.send(body)
            write_output(await connection.recv())
asyncio.run(main())
`
