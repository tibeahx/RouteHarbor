"""Network-namespace lab controller. Test-only addresses and credentials never enter runtime fixtures."""
import concurrent.futures
import http.server
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time

CERT = "/tmp/openrhp-lab/cert.pem"
KEY = "/tmp/openrhp-lab/key.pem"
TARGET = "10.210.0.4"
MARKS = {"direct": 0x4F010000, "dpi-a": 0x4F020000, "dpi-b": 0x4F030000, "proxy": 0x4F040000}

class HTTPSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        raw = json.dumps({"client_ip": self.client_address[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self, *args):
        pass

class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(1024)
        if line != b"CONNECT 10.210.0.4:443 HTTP/1.1\r\n":
            return
        while self.rfile.readline(1024) != b"\r\n":
            pass
        target = socket.create_connection((TARGET, 443), timeout=3)
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        def relay(src, dst):
            try:
                while data := src.recv(16384):
                    dst.sendall(data)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        worker = threading.Thread(target=relay, args=(self.connection, target), daemon=True)
        worker.start()
        relay(target, self.connection)
        target.close()

class ThreadingProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def request(kind):
    s = socket.socket()
    s.settimeout(3)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARKS[kind])
    s.connect(("10.210.0.3", 3128) if kind == "proxy" else (TARGET, 443))
    if kind == "proxy":
        s.sendall(b"CONNECT 10.210.0.4:443 HTTP/1.1\r\nHost: 10.210.0.4:443\r\n\r\n")
        raw = b""
        while not raw.endswith(b"\r\n\r\n") and len(raw) < 1024:
            raw += s.recv(1)
        assert raw.startswith(b"HTTP/1.1 200"), raw
    ctx = ssl.create_default_context(cafile=CERT)
    with ctx.wrap_socket(s, server_hostname="lab.example") as tls:
        tls.sendall(b"GET / HTTP/1.1\r\nHost: lab.example\r\nConnection: close\r\n\r\n")
        raw = b""
        while data := tls.recv(8192):
            raw += data
    assert raw.startswith(b"HTTP/1.0 200"), raw[:100]
    result = json.loads(raw.split(b"\r\n\r\n", 1)[1])
    expected = "10.210.0.3" if kind == "proxy" else "10.210.0.2"
    assert result["client_ip"] == expected, (kind, result)
    return kind

def counters():
    data = json.loads(subprocess.check_output(["nft", "-j", "list", "table", "inet", "openrhp_probe_lab"]))
    result = {}
    for entry in data["nftables"]:
        counter = entry.get("counter")
        if counter:
            result[counter["name"]] = counter["packets"]
    return result

def checks():
    assert counters() == {"dpi_a": 0, "dpi_b": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(request, ["direct", "proxy"] * 4))
    assert counters() == {"dpi_a": 0, "dpi_b": 0}, "unselected direct/proxy entered a DPI queue"
    request("dpi-a")
    first = counters()
    assert first["dpi_a"] > 0 and first["dpi_b"] == 0, first
    request("dpi-b")
    second = counters()
    assert second["dpi_a"] == first["dpi_a"] and second["dpi_b"] > 0, second
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        completed = list(pool.map(request, list(MARKS) * 8))
    print(json.dumps({"phase": "parallel_paths", "requests": len(completed), "queues": counters(), "proxy_exit": "10.210.0.3", "direct_and_dpi_exit": "10.210.0.2"}), flush=True)
    pid = int(open("/tmp/openrhp-lab/dpi-a.pid").read())
    os.kill(pid, 15)
    time.sleep(0.3)
    failed = False
    try:
        request("dpi-a")
    except (TimeoutError, OSError):
        failed = True
    assert failed, "dead DPI engine silently fell back to direct"
    for kind in ("direct", "dpi-b", "proxy"):
        request(kind)
    print(json.dumps({"phase": "engine_crash", "dpi_a": "failed_closed", "dpi_b": "passed", "direct": "passed", "proxy": "passed"}), flush=True)

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "https":
        server = http.server.ThreadingHTTPServer((TARGET, 443), HTTPSHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
    elif mode == "proxy":
        ThreadingProxy(("10.210.0.3", 3128), ProxyHandler).serve_forever()
    elif mode == "check":
        checks()
