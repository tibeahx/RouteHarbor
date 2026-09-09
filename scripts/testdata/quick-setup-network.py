#!/usr/bin/env python3
"""Synthetic WAN responders and a real LAN client for the manual browser lab.

Only executed inside the dedicated network-none OpenWrt QEMU container. Public
addresses below are private namespace aliases, not Internet destinations.
"""

import http.server
import json
import pathlib
import socket
import socketserver
import ssl
import sys
import threading

BODY = b"OpenRHP quick setup lab\n"
ADDRESSES = [(4, "8.8.8.8"), (6, "2001:4860:4860::8888")]


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()

    def log_message(self, *_args):
        pass


class HTTPServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # The synthetic responder must not issue a reverse-DNS request merely
        # to format its own server name during startup.
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'openrhp-lab'
        self.server_port = self.server_address[1]


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            self.request.sendall(self.request.recv(1024))
        except OSError:
            pass


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        message, connection = self.request
        connection.sendto(message, self.client_address)


def serve(directory):
    servers = []
    for version, address in ADDRESSES:
        family = socket.AF_INET if version == 4 else socket.AF_INET6
        for port, base, handler in [
            (443, HTTPServer, HTTP),
            (18081, socketserver.ThreadingUDPServer, UDP),
            (53, socketserver.ThreadingUDPServer, UDP),
            (53, socketserver.ThreadingTCPServer, TCP),
        ]:
            server_type = type("Responder", (base,), {
                "address_family": family, "allow_reuse_address": True,
                "daemon_threads": True,
            })
            server = server_type((address, port), handler)
            if port == 443:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(directory / "server.pem", directory / "server.key")
                server.socket = context.wrap_socket(server.socket, server_side=True)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    print("READY", flush=True)
    threading.Event().wait()


def client(directory, selected_dns=False):
    context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    results = {}
    for version, address in ADDRESSES:
        family = socket.AF_INET if version == 4 else socket.AF_INET6
        for name, kind, port in [
            ("https", socket.SOCK_STREAM, 443),
            ("udp", socket.SOCK_DGRAM, 18081),
            ("port53-udp", socket.SOCK_DGRAM, 53),
            ("port53-tcp", socket.SOCK_STREAM, 53),
        ]:
            connection = socket.socket(family, kind)
            connection.settimeout(1)
            try:
                # The alternate destination has no responder or alias. Success
                # after application proves actual selected-resolver DNAT.
                destination = '1.1.1.1' if selected_dns and version == 4 and port == 53 else address
                connection.connect((destination, port))
                if name == "https":
                    connection = context.wrap_socket(connection, server_hostname=address)
                    connection.sendall(b"GET /quick-setup HTTP/1.0\r\nHost: lab\r\n\r\n")
                    response = b""
                    while part := connection.recv(8192):
                        response += part
                    results[f"{version}-{name}"] = response.endswith(BODY)
                else:
                    connection.sendall(BODY)
                    results[f"{version}-{name}"] = connection.recv(1024) == BODY
            except OSError:
                results[f"{version}-{name}"] = False
            finally:
                connection.close()
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            try:
                connection.connect(("10.44.0.1" if version == 4 else "fd44:1::1", 22))
                results[f"{version}-management"] = connection.recv(64).startswith(b"SSH-")
            except OSError:
                results[f"{version}-management"] = False
    print(json.dumps(results))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4) or sys.argv[1] not in ("server", "client"):
        raise SystemExit("Expected server|client and an isolated fixture directory")
    if len(sys.argv) == 4 and (sys.argv[1] != 'client' or sys.argv[3] != 'selected-path'):
        raise SystemExit('Only the client supports selected-path DNS verification')
    directory = pathlib.Path(sys.argv[2])
    if directory.parent != pathlib.Path("/tmp") or not directory.name.startswith("openrhp-quick-setup-"):
        raise SystemExit("Refusing a non-lab fixture directory")
    if sys.argv[1] == 'server':
        serve(directory)
    else:
        client(directory, len(sys.argv) == 4)
