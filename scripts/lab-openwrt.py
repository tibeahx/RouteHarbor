#!/usr/bin/env python3
"""Actual OpenWrt userland/procd package lifecycle, isolated from host networking.

Input image must already contain independently verified OpenWrt 24.10.7 x86_64
rootfs and signed-repository ip-full dependencies. This script downloads nothing.
It is a userland/container test, not a full OpenWrt boot or physical-router test.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import ssl
import time
import uuid


def run(args, data=None, good=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=60)
    if good and result.returncode:
        raise RuntimeError(f"Command failed: {args}\n{result.stderr}\n{result.stdout}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=pathlib.Path, required=True)
    parser.add_argument("--image", default=os.environ.get("OPENRHP_OPENWRT_LAB_IMAGE", "openrhp-openwrt-deps:24.10.7"))
    args = parser.parse_args()
    packages = args.packages.resolve(strict=True)
    for pattern in ("openrhp_*.ipk", "openrhp-guard_*.ipk", "openrhp-node_*.ipk"):
        if len(list(packages.glob(pattern))) != 1:
            raise ValueError(f"Expected exactly one current SDK package matching {pattern}")
    container_name = "openrhp-package-lab-" + uuid.uuid4().hex[:12]
    run(["docker", "run", "--detach", "--rm", "--name", container_name, "--platform", "linux/amd64", "--network", "none",
         "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--mount", f"type=bind,source={packages},target=/packages,readonly",
         "--entrypoint", "/bin/sh", args.image, "-c", "mkdir -p /var/run/ubus /var/lock /var/log; /sbin/ubusd & /sbin/procd -S & wait"])

    def command(*argv, data=None, good=True):
        return run(["docker", "exec", "-i", container_name, *argv], data, good)

    def shell(script, good=True):
        return command("/bin/sh", "-eu", data=script, good=good)

    def api(path, method="GET", data=None, revision=None, token="/root/openrhp-private/admin.token"):
        argv = ["/usr/bin/openrhp", "api", "--token-file", token, "--path", path, "--method", method]
        if data is not None:
            argv += ["--data", "-", "--idempotency-key", uuid.uuid4().hex]
        if revision is not None:
            argv += ["--revision", str(revision)]
        return json.loads(command(*argv, data=json.dumps(data) if data is not None else None).stdout)

    def wait_api():
        for _ in range(40):
            try:
                return api("/api/v1/status")
            except RuntimeError:
                time.sleep(0.1)
        raise AssertionError("API did not become ready")

    def service(name, expected_uid):
        report = json.loads(command("ubus", "call", "service", "list", json.dumps({"name": name})).stdout)
        instance = report[name]["instances"]["instance1"]
        assert instance["running"], report
        status = command("cat", f"/proc/{instance['pid']}/status").stdout
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        assert [int(v) for v in fields["Uid"].split()] == [expected_uid] * 4
        if expected_uid:
            for cap in ("CapEff", "CapPrm", "CapAmb"):
                assert int(fields[cap], 16) == 0, (name, cap)

    def blocked():
        for family, destination, source in (("-4", "8.8.4.4", "10.44.0.2"), ("-6", "2001:4860:4860::8888", "2001:db8::2")):
            result = command("ip", family, "route", "get", destination, "from", source, "iif", "br-test", good=False)
            assert result.returncode, f"Unmarked {family} traffic escaped the routing guard"
        local = command("ip", "-4", "route", "get", "10.44.0.3", "from", "10.44.0.2", "iif", "br-test").stdout
        assert "br-test" in local

    try:
        for _ in range(40):
            if command("ubus", "call", "service", "list", good=False).returncode == 0:
                break
            time.sleep(0.1)
        shell('''
[ -f /.dockerenv ] && [ -f /etc/openwrt_release ]
ip link add lablan0 type dummy
ip link add labwan0 type dummy
ip link set lablan0 up
ip link set labwan0 up
cat > /etc/config/network <<'CONFIG'
config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1'
 option netmask '255.0.0.0'
config device 'test_bridge'
 option name 'br-test'
 option type 'bridge'
 list ports 'lablan0'
config interface 'family'
 option device 'br-test'
 option proto 'static'
 option ipaddr '10.44.0.1'
 option netmask '255.255.255.0'
config interface 'fiber'
 option device 'labwan0'
 option proto 'static'
 option ipaddr '192.0.2.1'
 option netmask '255.255.255.0'
 option gateway '192.0.2.254'
CONFIG
/etc/init.d/network start
sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall > /tmp/network-before.sha
opkg install /packages/openrhp-guard_*.ipk /packages/openrhp_*.ipk /packages/openrhp-node_*.ipk
[ "$(uci -q get openrhp.main.enabled)" = 0 ]
[ "$(uci -q get openrhp-node.main.enabled)" = 0 ]
mkdir -p /root/openrhp-private
chmod 0700 /root/openrhp-private
/usr/libexec/openrhp-setup /root/openrhp-private/admin.token
/usr/libexec/openrhp-node-setup /root/openrhp-private/node.code
sha256sum /root/openrhp-private/admin.token /root/openrhp-private/node.code /etc/openrhp-node/identity.json > /tmp/identity-before.sha
/usr/libexec/openrhp-setup /root/openrhp-private/admin.token
/usr/libexec/openrhp-node-setup /root/openrhp-private/node.code
sha256sum -c /tmp/network-before.sha
sha256sum -c /tmp/identity-before.sha
''')
        assert not wait_api()["network_applied"]
        api_uid = int(command("id", "-u", "openrhp").stdout)
        node_uid = int(command("id", "-u", "openrhp-node").stdout)
        assert api_uid and node_uid and api_uid != node_uid
        for name, uid in (("openrhp", api_uid), ("openrhp-guard", 0), ("openrhp-node", node_uid), ("openrhp-node-helper", 0)):
            service(name, uid)
        report = api("/api/v1/capabilities")["platform"]
        assert report["supported"], report
        assert {i["device"] for i in report["interfaces"]} >= {"br-test", "labwan0"}
        assert report["capabilities"]["lifecycle_guard"]["available"]
        assert not report["capabilities"]["break_existing"]["available"], "Optional conntrack support was advertised without its package"
        print("PASS SDK opkg install, fresh disabled defaults, repeat setup, service credentials, helper platform report", flush=True)
        command("/usr/bin/openrhp", "as-service", "token", "--state", "/etc/openrhp", "--role", "read", "--out", "/etc/openrhp/admin/lab-read.token")
        api("/api/v1/status", token="/etc/openrhp/admin/lab-read.token")
        command("/etc/init.d/openrhp", "restart")
        command("/etc/init.d/openrhp-node", "restart")
        wait_api()
        shell("sha256sum -c /tmp/network-before.sha\nsha256sum -c /tmp/identity-before.sha\n")
        print("PASS credential administration and procd restart preserve identity and network", flush=True)

        # Read only the public certificate; keep the enrollment secret in memory
        # and send it on stdin, never through process arguments or test output.
        certificate = command("jsonfilter", "-i", "/etc/openrhp-node/identity.json", "-e", "@.certificate").stdout
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
        enrollment = command("cat", "/root/openrhp-private/node.code").stdout.strip()
        paired = api("/api/v1/nodes/pair", "POST", {"address": "https://127.0.0.1:9844", "fingerprint": fingerprint, "code": enrollment, "name": "Packaged node"})
        node = paired["result"]["node"]
        assert node["capabilities"]["openwrt"] and node["capabilities"]["ethernet"], node["capabilities"]
        api(f"/api/v1/nodes/{node['id']}/status")
        denied = command("/usr/libexec/openrhp-helper", "verify-wireless", "--radio", "radio0", "--interface", "wlan0", "--mode", "wds", "--peer-fingerprint", fingerprint, "--peer-mac", "02:00:00:00:00:42", "--checked-encryption", "--checked-client-addresses", "--checked-single-dhcp", "--checked-management-recovery", "--checked-concurrent-ap", good=False)
        assert denied.returncode, "Radio-free container incorrectly authorized a wireless receipt"
        assert command("test", "-e", "/etc/openrhp-helper/wireless-verification.json", good=False).returncode
        api(f"/api/v1/nodes/{node['id']}", "DELETE", {})
        print("PASS packaged node pairing/capabilities/status/revocation and wireless receipt refusal without live hardware", flush=True)

        config = api("/api/v1/config")
        config["sources"] = [{"id": "direct", "name": "Lab direct", "type": "direct", "enabled": True, "auto": True, "settings": {}}]
        config["targets"] = [{"id": "lab-unreachable", "url": "https://8.8.8.8/", "required": True, "status_codes": [200], "max_bytes": 1024}]
        config["policy"].update(mode="auto", fallback="closed", break_existing=True)
        config["network"] = {"enabled": True, "lan_interfaces": ["br-test"], "wan_interface": "labwan0", "local_prefixes": ["10.44.0.0/24"], "ipv6": "block", "dns": "block", "dns_resolver": "8.8.8.8"}
        api("/api/v1/config", "PUT", config, config["revision"])
        revision = api("/api/v1/config")["revision"]
        try:
            api("/api/v1/transactions", "POST", {"confirm_timeout_seconds": 30}, revision)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Missing optional conntrack support passed privileged preflight")
        assert command("test", "-e", "/etc/openrhp-helper/transaction.json", good=False).returncode
        config["revision"] = revision
        config["policy"]["break_existing"] = False
        api("/api/v1/config", "PUT", config, revision)
        revision = api("/api/v1/config")["revision"]
        print("PASS optional conntrack absence is explicit and opt-in fails before routing mutation", flush=True)
        operation = api("/api/v1/transactions", "POST", {"confirm_timeout_seconds": 30}, revision)
        transaction = operation["result"]["id"]
        for action in ("apply", "confirm"):
            outcome = api(f"/api/v1/transactions/{transaction}/{action}", "POST", {})
            assert outcome["state"] == "succeeded", outcome
        command("/etc/init.d/openrhp", "stop")
        blocked()
        command("fw4", "flush")
        blocked()
        command("/etc/init.d/firewall", "start")
        assert "OpenRHP" in command("nft", "list", "table", "inet", "openrhp_guard").stdout
        command("/etc/init.d/firewall", "reload")
        blocked()
        print("PASS real API apply/confirm, procd stop, fw4 flush/start/reload and LAN management preservation", flush=True)
        command("opkg", "remove", "openrhp")
        assert command("/usr/libexec/openrhp-helper", "can-remove", "--state-dir", "/etc/openrhp-helper", good=False).returncode
        result = command("opkg", "remove", "openrhp-guard", good=False)
        assert result.returncode and "openrhp-guard" in command("opkg", "list-installed").stdout
        blocked()
        command("/usr/libexec/openrhp-helper", "decommission", "--state-dir", "/etc/openrhp-helper", "--policy", "restore-direct")
        command("/usr/libexec/openrhp-helper", "can-remove", "--state-dir", "/etc/openrhp-helper")
        command("opkg", "remove", "openrhp-guard", "openrhp-node")
        assert "openrhp" not in command("opkg", "list-installed").stdout
        shell("sha256sum -c /tmp/network-before.sha\nsha256sum -c /tmp/identity-before.sha\n")
        print("PASS protected guard removal refused; explicit decommission and ordinary uninstall preserve user state", flush=True)
        print("PASS OpenWrt 24.10.7 x86_64 userland/procd package lifecycle (Docker Linux kernel; no physical or radio claim)", flush=True)
    finally:
        run(["docker", "rm", "--force", container_name], good=False)


if __name__ == "__main__":
    main()
