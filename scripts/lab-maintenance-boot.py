#!/usr/bin/env python3
"""Public API maintenance on the isolated, already provisioned OpenWrt boot VM.

Requires a current feature-capable 0.1.0 baseline and its confirmed closed policy.
SDK 0.1.1 is an isolated upgrade fixture, not a published production release.
The retained guard is never replaced. Run only after the VM owner's handoff.
"""
import argparse
import atexit
import hashlib
import importlib.util
import json
import os
import pathlib
import shlex
import signal
import subprocess
import tempfile
import tarfile
import io
import time
import uuid


spec = importlib.util.spec_from_file_location("boot_lab", pathlib.Path(__file__).with_name("lab-openwrt-boot.py"))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def make_bundle(directory, version, key, release_tool, base_commit, output):
    output.mkdir(mode=0o700)
    artifacts = []
    for source in sorted(directory.glob("*.ipk")):
        data = source.read_bytes()
        destination = output / source.name
        destination.write_bytes(data)
        destination.chmod(0o600)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as outer:
            control_member = next(entry for entry in outer.getmembers() if entry.name.removeprefix("./") == "control.tar.gz")
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile(control_member).read()), mode="r:gz") as control_archive:
                control_file = next(entry for entry in control_archive.getmembers() if entry.name.removeprefix("./") == "control")
                fields = dict(line.split(": ", 1) for line in control_archive.extractfile(control_file).read().decode().splitlines() if ": " in line and not line.startswith(" "))
        assert fields["Architecture"] in ["x86_64", "all"]
        assert fields["Version"].split("-", 1)[0] == version
        artifacts.append({"name": source.name, "architecture": fields["Architecture"], "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    assert artifacts, "No SDK package fixtures"
    manifest = {"schema_version": 1, "project": "OpenRHP", "version": version, "commit": base_commit, "artifacts": artifacts}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    command([str(release_tool), "sign", "--manifest", str(output / "manifest.json"), "--signature", str(output / "manifest.sig"), "--key", str(key)])
    return artifacts


def api(lab, path, method="GET", body=None, revision=None, key=None, check=True):
    argv = ["/usr/bin/openrhp", "api", "--token-file", "/root/openrhp-lab/admin.token", "--path", path, "--method", method]
    if body is not None:
        argv += ["--data", "-", "--idempotency-key", key or uuid.uuid4().hex]
    if revision is not None:
        argv += ["--revision", str(revision)]
    script = shlex.join(argv)
    if body is not None:
        marker = "OPENRHP_LAB_" + uuid.uuid4().hex
        script += " <<'" + marker + "'\n" + json.dumps(body) + "\n" + marker
    result = lab.guest(script + "\n", check=check)
    if not check:
        return result
    return json.loads(result.stdout)


def root_status(lab, identifier):
    assert len(identifier) == 32 and all(c in "0123456789abcdef" for c in identifier)
    result = lab.guest("/usr/libexec/openrhp-helper maintenance-status --operation " + identifier + "\n", check=False)
    if result.returncode and result.stderr.strip() in {"maintenance state busy", "maintenance_state_busy"}:
        return None
    assert result.returncode == 0, "Root maintenance status inspection failed: " + result.stderr
    return json.loads(result.stdout)


def jobs(lab):
    names = lab.guest("for path in /etc/openrhp-maintenance/job-*.json; do [ -f \"$path\" ] && basename \"$path\"; done; true\n").stdout.splitlines()
    return {name[4:-5] for name in names if name.startswith("job-") and name.endswith(".json")}


def wait_job(lab, identifier):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        operation = root_status(lab, identifier)
        if operation is None:
            time.sleep(.2)
            continue
        if operation["state"] in ["completed", "failed", "interrupted"]:
            assert operation["state"] == "completed", operation
            return operation
        time.sleep(0.2)
    raise AssertionError("Root maintenance worker did not complete")


def routing_state(lab):
    return json.loads(lab.guest("cat /etc/openrhp-helper/transaction.json\n").stdout)


def confirm_closed(lab):
    config = api(lab, "/api/v1/config")
    assert config["network"]["enabled"] and config["policy"]["fallback"] == "closed"
    result = api(lab, "/api/v1/transactions", "POST", {"confirm_timeout_seconds": 90}, config["revision"])
    identifier = result["result"]["id"]
    for action in ["apply", "confirm"]:
        result = api(lab, "/api/v1/transactions/" + identifier + "/" + action, "POST", {})
        assert result["state"] == "succeeded", result
    assert not routing_state(lab).get("maintenance_hold", False)


# Fresh probes continue throughout controller restarts/removal. Captures are
# checked at the external WAN namespace; failed client replies alone prove nothing.
FLOOD = r'''
import json,pathlib,socket,time
stop=pathlib.Path('/tmp/openrhp-maintenance-flood.stop')
report=pathlib.Path('/tmp/openrhp-maintenance-flood.json')
count=0
while not stop.exists():
 for family,address in [(socket.AF_INET,'8.8.8.8'),(socket.AF_INET6,'2001:4860:4860::8888')]:
  for transport,port in [(socket.SOCK_DGRAM,53),(socket.SOCK_STREAM,53),(socket.SOCK_DGRAM,28081),(socket.SOCK_STREAM,28080)]:
   with socket.socket(family,transport) as connection:
    connection.setblocking(False)
    try:
     if transport==socket.SOCK_DGRAM: connection.sendto(b'OpenRHP-maintenance-probe',(address,port))
     else: connection.connect_ex((address,port))
    except OSError: pass
 count+=1
 staging=report.with_suffix('.tmp')
 staging.write_text(json.dumps({'iterations':count,'updated':time.time()}))
 staging.replace(report)
 time.sleep(.1)
'''


def progress(lab):
    result = json.loads(lab.container_command(["cat", "/tmp/openrhp-maintenance-flood.json"]).stdout)
    assert time.time() - result["updated"] < 5, "WAN probe generator stopped"
    return result["iterations"]


def management(lab):
    source = "import socket; s=socket.create_connection(('10.44.0.1',22),3); assert s.recv(64).startswith(b'SSH-'); s.close()"
    lab.container_command(["ip", "netns", "exec", "openrhp-client", "python3", "-c", source])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="openrhp-openwrt-boot-lab")
    parser.add_argument("--baseline", type=pathlib.Path, required=True)
    parser.add_argument("--candidate", type=pathlib.Path, required=True)
    parser.add_argument("--reuse-staged", action="store_true", help="Reuse already authenticated fixture bundles only when every package hash matches these exact SDK inputs")
    parser.add_argument("--execute", action="store_true", help="Run after the VM owner's explicit handoff")
    args = parser.parse_args()
    if not args.execute:
        parser.error("This mutates only the isolated VM; pass --execute after its owner releases it")
    assert args.container.startswith("openrhp-"), "Unexpected lab container"
    baseline, candidate = args.baseline.resolve(strict=True), args.candidate.resolve(strict=True)
    lab = boot.Lab(args.container)
    environment = lab.guest("cat /etc/openwrt_release; uname -r; cat /proc/1/comm\n").stdout
    assert "24.10.7" in environment and "6.6.141" in environment and "procd" in environment
    installed = lab.guest("opkg status openrhp | sed -n 's/^Version: //p'\n").stdout.strip()
    assert installed.split("-", 1)[0] == "0.1.0", "Provision a current feature-capable baseline first"
    lab.wait_api()
    assert api(lab, "/api/v1/maintenance/capabilities")["available"]
    config = api(lab, "/api/v1/config")
    assert config["network"]["enabled"] and config["policy"]["fallback"] == "closed"
    assert not routing_state(lab).get("maintenance_job"), "Another maintenance operation is active"
    helper_before = lab.guest("sha256sum /usr/libexec/openrhp-helper\n").stdout.split()[0]
    report = {"environment": environment, "scope": "isolated SDK fixtures on emulated OpenWrt; no physical acceptance", "checks": []}
    results = pathlib.Path("test-results/maintenance-boot")
    results.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openrhp-maintenance-signing-") as temporary:
        private = pathlib.Path(temporary)
        release_tool = private / "openrhp-release"
        command([os.environ.get("GO", "go"), "build", "-buildvcs=false", "-o", str(release_tool), "./cmd/openrhp-release"])
        key, public = private / "fixture.key", private / "fixture.pub"
        command([str(release_tool), "keygen", "--key", str(key), "--public-out", str(public)])
        base_commit = command(["git", "rev-parse", "HEAD"]).stdout.strip()
        report["fixture_manifest_base_commit"] = base_commit
        report["source_basis"] = "Current SDK working-tree fixtures; manifest commit is the base commit, not a clean release claim"
        bundles = []
        for directory, version in [(baseline, "0.1.0"), (candidate, "0.1.1")]:
            target = private / version
            artifacts = make_bundle(directory, version, key, release_tool, base_commit, target)
            bundles.append((target, artifacts))
        # Independent root administration provisions the test trust anchor once.
        # A preflight-only retry can reuse the existing authenticated cache;
        # its full package hash set must match the exact caller-selected inputs.
        existing = api(lab, "/api/v1/maintenance/bundles") if args.reuse_staged else []
        if not args.reuse_staged:
            lab.guest("mkdir -p /etc/openrhp-maintenance; chmod 0700 /etc/openrhp-maintenance; test ! -e /etc/openrhp-maintenance/trust.pub\n")
            lab.put_host_file(public, "/etc/openrhp-maintenance/trust.pub")
            lab.guest("chmod 0600 /etc/openrhp-maintenance/trust.pub\n")
        staged = []
        for index, (source, artifacts) in enumerate(bundles):
            if args.reuse_staged:
                hashes = sorted(artifact["sha256"] for artifact in artifacts)
                matches = [entry for entry in existing if entry["version"] == source.name and sorted(package["sha256"] for package in entry["packages"]) == hashes]
                assert len(matches) == 1, "Previously authenticated bundle does not exactly match the selected SDK files"
                staged.append(matches[0])
                continue
            target = "/root/openrhp-maintenance-bundle-" + str(index)
            lab.guest("mkdir -p " + target + "; chmod 0700 " + target + "\n")
            for path in source.iterdir():
                lab.put_host_file(path, target + "/" + path.name)
            summary = json.loads(lab.guest("chmod 0600 " + target + "/*; /usr/libexec/openrhp-helper maintenance-stage --source " + target + "\n").stdout)
            staged.append(summary)
            lab.guest("rm -f " + target + "/*; rmdir " + target + "\n")
        report["reused_authenticated_staging"] = args.reuse_staged
        report["authenticated_bundles"] = [{"id": entry["id"], "version": entry["version"], "commit": entry["commit"], "packages": entry["packages"]} for entry in staged]
        if args.reuse_staged:
            report.pop("fixture_manifest_base_commit", None)
        report["checks"].append("independent lab trust anchor and authenticated old/new actual SDK staging")
        print("PASS authenticated baseline and candidate SDK fixtures are available", flush=True)
        capture_filter = "(dst host 8.8.8.8 or dst host 2001:4860:4860::8888) and (port 28080 or port 28081 or port 53)"
        lab.container_command(["rm", "-f", "/tmp/openrhp-maintenance-flood.stop"])
        flood = boot.start_background(lab, "maintenance-traffic", "openrhp-client", FLOOD)
        atexit.register(lab.signal, flood, signal.SIGTERM, check=False)
        time.sleep(.3)
        first_progress = progress(lab)
        capture_path = "/tmp/openrhp-boot-maintenance-closed.pcap"
        capture = boot.start_capture(lab, capture_path, expression=capture_filter)
        plan = api(lab, "/api/v1/maintenance/plan", "POST", {"action": "upgrade", "bundle_id": staged[1]["id"], "components": ["openrhp"], "expected_installed_digest": ""})
        revision = api(lab, "/api/v1/config")["revision"]
        key_id = uuid.uuid4().hex
        # Deliberately discard the initial reply; retry exactly the same body/key.
        api(lab, "/api/v1/maintenance/operations", "POST", plan["request"], revision, key_id, check=False)
        lab.wait_api()
        replay = api(lab, "/api/v1/maintenance/operations", "POST", plan["request"], revision, key_id)
        operation = wait_job(lab, replay["id"])
        lab.wait_api()
        assert api(lab, "/api/v1/maintenance/operations/" + operation["id"])["state"] == "completed"
        assert routing_state(lab).get("maintenance_hold")
        assert lab.guest("sha256sum /usr/libexec/openrhp-helper\n").stdout.split()[0] == helper_before
        assert lab.guest("opkg status openrhp | sed -n 's/^Version: //p'\n").stdout.strip().split("-", 1)[0] == "0.1.1"
        management(lab)
        report["checks"].append("public API upgrade, discarded response and same-key replay, authoritative root completion, immutable guard retained")
        confirm_closed(lab)
        report["checks"].append("fresh confirmed network transaction clears maintenance hold")
        plan = api(lab, "/api/v1/maintenance/plan", "POST", {"action": "remove", "components": ["openrhp"], "removal_policy": "preserve-closed", "expected_installed_digest": ""})
        before = jobs(lab)
        revision = api(lab, "/api/v1/config")["revision"]
        api(lab, "/api/v1/maintenance/operations", "POST", plan["request"], revision, check=False)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (jobs(lab) - before):
            time.sleep(.2)
        created = jobs(lab) - before
        assert len(created) == 1, "Expected one durable removal job"
        wait_job(lab, created.pop())
        lab.guest("test ! -e /usr/bin/openrhp; test -x /usr/libexec/openrhp-helper\n")
        management(lab)
        assert progress(lab) > first_progress
        observed = boot.stop_capture(lab, capture, capture_path)
        command(["docker", "cp", lab.container + ":" + capture_path, str(results / "closed.pcap")])
        (results / "closed.txt").write_text(observed)
        assert not observed.strip(), "Protected traffic escaped during package maintenance:\n" + observed
        report["checks"].append("controller removal preserves closed routing and LAN management; trusted CLI reports completion after API removal; zero WAN packets throughout")
        # Restore only the already authenticated controller fixture for the second
        # policy case. This root fixture setup is not a public API operation.
        controller = next(p for p in staged[1]["packages"] if p["name"] == "openrhp")
        artifact = "/etc/openrhp-maintenance/artifact-" + controller["sha256"] + ".ipk"
        lab.guest("OPKG_CONF_DIR=/etc/openrhp-maintenance/empty-feeds opkg --conf /etc/openrhp-maintenance/opkg.conf install " + artifact + "\n/usr/libexec/openrhp-setup /root/openrhp-lab/admin.token\n")
        lab.wait_api()
        confirm_closed(lab)
        direct_path = "/tmp/openrhp-boot-maintenance-direct.pcap"
        direct_capture = boot.start_capture(lab, direct_path, expression=capture_filter)
        plan = api(lab, "/api/v1/maintenance/plan", "POST", {"action": "remove", "components": ["openrhp"], "removal_policy": "restore-direct", "expected_installed_digest": ""})
        before = jobs(lab)
        revision = api(lab, "/api/v1/config")["revision"]
        api(lab, "/api/v1/maintenance/operations", "POST", plan["request"], revision, check=False)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (jobs(lab) - before):
            time.sleep(.2)
        created = jobs(lab) - before
        assert len(created) == 1
        wait_job(lab, created.pop())
        time.sleep(.5)
        observed = boot.stop_capture(lab, direct_capture, direct_path)
        command(["docker", "cp", lab.container + ":" + direct_path, str(results / "direct.pcap")])
        (results / "direct.txt").write_text(observed)
        for address in ["8.8.8.8", "2001:4860:4860::8888"]:
            for port, tcp in [(28080, True), (28081, False), (53, True), (53, False)]:
                assert any(f"> {address}.{port}:" in line and ("Flags [" in line) == tcp for line in observed.splitlines()), ("Explicit direct policy did not restore expected traffic", address, port, tcp)
        management(lab)
        assert lab.guest("sha256sum /usr/libexec/openrhp-helper\n").stdout.split()[0] == helper_before
        report["checks"].append("separate explicit restore-direct removal restores IPv4/IPv6 TCP/UDP/DNS traffic while retaining guard package and LAN management")
        lab.container_command(["touch", "/tmp/openrhp-maintenance-flood.stop"])
        lab.signal(flood, signal.SIGTERM, check=False)
        (results / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        for check in report["checks"]:
            print("PASS " + check, flush=True)


if __name__ == "__main__":
    main()
