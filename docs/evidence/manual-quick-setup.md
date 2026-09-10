# Manual Quick setup browser smoke

This is a separate manual acceptance script for the actual booted OpenWrt guest.
It is not part of the ordinary browser fixture suite and does not replace physical
router or radio testing. The harness is prepared; its full guest run has not been
executed. Further VM scenarios and physical installation were deferred at the
user's request on 2026-09-09 while the current changes are submitted for review.

Prerequisites:

- The verified `routeharbor-openwrt-boot-lab` full-system VM, using Docker network
  `none`, no published ports and the existing pinned SSH identity.
- A clean installed and bootstrapped package baseline: routing off, policy off,
  no sources or resources, no maintenance hold/job and an available root helper.
  The harness refuses to replace an existing configuration.
- The default guest listener `127.0.0.1:8787` and the same free host loopback port.
  A TCP relay preserves the exact Host/Origin bytes; it does not weaken server
  origin validation or expose a LAN/public listener.
- Development dependencies installed from `tests/browser/package-lock.json`,
  including Playwright's Chromium. Node is only a development test dependency.
- No other process using the synthetic WAN fixture ports 443, 53 or 18081.
  The harness refuses occupied ports and never kills another task's responder.

Run only after the VM has been explicitly handed to this test:

```sh
node scripts/lab-openwrt-quick-setup.mjs --run
```

The script follows [Manual setup](../quick-setup.md) through the real UI: login,
add Direct access, add an HTTPS resource, perform actual measurements, save a
fixed method with closed fallback, enter detected gateway devices/local prefixes,
prepare, apply with the independent timer, test from the LAN namespace, confirm
and sign out. API calls outside the browser are read-only assertions. There are
no intercepted API responses or replacement browser fixtures.

Successful offline HTTPS checks use a dedicated synthetic WAN responder at the
private `8.8.8.8` alias. A newly generated one-day laboratory CA is installed as
one uniquely named guest trust file. Existing CA files and bundles are never
rewritten. Positive calibration checks IPv4/IPv6 HTTPS, UDP, TCP/UDP53 and LAN SSH
before routing changes. The applied Direct path must preserve IPv4 HTTPS/UDP and
LAN management while selected-path DNS uses the explicit `8.8.8.8` resolver and
external IPv6 is blocked. Post-apply TCP/UDP53 requests to `1.1.1.1`, which has no
test responder, must reach the selected resolver by actual destination NAT.
These are private namespace test addresses. This checks port53 interception;
valid uncached resolver forwarding has its separate DNS lab.

The current router-recursive DNS limitation also applies here: the independent
dnsmasq UID guard blocks that daemon's uncached upstream requests even with
Direct selected. The client selected-path DNS check does not prove that router
applications using dnsmasq, such as package tools or NTP, can resolve uncached
names. The smoke result must retain this explicit limitation.

The access key is read through pinned SSH into process/browser memory. It is not
put in arguments, environment variables, logs, browser storage or artifacts.
Raw Playwright traces and HAR are deliberately disabled because they can retain
Authorization headers and input values. Instead, the evidence file contains an
allowlisted action/response timeline, actual build hashes, traffic booleans and
SHA-256 hashes for desktop/mobile screenshots. Screenshots are taken only with
the credential input empty or hidden after successful login.

The `finally` cleanup closes the browser and loopback relay, drains only uniquely
tagged SSH processes, stops only the responder bearing this run's unique path,
removes the new CA and synthetic private keys, and restarts the controller to
discard its cached laboratory trust. Service stop retains quarantine. The saved
UI configuration is left in this disposable guest for review; its synthetic
resource is intentionally unavailable after cleanup. Restore the named pristine
checkpoint before another clean acceptance run.

Artifacts are written under `test-results/openwrt-quick-setup-<run-id>/`, excluded
from Git. A local relay-only check uses an echo child and accesses no VM:

```sh
node scripts/lab-openwrt-quick-setup.mjs --self-test
```
