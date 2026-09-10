# Manual setup

There is no stable router release yet. Start with the local preview from the README,
or build a development package using [the SDK guide](openwrt-build.md) for a disposable
OpenWrt test device. Read [compatibility](compatibility.md) and prepare recovery first.
Installation assumes OpenWrt is already running; it never flashes factory firmware.

1. Install a verified matching package. The service initially leaves routing off.
   Use existing trusted administrator access to bootstrap the local access key.
   Open the management panel on loopback (an SSH tunnel is suitable), or at a LAN
   address configured with a trusted TLS certificate. Internet-facing access is not
   supported. The first visitor does not become the owner.
2. On **Connect to your gateway**, enter the local **Access key** and press
   **Connect**. The key remains in memory for this browser session.
3. Open **Access methods → Add access method**. Enter a name and choose a connection
   type. Direct access needs no extra configuration; proxy server/port/credentials
   have ordinary fields. A native connection exposes its supported import field.
   Press **Add method**.
4. Open **Overview → Add resource**. Enter an HTTPS address and expected status;
   mark resources that every usable path must reach as **Required for a usable path**.
   Add multiple independent resources. These are real network requests, so choose
   resources you want this gateway to visit.
5. Press **Check all methods**, or **Check** beside one method. Review the measured
   status and freshness. A dash means no measurement; errors are not zero latency
   or packet loss. Resolve missing-engine and resource failures before continuing.
6. Under **Path selection**, choose **Automatic**, or **Keep one method**, then
   **Save selection**. **Selection thresholds and fallback** exposes the advanced
   policy. Direct fallback is never enabled implicitly.
7. Open **Gateway setup and diagnostics**. Use detected LAN/WAN devices and local
   subnets. Choose a DNS policy and explicit resolver when using selected-path DNS.
   Save the plan, then **Prepare routing**. Unsupported features stop preflight.
8. Apply only after reviewing the plan and preparing local recovery. Press
   **Apply with rollback timer**. Test management, DNS, internet and local services
   from an actual LAN client, including required UDP/IPv6 behavior. Then press
   **Confirm tested connectivity**, or **Roll back**. The independent timer does not
   require this browser to remain open. Test its operation on your device first.
9. Optionally open **Coverage → Add an access point**. Install its node agent,
   verify its fingerprint through trusted access, and enter the node's HTTPS
   address and one-time pairing code. [The coverage guide](coverage.md) describes
   compatible Wi-Fi/Ethernet modes, actual pair verification and the coordinated
   Wi-Fi transaction with separate local rollback processes on both devices.

**Traffic routing is not applied** is intentional: configuring/checking a method
is distinct from changing LAN routing. Never interpret a healthy gateway probe as
proof that a second AP's clients have working DHCP, DNS or internet.

Use **Sign out** to clear the browser's key. Use **Download diagnostics** for a
redacted report. Changes made by another UI or agent cause a revision conflict;
refresh and review the new state before saving your edit again.

## Choose which destinations use bypass

New installations default to **Only blocked destinations**, with interception still
off. Open **Selective routing and blocked destinations** to review Antifilter
provenance, exact-domain/IP exceptions, and emergency direct behavior. Detection is
off until you explicitly choose control resources. Save, prepare, apply and confirm
a network transaction; saving alone never changes the network. Old configurations
retain their previous all-traffic behavior until this explicit migration.

Ordinary destinations use WAN; failures of a bypass method should affect only bypass
traffic. Classifier or managed DNS failure restores ordinary WAN and DNS, as
explicitly permitted by the profile. That recovery can interrupt sessions and
require a DNS-cache refresh. See [selective routing](selective-routing.md).
