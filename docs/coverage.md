# Coverage nodes

OpenRHP keeps one gateway responsible for routing and path selection. A coverage
node bridges clients into that gateway's LAN. Node link quality is separate from
WAN measurements: a slow wireless uplink must not trigger a VPN/DPI switch.

The English **Coverage** panel pairs an access point, reads its detected bridge,
management address, cable ports, and radios, then guides **Connection → Review →
Test and confirm**. The normal path uses labelled fields and never requires a
user to compose JSON. **Review setup** checks the plan; **Prepare access point**
stores the node snapshot; **Apply with a 90-second rollback timer** starts the
change. Confirmation remains disabled until the user records the management,
address/DNS, and client traffic checks. **Roll back** and **Refresh access point
status** remain available for the active transaction. Reopening setup reads the
persisted node transaction instead of assuming an interrupted request succeeded.

The node agent, pairing protocol, capability checks, typed UCI backend, and local
rollback journal are implemented. Automated tests exercise real local TLS
enrollment and a simulated UCI command boundary. **No physical WDS, mesh, or
Ethernet device pair is certified by these tests.** Generic OpenWrt discovery
currently reports WDS, encrypted mesh, and concurrent-radio compatibility as
unverified; those options remain unavailable until a platform adapter can prove
the specific pair's capabilities. Compilation alone does not enable them.
**Gateway-side wireless backhaul provisioning is not implemented in this
version.** A compatible gateway backhaul must already be established and verified;
the capability `gateway_backhaul_ready` remains false in production discovery.
This is an explicit blocking gate for automatic Wi-Fi setup, not a claim that a
wireless coverage feature has been delivered or certified.

## Trust and bootstrap

Discovery gives no control. Enter the node's explicit LAN HTTPS address, then
verify its certificate fingerprint using the existing trusted SSH connection or
another established administrator channel. The agent does not enroll the first
LAN caller, scan for credentials, disable TLS verification, or trust an arbitrary
discovered AP.

The same `openrhp-node` binary runs in two separate processes:

- `serve` runs as an unprivileged service user, owns its unique Ed25519 identity,
  and exposes the authenticated TLS 1.3 node protocol.
- `helper` runs as root and accepts only typed node operations from that service
  user's Unix socket connection. Socket permissions and Linux peer credentials
  both enforce this boundary. The helper owns UCI snapshots and the rollback
  journal. `serve` explicitly refuses to run as root.

Create the service user and private directories as part of the OpenWrt package
installation. Use the actual assigned UID and the device's discovered LAN
address; the following flags describe the installed commands, not fixed network
interface names:

```text
openrhp-node helper --state-dir /etc/openrhp-node-helper \
  --helper-socket /var/run/openrhp-node-helper.sock --uid NODE_SERVICE_UID

openrhp-node serve --state-dir /etc/openrhp-node \
  --helper-socket /var/run/openrhp-node-helper.sock --listen NODE_LAN_IP:9844
```

Run bootstrap through existing administrator access **as the node service user**
so the private identity belongs to the TLS agent:

```text
openrhp-node bootstrap --state-dir /etc/openrhp-node \
  --enrollment-file /etc/openrhp-node/enrollment-code
```

Bootstrap writes the code to a new 0600 file and prints only the public device ID,
fingerprint, file path, and expiry. The code expires after ten minutes, has five
attempts, and can be consumed once. State changes are atomic and serialized across
processes. Transfer the code privately and remove the transient code file after
pairing. Reissuing a challenge on an already enrolled device is rejected. Each
node and gateway has a different certificate; a gateway validates the exact
administrator-verified node certificate on every connection, and the node binds
the gateway's presented client certificate when it consumes the code.

Certificates expire after one year. Certificate renewal or recovery from a lost
identity currently requires trusted local administrator access and a fresh
pairing; there is no universal recovery credential or silent trust reset.

## Gateway API flow

The gateway's authenticated `/api/v1` interface drives both UI and agent flows.
Use the normal administrator authorization, revision, and idempotency headers
documented in the API contract. Keep enrollment codes and Wi-Fi keys out of URLs,
logs, and shared examples.

1. Read `GET /api/v1/nodes` and `POST /api/v1/nodes/discover`. The latter reports
   known nodes, gateway capabilities, and explicit address entry; it does not
   grant authority or claim a subnet scan happened.
2. Pair with `POST /api/v1/nodes/pair`, passing `address`, `fingerprint`, `code`, and
   an optional `name`. `address` must be an HTTPS origin using an explicit private
   or loopback IP literal. Redirects, URL credentials, query strings, and arbitrary
   public endpoints are rejected. The one-time code is not retained in gateway
   records. If the enrollment response is lost, retrying can recover the existing
   authenticated association through the node's capabilities endpoint.
3. Preview a full node plan with `POST /api/v1/nodes/{id}/plan`. Wi-Fi modes are
   offered before Ethernet only when both peers prove the required capabilities.
   Stock firmware without a verified device adapter receives no automatic plan.
4. Prepare with `POST /api/v1/nodes/{id}/prepare`, passing an operation object:
   `{"key":"a-unique-operation-key","plan":{...}}`. The node validates the plan
   again and stores its own snapshot. Repeating the same key and plan returns the
   same transaction; using that key for another plan is rejected.
5. Apply with `POST /api/v1/nodes/{id}/apply`, passing
   `{"id":"NODE_TRANSACTION_ID","timeout_seconds":90}`. The confirmation window
   must be 30–180 seconds. The root helper persists the deadline and waits for a
   detached watchdog's readiness acknowledgement before changing UCI.
6. Check `GET /api/v1/nodes/{id}/status`, then verify the node management address,
   client DHCP, DNS, address visibility at the gateway, LAN access, and real client
   traffic through the selected gateway policy. An HTTP success from the gateway
   is not a substitute for these checks.
7. Confirm with `POST /api/v1/nodes/{id}/confirm` and `{"id":"NODE_TRANSACTION_ID"}`.
   On failure, call the matching `/rollback` operation. Lost gateway, WAN, browser,
   or TLS-agent process does not cancel the node's persisted rollback deadline.
   A helper restart resumes overdue or interrupted rollback.
8. Revoke with `DELETE /api/v1/nodes/{id}`. The gateway first revokes its certificate
   on the reachable node, then removes the local record. An offline node produces
   an explicit failure; it is not reported as remotely revoked. Revocation does
   not rotate the shared Wi-Fi password.

Mutation responses may wrap the result in the gateway's operation envelope; the
node transaction ID inside that result is distinct from the gateway operation ID.

## Supported plan boundary

The current UCI backend adopts an explicitly identified, existing management
bridge. Its `management_interface`, `bridge_section`, and `bridge_device` must
match discovered UCI state. A pre-reserved static management address stays
unchanged throughout the transaction; changing that address is a separate
administrator operation. Existing bridge ports are preserved as client ports
except the explicitly identified inactive uplink.

An Ethernet plan specifies `mode: "ethernet"`, one `uplink` from `lan_ports`, the
existing `management_address` as an IPv4 CIDR, and the main `gateway_address` in
that LAN. It disables DHCPv4, DHCPv6, RA, and NDP relay on the adopted scope and
removes any OpenRHP-owned wireless backhaul. It rejects unrelated active DHCP
scopes, any node masquerading, and conflicting foreign radio configurations.
Those conflicts must be resolved explicitly during preflight; unrelated WAN,
PPPoE, and Wi-Fi configuration is not silently taken over.

Bridge conversion also requires the existing dnsmasq and odhcpd service scripts;
preflight rejects missing tools before any mutation. Pairing and status remain
usable without these conversion tools. Radio changes additionally require the
OpenWrt `wifi` reload tool; an Ethernet conversion that changes no radio does not
invoke it. The package does not silently replace the user's DHCP implementation.

A verified wireless plan additionally supplies `radio`, `ssid`, `passphrase`,
`channel`, `uplink` for the wireless link, and `ethernet_uplink` identifying the
physical backhaul port that must leave the bridge. The current model places AP
clients and backhaul on one radio, so `share_radio: true` and verified concurrent
mode support are required. Removing the Ethernet uplink before activating WDS or
mesh, and removing the wireless backhaul before returning to Ethernet, enforce a
single active uplink. This reserves that physical port while Wi-Fi is active.

Every plan requires `preserve_management_path: true` and keeps `dhcp_server`,
`nat`, and `router_advertisements` false. A plan containing an executable, script,
file path, unknown property, or additional listener fails strict decoding. UCI
receives only fixed executable paths and validated arguments. Wi-Fi passphrases
are single-quoted using [UCI's own escaping
convention](https://github.com/openwrt/uci/blob/74f6277aabffc943d026f406df57c22595134c42/file.c)
and sent through stdin to a fixed `uci -q batch` invocation. Keys never enter
process arguments; control characters are rejected, and quotes, backslashes,
comments, semicolons, and substitution syntax remain literal data. Ordinary plans
and status responses omit the passphrase and rollback snapshot.

Gateway and node changes are sequential; no distributed atomic commit is claimed.
The gateway-side backhaul must already be available and verified before changing
the node. Shared radio airtime can reduce throughput. A common SSID does not
guarantee client roaming, and 802.11s backhaul does not imply 802.11r support.

## Local uplink observations

The node status exposes a separate `node_link` object for the applied or confirmed
plan. The Coverage wizard refreshes it every ten seconds while visible (five
seconds during a transaction). It reads the selected Ethernet interface's kernel
carrier and cumulative RX/TX byte, error and drop counters. Wireless plans resolve
the owned backhaul interface through actual `ubus network.wireless status`, then
read `iw station dump` signal and radio rates when exactly one peer is identified.
No raw station address or configuration key appears in the response.

Unknown, missing, malformed or ambiguous measurements are JSON `null` and shown
as **Unavailable**. Carrier up proves a local link only; byte totals are cumulative
counters, error counters are not measured packet loss, and radio bitrates are not
useful client download speed. These values do not enter the WAN selector. Before
an applied plan identifies the uplink, or after rollback without an attributable
plan, the status remains explicitly unavailable.

## Validation and recovery evidence

`go test -race ./internal/node` covers unique and persistent identities, exact
certificate pinning, unauthorized client rejection, code expiry and attempt
limits, replay prevention, enrollment races, gateway-to-node TLS operations,
revocation, capability intersection, one-uplink command generation, preflight
rejection before mutation, UCI argument safety, idempotent transactions, watchdog
readiness before apply, independent journal recovery, and interrupted rollback
retry. The TLS integration test needs permission to bind loopback sockets.

`scripts/lab-uci.sh` builds the upstream OpenWrt UCI parser and libubox at pinned
commits in a separate Docker image. It verifies exact secret round trips through
the real parser with adversarial quote/backslash/metacharacter values, no secret
arguments, no assignment output, and no injected commands or sections. This
parser check complements the command-boundary tests; it does not prove wireless
driver or physical network behavior.

`scripts/lab-node-link.sh` runs a real Linux veth pair in a Docker network namespace
with no external network. It verifies observed carrier up/down and an increased
TX byte counter after a real Ethernet frame. Unit tests cover missing and malformed
sysfs values, bounded station parsing, ambiguous peers, and read-only command
allowlists. This is Linux interface telemetry evidence, not OpenWrt radio or client
connectivity certification.

The default browser coverage test uses the real local gateway API for rejected
unverified pairing and checks credential clearing and mobile layout. The complete
paired-node prepare/apply/rollback browser test is opt-in and remains skipped until
an explicitly configured isolated OpenWrt coverage lab is supplied; no successful
network apply is fabricated in the browser tests.

Physical acceptance remains separate: test both Ethernet and each available
wireless mode with a real client; capture DHCP and IPv6 RA; verify client MAC/IP
visibility and the gateway policy; kill the TLS agent and root helper during an
unconfirmed apply; verify local watchdog recovery; unplug each uplink; and confirm
management access after rollback. Record device, OpenWrt version, package
architecture, driver/radio capabilities, and observed results before advertising
that device pair as supported.
