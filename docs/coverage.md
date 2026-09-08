# Coverage nodes

OpenRHP keeps one gateway responsible for routing and path selection. A coverage
node bridges clients into that gateway's LAN. Node link quality is separate from
WAN measurements: a slow wireless uplink must not trigger a VPN/DPI switch.

The English **Coverage** panel pairs an access point, reads its detected bridge,
management address, cable ports, and radios, then guides **Connection → Review →
Test and confirm**. The normal path uses labelled fields and never requires a
user to compose JSON. **Review setup** checks the plan; **Prepare access point**
stores the participant snapshots; **Apply with a 90-second rollback timer** starts the
change. Confirmation remains disabled until the user records the management,
address/DNS, and client traffic checks. **Roll back** is available before confirmation
starts; an uncertain `confirming` result must reconcile because the node may already
have committed. **Refresh access point status** reads the persisted transaction
instead of assuming an interrupted request succeeded.

The node agent, pairing protocol, both gateway/node UCI backends and independent
rollback journals are implemented. The gateway adopts an explicitly approved,
detected main AP; it preserves LAN/WAN addresses, DHCP, NAT and unrelated wireless
settings. Its existing Wi-Fi password is transferred privately to the paired node
and never through the browser. The public API accepts a `gateway_plan` alongside
the node plan for managed Wi-Fi; Ethernet retains its existing node-only flow.

Generic radio advertisements remain insufficient. Both devices require current,
root-recorded verification for the exact reciprocal TLS identities, radio and
mode. See [wireless-verification.md](wireless-verification.md) for the live evidence,
client checks, commands and expiry policy. **No physical WDS, mesh, or Ethernet
device pair is certified by our automated tests.** Tests exercise real local TLS,
the upstream UCI parser, private receipt storage and detached rollback processes;
they do not substitute for qualifying the actual device pair.

Wi-Fi operations return one durable paired transaction with separately reported
gateway and node participants. Apply runs gateway first, then node; confirmation
retains a gateway compensation snapshot until the node's confirmation is known.
Interrupted confirmation remains `confirming` and resumes from the durable intent.
This is recoverable sequential coordination, not globally atomic two-device change.

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
   known nodes, `gateway_fingerprint`, gateway capabilities, detected
   `gateway_setup.aps`, and explicit address entry; it does not grant authority or
   claim a subnet scan happened.
2. Pair with `POST /api/v1/nodes/pair`, passing `address`, `fingerprint`, `code`, and
   an optional `name`. `address` must be an HTTPS origin using an explicit private
   or loopback IP literal. Redirects, URL credentials, query strings, and arbitrary
   public endpoints are rejected. The one-time code is not retained in gateway
   records. If the enrollment response is lost, retrying can recover the existing
   authenticated association through the node's capabilities endpoint.
3. Preview a full node plan with `POST /api/v1/nodes/{id}/plan`. Wi-Fi modes are
   offered before Ethernet only when both peers prove the required capabilities
   with reciprocal identity/radio/mode verification. Include `gateway_plan` in the
   flat node-plan body for Wi-Fi, selecting the explicitly adopted detected AP.
   Stock firmware without a verified device adapter receives no automatic plan.
4. Prepare with `POST /api/v1/nodes/{id}/prepare`, passing an operation object:
   `{"key":"a-unique-operation-key","plan":{...}}` for Ethernet; managed Wi-Fi
   additionally includes `gateway_plan` alongside `plan`. The gateway privately
   derives the shared AP settings, then both participants validate and store their
   own snapshots. Repeating the same key and plan returns the same transaction;
   using that key for another plan is rejected.
5. Apply with `POST /api/v1/nodes/{id}/apply`, passing
   `{"id":"TRANSACTION_ID","timeout_seconds":90}`. Use the aggregate paired
   transaction ID for Wi-Fi or the node transaction ID for Ethernet. The window
   must be 30–180 seconds. Each root helper persists its deadline and waits for its
   detached watchdog's readiness acknowledgement before changing UCI. Wi-Fi applies
   the gateway first and gives the node the remaining confirmation window.
6. Check `GET /api/v1/nodes/{id}/status`, then verify the node management address,
   client DHCP, DNS, address visibility at the gateway, LAN access, and real client
   traffic through the selected gateway policy. An HTTP success from the gateway
   is not a substitute for these checks.
7. Confirm with `POST /api/v1/nodes/{id}/confirm` and `{"id":"TRANSACTION_ID"}`.
   A Wi-Fi `confirming` result is unfinished: read status and retry the same
   confirmation. The gateway retains compensation until node confirmation is known,
   then finalizes. Manual rollback is rejected during uncertain confirmation to
   avoid removing backhaul behind a committed node. Prepared/applied transactions
   can use `/rollback`. Lost gateway, WAN, browser, or TLS-agent process does not
   cancel an armed local deadline; helper restart resumes interrupted rollback.
8. Revoke with `DELETE /api/v1/nodes/{id}`. The gateway first revokes its certificate
   on the reachable node, then removes the local record. An offline node produces
   an explicit failure; it is not reported as remotely revoked. Revocation does
   not rotate the shared Wi-Fi password.

Mutation responses may wrap the result in the gateway's operation envelope; the
transaction ID inside that result is distinct from the asynchronous API operation
ID. Wi-Fi participant IDs are status details and cannot bypass the paired coordinator.

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

A verified wireless node plan additionally supplies `radio`, `uplink` for the
wireless link, and `ethernet_uplink` identifying the
physical backhaul port that must leave the bridge. The current model places AP
clients and backhaul on one radio, so `share_radio: true` and verified concurrent
mode support are required. Removing the Ethernet uplink before activating WDS or
mesh, and removing the wireless backhaul before returning to Ethernet, enforce a
single active uplink. This reserves that physical port while Wi-Fi is active.
The public `gateway_plan` selects the detected main AP by `ap_section` and `network`,
binds `peer_fingerprint` and `mode`, and requires `adopt_existing_ap: true` plus
`preserve_management_path: true`. The gateway helper supplies `ssid`, `passphrase`
and `channel` to the node privately; the normal managed setup does not ask the user
to re-enter them. A trusted direct node operation still uses the complete narrow
node plan and does not configure the gateway counterpart.

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
The actual pair must first be qualified, and the coordinated apply provisions the
gateway-side backhaul before changing the node. Shared radio airtime can reduce
throughput. A common SSID does not
guarantee client roaming, and 802.11s backhaul does not imply 802.11r support.

## Synchronize a separately changed home Wi-Fi key

Revoking node management leaves the Wi-Fi key unchanged. Credential changes use
the existing node `Plan` fields and a new preparation, separately from unpairing.
OpenRHP does not provide a privileged operation that writes a new main-AP password.

1. Finish any pending transaction. Preserve independent wired management to both
   routers and a private backup of the old main-AP settings. Do not create a second
   active bridged uplink as a recovery shortcut.
2. Explicitly change the main AP's key through trusted OpenWrt administration.
   This can disconnect Wi-Fi clients and backhaul immediately. This administrator
   action is outside OpenRHP's paired transaction and is not silently performed by
   discovery, unpairing, or an ordinary retry.
3. For managed Wi-Fi, review the same adopted AP through **Set up connection** and
   create a fresh preparation. API users supply a **new** prepare `key` with the
   ordinary node plan and `gateway_plan`. The gateway privately reads the current
   home key and sends it to the node; applying also updates the owned mesh section
   when using mesh. Reusing the old idempotency key returns the old transaction and
   does not synchronize a new password. Valid pair verification remains required.
4. Apply with the independent rollback timers, reconnect actual clients using the
   intended key, verify management, addressing/DNS and gateway traffic policy,
   then confirm. An Ethernet-connected AP can instead receive explicit updated
   `ssid`/`passphrase` fields through its existing node-only plan.

The rollback boundary matters: the gateway snapshot contains its adopted WDS flags
and owned mesh settings, **not the administrator-edited main-AP password**. An abort
can restore the node and owned mesh to their previous credentials while the main
AP still has its new key. Restore the old main-AP settings separately through the
preserved wired administrator path if abandoning the change. A shared key change
affects every device using it; this flow does not claim atomic rotation across all
home clients or multiple APs.

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

`go test -race ./internal/node ./internal/coverage` covers unique and persistent identities, exact
certificate pinning, unauthorized client rejection, code expiry and attempt
limits, replay prevention, enrollment races, gateway-to-node TLS operations,
revocation, capability intersection, one-uplink command generation, preflight
rejection before mutation, UCI argument safety, idempotent transactions, watchdog
readiness before apply, independent journal recovery, and interrupted rollback
retry. Paired regressions cover gateway-first ordering, lost prepare/confirmation/
finalization responses, restart reconciliation, node-deadline compensation, reciprocal
receipt checks, revoked evidence before apply, participant-ID rejection, and private
credential erasure. Gateway/node UCI effects are injected fixtures in these tests.
The TLS integration test needs permission to bind loopback sockets.
The key synchronization regression uses both real durable transaction managers and
the pinned node TLS protocol with injected UCI effects. It proves that a new prepare
uses the current private gateway key, an old request does not silently rotate it,
and public results and confirmed node state do not retain that credential.

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
network apply is fabricated in that integration suite. The separate
`coverage-ui.spec.js` uses explicit UI-only response fixtures to exercise Wi-Fi
choice, AP adoption, no password request and pending confirmation; those fixtures
are not router execution evidence.

Physical acceptance remains separate: test both Ethernet and each available
wireless mode with a real client; capture DHCP and IPv6 RA; verify client MAC/IP
visibility and the gateway policy; kill the TLS agent and root helper during an
unconfirmed apply; verify local watchdog recovery; unplug each uplink; and confirm
management access after rollback. Record device, OpenWrt version, package
architecture, driver/radio capabilities, and observed results before advertising
that device pair as supported.
