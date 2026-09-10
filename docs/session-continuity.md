# Session continuity through a private relay

The optional `continuity` profile keeps destination-side TCP and UDP sockets on a
relay that you administer. Access methods carry encrypted traffic to that same
relay. A path switch can resume the existing logical session through another ready
carrier while the relay retains the destination socket and its external address.
The relay is an additional trusted component and a point of failure. A relay reboot,
expired disconnected grace, exhausted resources, or an unavailable standby can still
interrupt traffic. No fixed switch-latency guarantee has been established.

In selective routing, only blocked/bypass destinations use the relay. Ordinary
traffic leaves directly through WAN. A direct source may transport encrypted traffic
to the relay; it never becomes a direct fallback for a bypass destination.

New workers prepare an authenticated loopback SOCKS5 bridge alongside their legacy
transparent listeners. The private bridge stays dormant in legacy routing; a
confirmed routing transaction chooses which input receives application traffic.
Moving between legacy and selective routing with unchanged relay, network and
source allocations therefore keeps the same worker and relay session. The bridge
accepts TCP and bounded UDP associations to numeric public destinations only. Its
random credentials remain in private process configuration and never appear in
status, ordinary diagnostics, command arguments or the transaction journal.

Without this optional profile, path selection sends new bypass connections through the
selected source. Existing marked connections retain their previous prepared path;
there is no application traffic replay across unrelated external IP addresses.
Old configuration files omit `continuity` and keep that behavior.

## Pair your own VPS

Build `cmd/openrhp-relay` for the VPS architecture and install it as
`/usr/local/bin/openrhp-relay`. Create an unprivileged `openrhp-relay` account with no
interactive shell. Give it a 0700 state directory `/var/lib/openrhp-relay`. Run
`openrhp-relay identity --state /var/lib/openrhp-relay` as that account. This creates
or reuses a private identity and prints only its public SHA256 fingerprint. Keep
private identity files on their own machine and back them up through trusted local
administration. Never paste private keys into the web interface or command arguments.

Install the optional `openrhp-continuity` IPK on the gateway using a verified local
package or authenticated maintenance bundle. The package installs a helper-supervised
worker; installing it does not enable interception or start an independent service.
Create `/etc/openrhp/continuity` owned by the unprivileged `openrhp` account with
mode 0700. Run `/usr/libexec/openrhp-continuity identity --state /etc/openrhp/continuity`
as that account through trusted gateway administration. Root-owned private identity
files cannot be read by the control service. Exchange the two public certificate fingerprints
through your existing trusted access to the gateway and VPS. The UI also shows the
worker's public pairing fingerprint when available.

Create `/etc/openrhp-relay/config.json`, owned by the relay account and mode 0600:

```json
{
  "listen": "YOUR_VPS_IP:8443",
  "client_fingerprints": ["YOUR_GATEWAY_SHA256_FINGERPRINT"]
}
```

Replace both placeholders. `listen` binds the explicitly chosen numeric address;
use an unprivileged port such as 8443 with the provided
[systemd unit](../packaging/systemd/openrhp-relay.service). Permit the relay listener
through your VPS firewall as appropriate for your own paths. The service runs as the
relay account with a private state directory and no elevated network capabilities.
The listener refuses wildcard or hostname addresses. The private config may also
set `max_clients` (default 16, maximum 256) and an optional `limits` object with
`buffer_bytes`, `udp_reserve_bytes`, `flow_bytes`, `control_bytes`, `max_tcp`,
`max_udp`, `disconnected_grace_seconds`, `udp_idle_seconds`, and `udp_replay_ms`.
Omitted/zero limits use the core defaults; invalid limits fail before listening.
Keep administrative access available while changing that host's firewall.

In the gateway's **Session continuity through your relay** panel, set the explicit
public relay IP and port and verify its 64-character SHA256 certificate fingerprint.
Use closed fallback and turn off connection tracking reset. Save settings, then
prepare, apply, and confirm the gateway routing plan after testing connectivity.
Saving a profile is separate from confirming network activation. To change an
active worker's relay, buffer/grace settings or prepared source set, first disable
continuity and confirm that routing change. Then edit and prepare the new profile.
Changing the active worker inventory in place would terminate protected sessions. No relay hostname,
public provider, credential, or direct bypass is chosen automatically.

## Buffers and limits

The default total buffering budget is 32 MiB, with a 4 MiB UDP reserve and 30 seconds
of disconnected grace. Configuration allows 2–64 MiB total, a UDP reserve of at least
512 KiB that leaves more than 512 KiB for worker queues, and 1–300 seconds of grace.
At defaults, the 32 MiB application budget allocates 29.5 MiB to the worker core
(including 2 MiB for UDP), 2 MiB to helper UDP reply queues, and 512 KiB to fixed
ingress staging and mapping reservation. The displayed queued total includes this
reservation. A separate bounded 256 KiB service/control queue sits outside the
32 MiB budget and is displayed separately. These are application buffer
limits; they are not the entire process or operating-system memory footprint.
Bounded flow counts and per-flow/control budgets also protect the worker and relay.
The relay budgets apply per logical session; `max_clients` also bounds its session
count, so relay-wide memory can exceed one session's configured buffer.
Changing those limits does not create more RAM on a router.

TCP uses logical sequence numbers, acknowledgement and bounded replay. Backpressure
slows senders when buffers fill. UDP retains datagram boundaries and has bounded
short replay/expiry; stale or excess datagrams are dropped and counted. A UDP media
application can notice loss or jitter even when the logical session survives.
Neither replay nor an unchanged external address promises zero packet loss.

A ready standby must already reach the same authenticated relay through another
usable access method. Readiness is measured per carrier; saved source settings alone
are not evidence of a live standby. If the preferred path is unavailable, session
continuity can use its established standby within the grace and buffer limits.
It cannot repair a shared WAN outage that also prevents every standby from reaching
the relay. Restarting the relay loses its destination sockets; reconnecting cannot
restore those old sessions merely by reusing a fingerprint.

## Observe and verify

`GET /api/v1/continuity` returns public settings (or `null`) and an ETag.
Admin-only `PUT /api/v1/continuity` takes the complete public object or `null`, with
quoted `If-Match` and an `Idempotency-Key`. `GET /status` supplies the worker's
allowlisted continuity observation: readiness, active/standby paths, queue bytes,
flow counts, replayed frames, expired/dropped UDP, switch count, and the last measured
path-change-to-first-acknowledgement interval. That interval excludes failure
detection and does not measure the application's end-to-end interruption. An absent measurement is unknown, not zero. `qualified:false` means
that a latency claim has not been established for the current device/path profile.

Test a continuous TCP transfer and a sequenced UDP stream from an actual LAN client.
Record external address, connection identity, TCP byte integrity, UDP gaps/duplicates,
queue pressure and the interval around each cutover. Exercise both a healthy manual
switch and a failed carrier, then all-carrier failure, grace expiry, standby recovery,
relay restart and bounded-buffer pressure. Keep the gateway management path available.

Evidence must be reported separately: deterministic unit/socket tests, real Linux
kernel interception, OpenWrt SDK package output, booted OpenWrt VM, and the specific
physical gateway/VPS/LAN clients. A passing build or socket test does not demonstrate
physical latency, WAN resilience, OpenWrt boot ordering, or a sub-100 ms pause. The
existing boot evidence predates this feature and must not be treated as continuity
acceptance. No physical device has been changed as part of this implementation.

For the development Linux image, run `sh scripts/lab-continuity-transparent.sh`.
It builds the current helper and worker, then runs a disconnected Docker container
with separate LAN, relay and destination network namespaces. The real helper RPC,
supervisor, unprivileged worker, TPROXY and conntrack path carry TCP, UDP and router
DNS traffic through an authenticated relay. The test checks repeated UDP on the
same path, destination socket identity through three path changes, binary and empty
datagrams, and unchanged LAN rules. The two named carriers share one synthetic
egress, so this proves functional continuity rather than independent WAN failover
or a measured device latency target. The relay uses the real core and destination
policy within the test executable; the separate relay CLI has focused tests.

In selective mode, classifier or managed DNS failure follows the explicit emergency
direct policy documented in [selective-routing.md](selective-routing.md). Worker
or relay failure alone does not invoke it and does not disturb ordinary direct
traffic. A comparative restriction probe must test the actual relay exit.
