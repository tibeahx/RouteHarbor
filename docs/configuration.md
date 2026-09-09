# Configuration

Schema 1 lives in `internal/model` and `api/openapi.yaml`. The private JSON file is
`config.json` under the chosen state directory. The directory is 0700; files are
0600, directory-anchored and atomically replaced with fsync. Concurrent writers
must match the current revision. Unknown versions, duplicate JSON keys, unknown
fields, invalid enum values and oversized documents are rejected.

The initial role is `gateway`. Sources and targets are empty. Selection is off;
fallback is `closed`. The `node` role never runs a competing gateway selector.
Source configuration is portable; select physical interfaces again on each device.
Do not restore another device's interface mapping without a new preflight.

## Sources and measurements

Every source has a stable safe `id`, a display `name`, `type`, `enabled`, `auto` and
adapter-specific `settings`. `auto:false` excludes a source without deleting its
credentials. `enabled:false` stops its engine. There is no fixed saved-source
count: the 1 MiB configuration limit protects memory, and simultaneous paths are
limited by available memory, engine resources, ports and routing slots.

See [probe-paths.md](probe-paths.md) for exact import formats and version pins.
A successful import only means the safe configuration subset is valid; it does not
prove engine installation, network availability, UDP support or real LAN behavior.

Targets contain `id`, `url`, `required`, `status_codes`, `max_bytes`. They must use
HTTPS port 443. Credentials/fragments, private or special-use destinations and
redirects are refused. Body budget is at most 8 MiB per speed request; a light check
reads at most 32 KiB. DNS results are checked and the destination IP is pinned before
connecting, including when a remote proxy handles the connection.

`speed_bps` means **bits per second**. `packet_loss` is optional adapter telemetry;
HTTP errors are not packet loss. Measurements are bounded in memory, include their
source path and resource outcome, and expire. They are not written to flash on
every check. Changing source/target configuration invalidates affected decisions.

## Selection and probe settings

- `policy.mode`: `off`, `auto`, or `manual`; manual requires enabled `pinned` source.
- `fallback`: `closed` or explicit `direct`. An unavailable old measurement never
  becomes a healthy fallback, and exclusion from auto remains effective.
- Default improvement: 20%; confirming, failure and recovery checks: 3 each;
  minimum dwell and cooldown: 60 seconds; freshness: 90 seconds.
- Default probes: active every 10 seconds, other sources every 30 seconds with
  jitter, speed every 300 seconds, timeout 8 seconds, concurrency 2, history 32.
- `break_existing` is false by default. Opting in resets **only the previous
  selected source's connection tracking** after the next routing change is
  confirmed. Existing marked connections otherwise retain their allocated path
  while it remains prepared. Install the optional `openrhp-conntrack` package
  (`conntrack` and its kernel netlink dependencies); privileged preflight checks
  IPv4 and IPv6 before accepting the opt-in. No table flush or arbitrary mark
  deletion is exposed. No source change means no reset. The matching and deletion
  semantics follow the [Netfilter conntrack manual](https://netfilter.org/projects/conntrack-tools/conntrack-manpage.html).

The reset matches the old source's exact reserved high 16-bit connmark; low bits
are preserved as independent metadata. Both IPv4 and IPv6 are checked. New/current
source entries and foreign marks remain intact. Deletion resets tracking/NAT
state; it does not directly close endpoint sockets, force applications to reconnect
immediately, or migrate TCP sessions between external IPs.

Routing is durably confirmed before reset. The transaction reports
`flow_termination:pending|completed|failed`; a failure keeps the new route confirmed
and exposes `conntrack_delete_failed` in network `last_error`. Interrupted pending
work is replayed by the independent watchdog/restart. Reconfirming the same failed
transaction explicitly retries the bounded, idempotent reset. A completed reset is
never repeated by a duplicate confirmation. Rollback does not reset connections.

## Network intent

`network.enabled` is initially false. Enabling it saves intent; the separate network
transaction applies rules. Select discovered `lan_interfaces`, `wan_interface` and
canonical `local_prefixes`; interface names/subnets are never guessed from a model.
`ipv6:block` is conservative. `ipv6:proxy` requires verified support on every active
path. DNS is `block` or `selected-path`; the latter requires an explicit public
`dns_resolver` IP. OpenRHP never silently chooses an external DNS provider.

Normal API reads remove **all source settings**, rather than guessing which fields
may contain a secret. Use source PATCH and the dedicated policy/targets/network
endpoints to preserve stored settings. Full PUT `/config` or source PUT requires
complete settings; a redacted GET response is not a portable backup.

Explicit admin-only `/config/export` returns complete secrets. Use the CLI's private
`--out` file or an encrypted age backup, then delete plaintext temporary exports.
Diagnostics contain an allowlisted set of counts, versions and policy state; no
source endpoints, names, tokens, Wi-Fi keys or packet contents.

Protected DNS also requires a verified dedicated, non-root dnsmasq 2.90 service.
The helper inspects its trusted executable, procd instance, account, recursive
configuration includes and live socket ownership. Any `query-port` setting
(including `0`), explicit server source binding/port, external configuration script,
or unverifiable identity is rejected. Those dnsmasq configurations can create DNS
sockets while still root, before dropping privileges.

The helper journals the verified DNS identity and installs independent IPv4/IPv6
rules for that user's TCP/UDP destination port 53. These rules survive an nftables
flush. They also block router-originated upstream queries from that dnsmasq user
while managed routing remains installed; cached/local answers and ordinary router
management keep the kernel's existing local routing rule. Selected-path DNS uses
its separately prepared interception path. Only explicit decommission removes the
DNS guard. A changed DNS identity prevents reapply and retains prior protection.
Changing the router's DNS service outside OpenRHP requires another preflight.

The helper also records the selected LAN bridges' verified ingress members. It
protects both the bridge and those ports, so netifd cannot expose a still-running
physical LAN port while dismantling the bridge during shutdown. This metadata is
private to the root journal and replays before interfaces exist at boot. Shared
VLAN trunk lower devices are not inferred. Changing confirmed bridge membership
requires explicit decommission and a new network transaction, preventing an old
port name or routing priority from silently acquiring a different owner.

## Optional session continuity

`continuity` is optional and omitted from old configuration. Missing or `null`
leaves legacy behavior unchanged. Its public fields are `enabled`, `relay_address`,
`relay_fingerprint`, `buffer_bytes`, `udp_reserve_bytes`, and
`disconnected_grace_seconds`. The explicit relay address must be a public numeric
IP and port; the fingerprint is a pinned 64-character SHA256 certificate digest.
No certificate or private key belongs in the configuration/API object.

Defaults for a new profile: disabled, 32 MiB buffer, 4 MiB UDP reserve, 30 seconds
of disconnected grace. Enabling requires gateway role, closed fallback and
`break_existing:false`; conflicting policy edits are rejected too. Dedicated
GET/PUT `/continuity` preserves source credentials and follows normal authenticated
CAS/idempotency requirements. Changes require a fresh network transaction.
See [session-continuity.md](session-continuity.md) for pairing, limits and evidence.
