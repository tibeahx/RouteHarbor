# Independent source paths and safe imports

Every prepared source owns a routing slot, mark, NFQUEUE number where applicable, and separate loopback engine inputs. The active LAN selection never substitutes another source's probe input. The public adapter contract is `Validate`, `Prepare`, `Start`, `Stop`, `ProbePath`, and `Status` in `internal/adapter`.

Saved sources have no artificial count limit. At most 250 active routing allocations exist at once because route marks and queues are finite resources. Stopping an unused source frees its allocation. Engine listeners reserve separate ephemeral loopback ports. Generated configuration files use mode 0600 under a private 0700 runtime directory. Processes start from fixed installed paths with fixed arguments; credentials appear only in private configuration or inherited descriptors. In managed mode the helper regenerates the strict engine configuration and launches the fixed engine under the API service UID/GID with only `CAP_NET_RAW`, needed for transparent sockets. The HTTP API receives no capabilities, and the engine binaries receive no global file capabilities.

| Source type | Settings accepted | Probe path |
| --- | --- | --- |
| `direct` | `{}` | WAN socket; helper marks it when a managed path is available |
| `socks5` | `server`, `server_port`, optional `username` and `password` | Numeric-destination SOCKS5 CONNECT through this source |
| `http-connect` | Same endpoint and credential fields | Numeric-destination HTTP CONNECT through this source |
| `interface` | `name`, an existing netifd tunnel device | Helper socket bound to that exact interface; never falls back to direct |
| `packet-engine` | `strategy: "multisplit-v1"` only | Helper-marked socket into this source's real nfqws queue |
| `sing-box` | One outbound from the subset below | Separate owned loopback SOCKS input into exactly that outbound |
| `xray` | One supported `link` or one native `outbound` | Separate owned Xray SOCKS input; no reinterpretation as sing-box |

With a privileged helper, direct and existing tunnel-interface sources register their own probe slot before the first check; no network transaction, route or firewall mutation is needed. The helper accepts only bounded direct/tunnel registrations, checks collisions against native, packet, committed and pending allocations, and verifies tunnel identity through active netifd metadata and the actual kernel device kind. Tunnel identity is checked again when dialing. Stop unregisters the path. Abandoned uncommitted registrations expire after 90 seconds, while committed marks remain protected by the durable routing journal; preparation and probe activity renew live registrations.

When LAN management is enabled, external SOCKS5/HTTP CONNECT sources receive a generated sing-box bridge. Probes then use the same bridge outbound as the transparent LAN input. An HTTP CONNECT source has no general UDP capability. Other protocol capabilities must still pass device and traffic checks before deployment.

## Safe engine import subset

All objects reject unknown fields, duplicate keys, trailing JSON, oversized input, custom listeners, file paths, scripts, arbitrary marks, routing rules, administrative APIs, and executable arguments. Unsupported formats fail with a stable explanation.

A sing-box outbound accepts `type`, `server`, `server_port`, and the applicable credential fields:

- `vless`: `uuid`; verified `tls` is mandatory.
- `trojan`: `password`; verified `tls` is mandatory.
- `shadowsocks`: `method` and `password`. Methods: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, or `2022-blake3-aes-256-gcm`.
- `socks` and `http`: optional `username` and `password`.

`tls` accepts only `enabled: true` and optional `server_name`. VLESS/Trojan may specify `transport` with `type: "ws"` and optional `path`, or `type: "grpc"` and optional `service_name`. REALITY, uTLS, custom certificates, and other transports are not accepted by this initial strict subset.

Xray accepts an explicitly named VLESS link with query fields `security=tls`, `type=tcp|ws`, optional `sni`, optional WebSocket `path`, and `encryption=none`. Native imports use one `outbound` object: `protocol: "vless"`, `settings.vnext` containing one `address`, `port`, and `users` entry with `id` and `encryption: "none"`; `streamSettings` contains `network: "tcp"|"ws"`, `security: "tls"`, `tlsSettings.serverName`, and optional `wsSettings.path`. Multiple outbounds and full native configurations are rejected.

The exact runtime versions are sing-box **1.14.0**, Xray **26.3.27**, and zapret nfqws **v72.10**, commit `f0b0d89f02f44bb047fbfde5d96e9a1fc38e46f0`. Native validator checks run before starting sing-box or Xray. Runtime version checks refuse an untested version. Engine binaries and their parent directories must be owned by root and not writable by other users. The lab Dockerfiles pin upstream archives by SHA-256; updating an engine requires reviewing the schema and rerunning its native validator and traffic tests.

Packet processing uses nfqws from zapret, not arbitrary zapret2 Lua. The fixed strategy splits TLS ClientHello at `1,midsld`. Each process drops to `nobody` with the capabilities retained by upstream nfqws. The helper creates only the owned `openrhp_probe` output table for independent probes; the main dataplane separately queues LAN traffic. Marks preserve the source allocation and use low bits to prevent reinjecting generated packets or queueing a probe twice. A stopped/crashed engine's queued traffic fails closed because rules never use NFQUEUE bypass.

## Probe security and measurement semantics

Probes require HTTPS on port 443, expected HTTP status codes, and a body budget of 1 byte to 8 MiB. Each request resolves the target once and validates every returned address. Private, loopback, link-local, multicast, reserved, mapped private IPv4, translated IPv6, scoped IPv6, and local hostnames are rejected. A SOCKS/CONNECT request sends the validated numeric IP; TLS SNI, certificate verification, and the HTTP Host retain the original hostname. Redirects are rejected. Response bodies are discarded after the budget, header sizes and deadlines are bounded, and concurrent source requests share the configured concurrency budget.

The gateway records per-resource success, status, latency, bytes read, and useful speed when a speed measurement was requested. Packet-loss telemetry stays absent unless measured by a suitable adapter. An HTTP error is never recorded as packet loss. Lightweight probes read at most 32 KiB and do not invent a speed metric. Failures use stable error codes and omit endpoint URLs, credentials, and server-provided content.

The scheduler can request a speed check before its regular interval when fresh
lightweight evidence shows a required-resource failure, a measured packet-loss
increase of at least ten percentage points, or latency at least twice a recent
per-resource baseline with a minimum 100 ms increase. Latency needs at least two
successful baseline samples. Extra checks have a per-source cooldown of at least
one minute and twice its normal lightweight interval after any speed attempt. Evidence from
before that attempt or beyond the configured freshness window cannot retrigger
it. These checks share the existing concurrency, timeout and target-byte limits;
the usual 10-second active, 30-second other and 300-second speed defaults stay
unchanged. A speed-check trigger alone never switches a route.

Engine endpoint hostnames are resolved during preparation and pinned to a numeric address in the generated config, retaining their original TLS identity. This bootstrap lookup uses the gateway's existing system resolver and occurs before starting the candidate engine. It is distinct from client DNS; no hidden DNS resolver is added inside the engine. Sources needing to avoid bootstrap hostname disclosure can specify a numeric server and an explicit TLS server name.

When network management is enabled, **probe target DNS also uses each candidate source**. A per-run resolver sends TCP DNS to the explicitly configured `network.dns_resolver` through that source's numeric SOCKS/CONNECT endpoint or helper-marked socket. It never falls back to the system resolver. Without an explicit resolver, hostname targets fail with `target_dns_resolver_required`; public IP literal targets remain usable. Unmanaged local development may use the system resolver. A DNS wire-format test supplies different answers over two source-specific TCP paths and verifies no global resolver is used.

Selected-path DNS requires the user's explicit public `network.dns_resolver` IP; there is no default third-party resolver. A proxy engine owns a separate loopback DNS input. sing-box converts received queries to TCP DNS through the source outbound; Xray's DNS input forwards through the same native VLESS outbound. Native direct/interface/packet paths use the configured resolver through their own marked route. Plaintext DNS remains blocked when the policy is `block`. Resolver address-family and adapter UDP limitations are enforced by the dataplane, not silently bypassed.

## Recovery and allocation identity

The controller saves the complete candidate configuration to a private transaction checkpoint before network apply. Confirmation promotes its private snapshot. On restart, source settings from that snapshot must match the helper's committed routing intent before restoring slots, marks and LAN/DNS input ports. Removed sources remain available for rollback until the replacement is confirmed. An occupied port is a preflight failure; OpenRHP never terminates an unrelated listener. A missing or unreadable checkpoint blocks probes and keeps the management API available with a stable initialization error. Obsolete candidate checkpoints are pruned after the prior confirmed snapshot is durable.

Engine process generations are reaped independently. A failed process is cleared so the next recovery probe can restart it with the same inputs. Startup becomes `running` only after the generated TCP listeners accept connections. Managed engines have a root supervisor controlled by the authenticated API connection and a private helper-liveness pipe. API disconnect, helper death or worker death terminates the engine; an explicit stop waits for its listeners to close before releasing ownership. Engine readiness verifies that the required TCP/UDP IPv4/IPv6 listener inodes belong to that exact child. nfqws likewise uses a separate root supervisor and private liveness pipe because nfqws drops credentials. Network policy remains governed by the independent helper watchdog.

A new, uncommitted source whose engine cannot start remains saved and visibly unhealthy. A routing transaction can include healthy paths while explicitly recording that source in `candidate.unavailable`; paths and unavailable IDs together must exactly match the enabled sources in its private checkpoint. An unavailable source cannot be selected. After it recovers, prepare and confirm routing again before using it for LAN traffic. `unavailable_sources` and `recovered_source_requires_routing_prepare` explain this state in routing status.

A failed engine that already owns committed transparent inputs is different: preparing a routing change still requires restoring that engine. Existing sticky flows must never be redirected to an unrelated process that happens to bind its old local port. The helper retains strict ownership checks for every committed input; this limitation is explicit rather than silently removing an old protected path.

## Reproducing the Linux isolation prototype

Run `scripts/lab-paths.sh` with Docker. It builds a pinned Debian image and runs a disposable privileged container with **no external network and no host mounts**. All interfaces, queues, and rules exist inside dedicated container namespaces; the host network is not changed.

The prototype uses a local verified TLS test origin and a local CONNECT proxy. It checks direct and proxy requests never enter either DPI queue, then checks that profile A and profile B increment only their own queues. It runs 32 concurrent requests across direct, both real nfqws profiles, and proxy, verifies the observed exit address, kills profile A, and checks that only A fails closed while the other paths still work. This is real nfqws processing, not a pass-through or mock DPI handler.

Observed on the development Docker Linux ARM64 lab: 32 concurrent requests passed; each profile counted 72 queued packets in that run; killing A failed closed and B/direct/proxy remained available. Counts may vary with retransmission. This proves source-path independence and crash isolation on that lab; it does not prove censorship bypass for an ISP, OpenWrt package compatibility, Wi-Fi performance, or physical-router acceptance.

`scripts/lab-engines.sh` checks generated source configurations against the exact pinned sing-box and Xray binaries in a second disposable container. It supports Docker Linux amd64 and arm64 and is separate from the OpenWrt build matrix. The tests include explicit selected-path DNS and protocol UDP/IPv6 capability configurations, real native listener startup, engine death and recovery with unchanged inputs, and controller SIGKILL followed by restoration of committed listener ports. Ordinary Go tests cover hostile imports, DNS rebinding, mapped IPv6, redirect refusal, numeric proxy destinations, body budgets, concurrency, and absent telemetry.

Primary contracts: [sing-box TCP DNS](https://sing-box.sagernet.org/configuration/dns/server/tcp/), [sing-box routing actions](https://sing-box.sagernet.org/configuration/route/rule_action/), [Xray transport](https://xtls.github.io/en/config/transport.html), and [pinned zapret release](https://github.com/bol-van/zapret/releases/tag/v72.10).

Native engine labs support Docker Linux amd64 and arm64. ARM64 asset digests are recorded above; the pinned amd64 sing-box archive SHA-256 is `2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63`, and Xray is `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`. Both are verified before extraction.

`scripts/lab-engine-worker.sh` exercises the actual service-user boundary: native sing-box and Xray processes receive only `CAP_NET_RAW`; the API fixture has zero effective/permitted/ambient capabilities. The tests verify private inherited configuration, listener ownership, API/helper crash cleanup, ordinary RPC availability while an engine runs, and restart on restored ports.
