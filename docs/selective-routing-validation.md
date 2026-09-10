# Selective routing validation

This report records development evidence for `codex/selective-routing`, based on
`origin/main` commit `9a471c62b13e229c54141c7eafd53a51211e184f` (`9a471c6`). The
checks below ran against the implementation worktree, not a released router image.
The dispatcher uses pinned sing-box 1.14.0. Go builds use Go 1.27.1.

No physical router, radio, user's active WAN, or production relay was a test
target. Linux namespaces and OpenWrt guests use synthetic interfaces and
destinations. A passing namespace test does not establish device throughput,
memory suitability, ISP blocking coverage, or a continuity latency guarantee.

## Evidence by environment

| Environment | Observed result | Scope |
| --- | --- | --- |
| Focused Go tests | Passed | Registry parsing and snapshots, exact policy precedence, detector confirmations and resets, DNS, config/API contracts, dispatcher generation, helper boundaries and service recovery |
| Race checks | Full `go test -race ./...` passed | Applied-policy/staged-instance regressions, prepared-watchdog handover and all package tests; the final health fix also passed focused race checks |
| Static checks and portable builds | Passed | Host/Linux lint, vet, formatting, 60 documented operations, 10 packaging tests, 66 binaries across 11 targets and byte-identical reproducibility |
| Browser | 22 passed; one existing paired-device case excluded by its prerequisite | Four selective-routing cases passed; the skipped case requires an independently paired lab access point and is outside physical-device acceptance |
| Native Linux dispatcher | Passed | Twelve pinned-engine configuration checks; actual same-IP domain isolation across all six bypass source kinds, both families and supported transports |
| Native Linux learning and relay composition | Passed | Actual DNS observations, three TLS confirmation rounds, hot learned rules, CNAME/TTL/restart, relay TCP/UDP transport switching and failure isolation |
| Native Linux guards/watchdog | Passed | Tunnel/NFQUEUE failure isolation, FakeIP quarantine, owned DNS recovery, legacy migration and detached watchdog after owner death in three transaction states |
| Native Linux helper/worker | Passed with the small fixture | Real root RPC, unprivileged owner, inherited configuration descriptors, native dispatcher/DNS processes, two staged pools and owner cleanup |
| Current full registry fixture | Download and validation passed | 1,632,726 accepted domains, 75 explicit prefixes, 25 rejected domain rows; encoded snapshot 34,212,906 bytes |
| Full-registry memory/storage scale | Two simultaneously staged full-domain dispatchers passed within 1 GiB, with swap disabled | 962.5 MiB container peak including native hot reload after bounded rule partitioning; no 256/512 MiB router qualification |
| Current OpenWrt SDK packages | Final source passed on all three targets | Seven IPKs each for x86-64, ARM64 and MIPS; pinned Go toolchain, package dependencies and ELF/softfloat inspection |
| Current booted OpenWrt VM | Full final-source run passed | Fresh x86 OpenWrt 24.10.7 installation, selective paths, applied rollback, DNS/engine hangs, reboot, fw4 recovery, FakeIP quarantine and explicit direct decommission |
| Physical devices and active WAN | Excluded from this implementation | No physical qualification or deployment is claimed |

The older [SDK report](evidence/openwrt-sdk.md),
[boot report](evidence/openwrt-boot-network.md), and
[continuity measurements](continuity-test-results.md) describe separate checkpoints
and are not promoted to selective-routing results.

## Acceptance mapping

| Plan group | Implemented behavior and concrete evidence | Scope or limitation |
| --- | --- | --- |
| Fresh base and isolated work | `codex/selective-routing` in a separate worktree from `9a471c6`; exact final SDK source/runtime digests below | Development snapshot; original checkout and physical WAN untouched |
| Direct default and exact classification | Policy/config unit tests and all-six-source native same-IP domain tests; explicit IPv4/IPv6 CIDRs and supported TCP/UDP verified | Ordinary traffic traverses the local classifier before leaving WAN; domains hidden by private encrypted DNS cannot be inferred |
| DNS, precedence and mapping | Policy/DNS unit contracts; native local frontend, distinct FakeIPs, CNAME, HTTPS NODATA, 600-second TTL and orderly persistent-cache restart | No strict synthetic DNSSEC; finite pool wrap can reuse addresses; no indefinite stale-cache identity promise |
| Prepared bypass sources and socket guards | Generated configs checked by pinned sing-box; actual interface, SOCKS5, HTTP CONNECT, sing-box, Xray and nfqws paths; tunnel/NFQUEUE death remains closed for bypass | HTTP CONNECT UDP is explicitly closed; no unsupported transport is counted as passing |
| Private relay continuity | Actual selective relay TCP/UDP destination sockets survive preferred A→B→A and carrier-A socket loss; relay-exit TLS comparison; relay failure retains direct sockets | Two carrier connections use one synthetic topology; relay/process loss can terminate bypass sessions; no new physical latency/throughput qualification |
| Registry and bounded snapshots | Provider/parser/hash/generation/last-good unit tests, live third-party feed validation, chunked root RPC and exact journal snapshot recovery | Domain and explicit subnet feeds only; 25 malformed rows rejected as counts; observed registry is time-specific |
| Conservative learning | Detector queue/epoch/expiry/recheck units; actual DNS observations and three TLS rounds ≥10 seconds apart; working alternative, site/WAN/DNS/certificate failures remain unlearned | TLS443 only; configured direct controls required; first user connection can fail; no automatic body replay or proof of RKN attribution |
| API and English UI | ETag/CAS, access/idempotency, redaction and operation contracts; final browser 22 passes, including migration, route reasons, managed DNS, stale/emergency states | One existing browser prerequisite requires a separately paired device and is outside the requested physical scope; ordinary diagnostics contain no DNS query history |
| Migration and explicit holds | Legacy absent-routing imports/journals, prepare/apply/confirm, applied-candidate/rollback and restore unit tests; actual Linux preserve-closed hold through boot/watchdog/firewall recovery | New settings do not activate network changes; explicit maintenance holds override automatic emergency direct |
| Atomic rule publication | Hash-bound last-good snapshots, staged pools and publication retry units; actual full-feed helper hot publication followed by native traffic observation, unchanged engine PID and held direct TCP | File publication and native application are distinct; status does not invent a synchronous engine acknowledgement |
| Fault isolation and recovery | Separate loader/detector state tests; actual native SIGSTOP health check, detached watchdog in confirmed/prepared/rolled-back states, Linux quarantine/foreign-rule preservation; final VM result below | Classifier/DNS outage permits connection loss and client DNS refresh; RouteHarbor restores only its own rules, not foreign fw4 NAT |
| Packaging and independent evidence tiers | Full Go race/static checks, 66 binary builds/11 targets, three real SDK package sets; separate Linux namespace and booted-VM evidence below | SDK ARM64/MIPS are compile/package evidence; VM is x86; no physical devices or active WAN used |
| Capacity | 1.63-million-domain fixture, two helper-owned workers, real hot reload and direct flow survival within 1 GiB without swap | Component/RPC-fixture measurement; no 256/512 MiB router or complete production-daemon memory qualification |

## Unit, API and service checks

The focused tests cover strict provider/domain/CIDR parsing; bounded malformed-row
handling; exact domain and explicit subdomain boundaries; local and manual-rule
precedence; last-good snapshots, integrity and bounded publication; DNS TCP/UDP,
local delegation and HTTPS/SVCB suppression; queue/concurrency limits and private
address/rebinding rejection.

Detector tests require three spaced direct failures with successful bypass and a
fresh configured control, reject incomplete or ambiguous rounds, retain any
working direct alternative, and exercise expiry, early removal, renewal and
WAN/source changes. TLS tests verify the pinned destination address, SNI,
certificate validation and absence of application HTTP requests. These use
controlled responders and injected DNS/failure conditions; they do not diagnose
an actual ISP or prove that a restriction was imposed by RKN.

Service regressions exercise prepare without changing the live classifier,
classification of the applied candidate before confirmation, rollback retaining
the previous instance, terminal-stage cleanup even in emergency mode, exact
journal-snapshot restoration, disjoint FakeIP pools, hot publication on rule expiry,
last-good rules after helper publication failure, and retry without a process
restart. WAN identity uses an opaque digest of actual link/address/default-route
data before and after comparisons. A source or WAN change discards accumulated
evidence. DNS candidates stay out of status and operation journals.

API checks cover read/admin access, ETag/CAS and idempotency, operation polling,
bounded inputs and secret preservation. Importing a legacy configuration with no
`routing` field remains legacy even when the destination store initially has new
selective defaults. Selective mode rejects `break_existing`, direct fallback and
non-443 detection controls. Browser checks cover the English migration form, exact
exceptions, route reasons, stale lists and emergency direct, including the absence
of an invented engine acknowledgement. Managed FakeIP DNS disables the legacy DNS
selector while preserving its stored value; selective fallback remains closed and
connection tracking reset is unavailable. Legacy controls stay editable.

Reproduce from the repository root, running focused checks before the wider suite:

```sh
go test ./internal/routing ./internal/dispatch ./internal/config ./internal/api
go test ./internal/control -run 'Test(Routing|Selective)'
go test ./internal/helper -run 'Test(Dispatcher|Selective)'
go test ./internal/probe -run 'Test(Comparative|ControlTLS)'
go test -race ./...
go vet ./...
sh scripts/lint.sh
sh scripts/fmt.sh --check
sh scripts/build-matrix.sh
sh scripts/check-reproducible.sh
python3 scripts/check-docs.py
git diff --check
```

Browser tooling is development-only; it is not installed on routers:

```sh
npm ci --prefix tests/browser --ignore-scripts
npm --prefix tests/browser exec playwright install chromium
sh scripts/format-web.sh --check
sh scripts/test-browser.sh
```

The recorded browser run used the pinned Playwright 1.63.0 Chromium cache at
`/private/tmp/routeharbor-playwright`. Screenshots and Playwright output are generated
under `test-results/`; response fixtures verify UI behavior, not packet paths.

## Native Linux paths and failures

The disconnected dispatcher lab creates separate LAN-client and destination
namespaces. Allowed and blocked names resolve to the same real address but receive
different FakeIP addresses. Actual echoed source addresses distinguish WAN from
tunnel/proxy egress; explicit IPv4/IPv6 prefix rules are also exercised using raw
destination addresses.

| Bypass kind | IPv4 TCP/UDP | IPv6 TCP/UDP | Path evidence |
| --- | --- | --- | --- |
| Interface/tunnel | Passed | Passed | Separate tunnel egress address |
| SOCKS5 | Passed | Passed | Native prepared proxy and remote proxy egress |
| HTTP CONNECT | TCP passed; UDP refused | TCP passed; UDP refused | Unsupported UDP remains closed rather than escaping directly |
| sing-box | Passed | Passed | Generated native source configuration behind prepared SOCKS ingress |
| Xray | Passed | Passed | Native VLESS/TLS source configuration behind prepared SOCKS ingress |
| Packet/DPI engine | Passed | Passed | Actual nfqws queue counters prove interception; this method deliberately retains the WAN address |

Ordinary traffic retained its WAN egress in every case. One established direct TCP
socket survived all bypass selector changes and atomic rule add/remove reloads.
Adding a rule moved new connections to bypass; removing it restored direct without
restarting the dispatcher. Killing nfqws blocked bypass TCP/UDP while direct TCP
continued. Deleting the tunnel likewise left direct working and prevented marked
bypass sockets from falling through to WAN.

The guard lab independently verifies actual nft syntax and Linux route behavior.
An nftables flush makes classifier health fail while IPv4/IPv6 FakeIP quarantine
survives. Emergency recovery removes the owned DNS UID blackhole and classifier
DNS conntrack state, preserves a foreign connection mark, restores ordinary WAN
and real DNS routing, and retains synthetic-address quarantine. Legacy global
blackhole migration is exercised separately. The deliberately missing nft chain
during the flush test emits a diagnostic; the expected health failure is asserted.

The booted guest exposed a real ordering bug: netifd removed the early synthetic-
address policy rules after RouteHarbor's boot guard had completed. A subsequent full
firewall flush could then expose cached FakeIP destinations to WAN. The independent
monitor now remains active in completed emergency mode and resumes the confirmed
journal after boot. It repairs only owned IPv4/IPv6 synthetic-address rules,
without resetting DNS connections or rewriting the journal on every tick. Prepared
transaction handoff and explicit maintenance holds retain their authority; an
inode-verified per-transaction lease prevents duplicate monitors.
The actual Linux completed-emergency regression passed in 2.63 seconds: it resumed
the detached monitor twice, deleted both synthetic policy rules, flushed nftables,
and deleted policy rules a second time. IPv4/IPv6 quarantine returned while
ordinary direct stayed usable. Journal bytes/mtime and existing DNS-marked
conntrack entries stayed intact; no bypass-only guard was reinstalled. A prepared
transaction then handed authority to its replacement monitor. Direct-only removal
cleans up that monitor through the durable maintenance journal; failed quarantine
or rule removal retains its hold, including across restart, until an explicit
successful retry. Focused failure/retry and race regressions pass. The complete
selective Linux lab and focused race checks passed; the log is
`test-results/selective-routing/monitor-linux.log`.

The detached production watchdog restores direct after the owner is killed in
`confirmed`, `prepared`, and `rolled-back` states. It checks saved emergency intent
and the resulting kernel rules independently. This proves a watchdog process
survives owner death; it is not merely a mocked health callback. An explicit
`preserve-closed` decommission creates a durable maintenance hold before quarantine.
The real Linux regression verifies it remains closed through boot, watchdog and
firewall recovery until an explicit new routing transaction or restore-direct
operation releases it. Pending migration and package-job ownership remain guarded.
The dedicated regression passed in 0.54 seconds; its focused race tests also passed.

With the pinned lab images already built:

```sh
sh scripts/lab-dispatcher.sh
sh scripts/lab-selective.sh
sh scripts/lab-dispatcher-worker.sh
sh scripts/lab-selective-acceptance.sh
sh scripts/lab-network.sh
```

The scripts build fresh Linux binaries, use `docker run --network none`, and grant
privileges only to disposable containers. They mount only their temporary build
directory read-only. `docker/lab-paths/Dockerfile` and
`docker/lab-engines/Dockerfile` define the lab images; the latter verifies the
native engine archive hashes. Image creation requires its declared package and
release downloads; the actual test containers have no external network.

The observed namespace logs are retained locally as
`test-results/selective-routing/linux-guards.log` and
`test-results/selective-routing/linux-dispatcher.log`. The broader existing Linux
network regression suite also passed; its packet, legacy lifecycle, DNS, early
boot, bridge and conntrack results are retained as
`test-results/selective-routing/linux-network-regression.log`.

## Native learning, DNS lifetime and selective continuity

`sh scripts/lab-selective-acceptance.sh` composes the native classifier, real DNS
frontend observations, comparative TLS probe, detector, rule compiler and private
relay bridge in disconnected LAN, destination and relay namespaces. Its test
controller advances publication explicitly; service scheduling and helper journal
transactions have separate control/helper tests above.

Unknown domains initially fail through direct. The test performs three actual
TCP/TLS rounds separated by at least ten seconds, verifies the configured direct
control, publishes the detector's exact learned domain set atomically, and observes
new LAN connections using the tunnel address. A CNAME resolves to the same real
address and also learns correctly. An unavailable site, a working alternate IP,
different DNS across paths, a certificate error and a general WAN outage produce
no learned rule. A continuity comparison separately verifies TLS at the actual
relay exit through the classifier's bypass probe ingress.

The native FakeIP answer advertises 600 seconds. Real upstream A/CNAME records use
a two-second fixture TTL and are resolved across the spaced rounds. An orderly
engine stop/restart retains the same private pool mapping: a client using its saved
synthetic address, without another DNS lookup, reaches the same bypass destination.
The test does not wait out a 600-second synthetic TTL or exhaust the pool. The
pinned allocator can reuse an address after pool wrap; TTL does not guarantee
indefinite mapping retention. See the [routing guide](selective-routing.md).

Allowed and blocked names share a real target. Ordinary TCP/UDP comes from the WAN
address; blocked TCP/UDP comes from the separate relay namespace. Both classes keep
the same destination socket or UDP mapping through preferred carrier A→B→A and
actual closure of carrier A's sockets. Relay death leaves the direct TCP/UDP
sockets intact and prevents bypass TCP from falling through. The carriers are two
real connections over the same synthetic topology; this test does not qualify
independent WAN links, the 100 Mbit/s latency target, or physical hardware.

The log is `test-results/selective-routing/linux-acceptance.log`. Each of the two
cases runs in its own 512 MiB, swap-disabled disposable container.

## Actual helper process boundary

`TestLinuxDispatcherWorkerRPCPrivilegesDNSAndOwnerCleanup` uses an unprivileged
client through the real typed helper protocol. It uploads and reloads snapshot
chunks, starts the production supervisor, sing-box and DNS frontend, and inspects
their actual UID/capability state. The private configuration arrives on inherited
descriptor 3 and its secret is absent from process arguments. The DNS frontend has
no capabilities; the engine retains only its required transparent-socket capability.

TCP and UDP DNS health, FakeIP answers, external HTTPS NODATA and the observation
pipe are exercised. Classifier health now requires the frontend to forward its
reserved probe to the native engine and validate a synthetic address from that
engine's assigned pool; it cannot pass on a frontend-only stub. This local probe
does not depend on external WAN or a public health service. The actual engine
`SIGSTOP` regression fails health while its TCP listener and frontend remain live;
`SIGCONT` restores health. Two independent staged pools start together. Both explicit
owner close and owner crash remove the owned processes and registrations. This
lab tests real process and descriptor boundaries but uses an in-memory network
backend; the separate namespace lab above supplies kernel packet-path evidence.
The final small-fixture run passed in 2.93 seconds with a 113,532,928-byte container
peak and zero OOM/limit events; its log is
`test-results/selective-routing/worker-final.log`.

## Registry size and capacity

The recorded third-party Antifilter snapshot contains 1,632,726 canonical domains
and 75 explicit prefixes. Twenty-five malformed domain rows were rejected and
reported as a public count; their contents are not exposed in ordinary diagnostics.
The 34,212,906-byte encoded snapshot is approximately 32.63 MiB. This is the snapshot
payload, not resident memory and not total installed storage.

The first full-domain run exposed excessive startup memory: one dispatcher reached
approximately 1 GiB, and a repeat with swap disabled was killed before readiness.
The implementation now partitions the exact-domain OR list into 16,384-entry rules,
sets bounded native Go memory targets, and releases the helper's temporary compile
heap before starting the engine. The partition changes representation, not matching
semantics.

The corrected offline measurement started **two full dispatchers simultaneously**,
with separate persistent pools, in a container limited to 1 GiB with swap disabled.
The initial startup-only run took 7.178 and 6.997 seconds to ready each worker.
The final run also published a learned domain through the typed helper and observed
actual native rule application while an ordinary TCP stream stayed connected.
Typed publication took 0.571 seconds; observed native reload took another 3.417
seconds. The worker PID stayed the same; new ordinary connections also worked.
Total final test time was 20.00 seconds. All
production startup deadlines remained unchanged. This domains-only fixture encoded
to 34,211,584 bytes; the separate full provider snapshot also contains 75 prefixes.

| Process | High-water RSS, KiB | Steady RSS, KiB |
| --- | ---: | ---: |
| First sing-box dispatcher | 345,340 | 95,888 |
| Second sing-box dispatcher | 348,956 | 95,136 |
| Helper test process | 293,676 | 61,076 |
| Unprivileged control fixture | 310,924 | 310,924 |

The final cgroup peak was 1,009,213,440 bytes (962.5 MiB), with zero memory-limit events and
zero OOM kills. Per-process peaks occur at different times and must not be added
as a simultaneous resident-memory value. The corrected log is
`test-results/selective-routing/worker-scale-hotpublish.log`. The startup-only
two-worker run peaked at 942,084,096 bytes and remains `worker-scale-two.log`; the
earlier swap-enabled
result remains `worker-scale-initial.log` for comparison, not qualification.

A routing transaction can retain two dispatchers and two rule sets at once. Root
and control snapshot stores, temporary upload/publication files, previous snapshots
and rollback references add storage beyond one downloaded list. The native engine
binary also occupies installed storage. These results do not establish operation
on a 256 or 512 MiB router; the small-fixture tests at 512 MiB are separate evidence.
The measured control process is an unprivileged RPC fixture, so this component lab
also does not qualify total memory of a complete production control daemon.

The live provider check is explicitly opt-in and only downloads the public lists:

```sh
ROUTEHARBOR_REGISTRY_LIVE=1 go test -v ./internal/routing -run '^TestLiveRegistryProvider$'
```

For a repeatable offline scale run, retain the validated provider domain-list
fixture and supply its absolute path:

```sh
ROUTEHARBOR_DISPATCHER_SCALE_DOMAINS=/absolute/domains.lst \
  ROUTEHARBOR_DISPATCHER_LAB_MEMORY=1g ROUTEHARBOR_DISPATCHER_SCALE_WORKERS=2 \
  sh scripts/lab-dispatcher-worker.sh
```

That script reports per-process RSS/high-water values and, where available, the
container cgroup peak. The fixture date and size must accompany any reported
capacity numbers; a future provider snapshot may differ.

## OpenWrt SDK and booted guest

The final SDK builds passed for x86-64, mediatek/mt7622 (ARM64), and ramips/mt7621
(MIPS little-endian softfloat). Each produced seven IPKs, inspected for package
metadata/dependencies, executable hashes, Go 1.27.1 version and correct ELF ABI.
The original SDK volumes remained read-only; builds used private clones.

The build-input snapshot SHA-256 is
`ef1cafa0518c5c78f92f7cf402c072ddbe232ab8bfb08aceea2cd5f29933d954`.
Its 183 runtime inputs match the final worktree without additions or changes;
the runtime-only digest is
`29e33266ea3f6afabe76f49beb558dee05d066e15cc5d1366389c63070d8e267`.
This is a development snapshot based on `9a471c6`, not a tagged clean release.
It includes the persistent emergency monitor, boot-resume and durable direct-only
removal fixes.
The package reports and exact runtime comparison are retained under
`test-results/selective-routing/sdk-{x86-64,mediatek-mt7622,ramips-mt7621}.json`
and `sdk-runtime-comparison.json`.

The fresh x86 OpenWrt 24.10.7 QEMU run passed using this exact SDK snapshot, kernel
6.6.141 and procd as PID 1. The final runtime comparison found no changed or added
inputs. Ordinary IPK installation retained disabled routing defaults and completed
root/service setup. Before interception, actual IPv4/IPv6 TCP/UDP/DNS and LAN
management passed.

The selective guest test then established the following:

- Two names sharing real IP `8.8.8.8` received `198.18.0.2` and `198.18.0.3`.
  Allowed TCP used WAN source `11.0.0.2`; blocked TCP used the prepared SOCKS
  egress `8.8.8.8`.
- Applying a manual-direct candidate moved classification to pool `198.19` and
  sent both names through WAN. Explicit rollback restored the exact previous
  committed intent, pool `198.18`, and blocked-name bypass.
- Suspending the DNS frontend restored real DNS and direct WAN for both names.
  Reconfirming restored selective routing. Suspending the native engine while
  leaving its frontend alive triggered the same emergency behavior.
- A graceful reboot and fw4 reload preserved emergency direct. Both IPv4 and IPv6
  FakeIP policy quarantine remained effective after late boot and full fw4 flush.
  Full flush also removes fw4's foreign NAT, so the routed direct source was the
  client address `10.44.0.20`; RouteHarbor did not recreate foreign masquerade. Explicit
  firewall restart restored WAN source `11.0.0.2`.
- Explicit `restore-direct` decommission cleared committed/pending intent, guard
  and maintenance hold, retained foreign fw4 rules, and left real DNS and normal
  WAN working for both names.

Selective guest flow assertions use IPv4 TCP. The all-source IPv4/IPv6 TCP/UDP
matrix and selective relay flows are the separate native Linux evidence above.
ARM64 and MIPS results establish SDK compilation and package inspection; no
ARM/MIPS guest or physical-device boot is claimed.

The verified OpenWrt image SHA-256 was
`3caea69f186b2bce80938d265e5e2a3dfd0f8713aed101df35d60b88d7270d1f`.
The extracted official static musl sing-box executable SHA-256 was
`ce3ed8667dd99ff40c85a8b236075e856ea9cb80731b304cedd2a47187828120`;
this differs from the archive digest in the installation guide. The result JSON
and complete output are retained as `test-results/selective-routing/boot-final.json`
and `boot-final.log`, with the original JSON at `test-results/selective-boot/results.json`.
Only the dedicated test container was stopped. Other VMs were untouched, and the
private completed disk plus pristine checkpoint were preserved for reproduction.

Reproduce with separately verified OpenWrt SDK/image inputs and Go toolchain:

```sh
sh scripts/sdk-build.sh /absolute/openwrt-sdk /absolute/go1.27.1/bin/go
ROUTEHARBOR_VM_PROFILE=selective sh scripts/lab-openwrt-vm.sh /absolute/verified-image-directory \
  /absolute/private-vm-state /absolute/current-sdk-packages \
  /absolute/verified-dependencies
python3 scripts/lab-selective-boot.py --packages /absolute/current-sdk-packages \
  --dependencies /absolute/verified-dependencies \
  --engine /absolute/pinned-amd64-musl-sing-box
```

The `selective` VM profile uses a dedicated disposable container and synthetic
`11.0.0.0/24` WAN. The older VM profile uses `198.18.0.0/24`, which deliberately
conflicts with reserved FakeIP space and is not suitable for this test. The feature
harness verifies sing-box's pinned binary hash/version and the installed SDK
executable hashes before testing. The official generic Linux engine archive is
glibc-linked and cannot execute on an OpenWrt musl guest; use the pinned musl asset
listed in the [routing guide](selective-routing.md). The disposable regular-file
disk is expanded to 512 MiB to fit the native engine and SDK packages; this does
not modify a physical block device. Its private writable state directory should
have mode 0700 and must not contain a production disk image.

SDK package creation, dependency/ELF inspection and booted guest network behavior
are recorded separately. The passing guest run closes the stated VM checks; it
does not extend ARM/MIPS SDK evidence into boot or physical qualification.
