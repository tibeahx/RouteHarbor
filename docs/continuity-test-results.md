# Continuity validation — 2026-09-09

The relay protocol passed isolated Linux carrier-failure and application tests.
These results do not qualify a physical router or a particular WAN/VPN pair.
The runtime therefore continues to report `qualified: false`.

## Linux carrier qualification

Run `scripts/lab-continuity.sh`. It builds a Linux test binary and uses an offline,
disposable Docker namespace with `NET_ADMIN` and no host network. Actual nftables
rules drop packets matching the test carrier TCP tuples; RST cases close sockets
with zero linger. The loopback relay and origin are separate listening sockets.
This exercises Linux TCP/TLS transport and session recovery, not adapter routing
through physical links.

- 1,000 switches completed: 250 RST, 250 bidirectional blackholes, 250 one-way
  blackholes, and 250 failures of a data carrier with the control carrier alive.
- The target TCP connection was opened once. The external UDP socket was retained.
  All 1,000 numbered stress datagrams arrived without duplication.
- Added delivery pause against a control exchange over the same reserve:
  p50 **42.821 ms**, p95 **54.043 ms**, p99 **58.860 ms**, maximum **66.228 ms**.

Twelve three-second load runs offered 100 Mbit/s of useful payload in total:
95 Mbit/s TCP plus 5 Mbit/s bidirectional numbered UDP. Each failure run has a
separate baseline over the same reserve. The reserve carries only control/probes
before the active path is blackholed 750 ms into the failure run.

| TCP direction | UDP payload | Delivered Mbit/s, failure run | Maximum added delivery gap | UDP loss / duplicates |
| --- | ---: | ---: | ---: | ---: |
| Download | 1,200 B | 99.877 | 25.210 ms | 0 / 0 |
| Download | 64 B | 99.924 | 21.453 ms | 0 / 0 |
| Upload | 1,200 B | 99.769 | 30.253 ms | 0 / 0 |
| Upload | 64 B | 99.733 | 35.358 ms | 0 / 0 |
| Mixed | 1,200 B | 99.785 | 41.178 ms | 0 / 0 |
| Mixed | 64 B | 99.823 | 45.501 ms | 0 / 0 |

Every TCP end-to-end SHA-256 matched. Each 1,200-byte run received 781 UDP
datagrams, and each 64-byte run received 14,648. The maximum sampled gateway
application queue was 606,400 bytes. Peak Go heap across the entire test process
(gateway, relay, origins and measurement fixtures together) was 6,496,240 bytes.
Kernel socket buffers and container overhead are additional; this is not a router
RAM measurement. CPU time and full p50/p95/p99/max distributions are recorded per
run in the machine-readable result.

Raw artifacts: `test-results/continuity/qualification-final.log` and
`test-results/continuity/qualification.json` (generated, not source-controlled).
The measured Linux binary SHA-256 was
`97ae10ea5ae803abf0ac550a1ea139789ee9e4c987811d5e022c67fd59a16dbb`.
Subsequent terminal-generation, configuration-window and receiver-backpressure
edge changes have separate focused/race validation; the above numbers identify
the measured binary instead of implying that formatter or later builds were
benchmarked again.

## Real application sessions

Run `scripts/lab-continuity-apps.sh`. Its disposable test image adds OpenSSH 9.2p1,
aioquic 1.2.0 in a test-only Python environment, and Python websockets 10.4. None
of these packages are gateway or relay runtime dependencies. Generated SSH keys
and QUIC test certificates exist only inside the offline test container.

All four application tests passed across RST, bidirectional blackhole, one-way
blackhole, and data-only failure, using one retained target connection/mapping:

- **SSH:** an authenticated OpenSSH connection and its remote `cat` process kept
  exchanging binary data without reconnecting or restarting the remote process.
- **QUIC:** an actual aioquic connection and one persistent stream retained binary
  data and the server-side UDP mapping through all four failures.
- **WebSocket:** one HTTP-upgraded connection preserved binary message boundaries.
- **DNS:** five real wire-format queries preserved their transaction IDs and A
  answers through one stable UDP mapping.

The application suite completed in 2.69 seconds. This proves protocol continuity
in the isolated application fixtures; it does not measure the above 100 Mbit/s
profile separately for SSH or QUIC. Raw log:
`test-results/continuity/applications.log`. Tested application binary SHA-256:
`e161c418f544eb2e84197a43d12ff7c3a8c0bf226ee759c4a68df1b6cc74e399`.

## Focused validation and remaining deployment evidence

The core suite covers mTLS identity rejection, generation loss without request
replay, ordinary preference changes, per-carrier failure, retained sockets,
half-close, duplicate delivery after application write before ACK, bounded
queues, UDP expiry, destination restrictions, partial writes, negotiated stream
windows and quotas. Repeated race runs pass. Frame-decoder fuzzing completed
164,426 executions in three seconds with no failure; maximum sequence-number
handling has an explicit regression test.

OpenWrt SDK compilation, full OpenWrt boot, worker/helper routing and leakage
tests, and a physical router are separate evidence categories. This document
does not promote the core lab to any of those categories. Final device admission
still needs physical CPU/RAM, useful throughput and pause measurements on the
actual main/reserve pair, including its RTT and loss conditions.
