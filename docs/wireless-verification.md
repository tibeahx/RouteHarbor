# Verifying a wireless router pair

Automatic wireless setup requires a tested pair. This development preview ships
with **no pre-certified router profiles**. Driver advertisements alone never
enable WDS or mesh. Use [home-lab.md](home-lab.md) to prepare a separate, recoverable
lab; do not use a working household WAN as the first test target.

OpenRHP records a short-lived, root-owned receipt after trusted local verification.
It binds the exact OpenWrt build, kernel, board, radio path, PHY/driver capability
digest, both TLS identities and one tested mode. It expires after 24 hours by
default (at most seven days). Software, driver, radio or identity changes invalidate
it. It is operator evidence for that pair, **not a product or hardware certification**.

## Qualify before recording

1. Establish independent management and recovery on both routers, then pair their
   node identities over the trusted management network. Read the gateway's public
   fingerprint through `POST /api/v1/nodes/discover` (`gateway_fingerprint`); verify
   the node fingerprint through its trusted bootstrap output. Confirm the wireless
   MAC addresses separately; a TLS fingerprint is not a radio MAC.
2. Deliberately qualify WDS/four-address or encrypted 802.11s on the actual isolated
   pair using its OpenWrt/driver setup instructions. The gateway must retain one
   enabled home AP with a fixed channel and WPA2-CCMP settings. Existing unowned
   WDS/mesh configurations are not silently taken over by the managed backend.
   The node's managed profile uses `wireless.openrhp_ap` and
   `wireless.openrhp_backhaul`, both with `openrhp_owner=1`; inspect the complete
   profile before explicitly adopting it. Ethernet setup with optional Wi-Fi can
   create the managed client AP before this qualification. Never mark an unrelated
   existing interface as owned merely to bypass a conflict.
3. Confirm encryption with the exact peer, client address visibility on the
   gateway, one DHCP/RA source, concurrent client AP traffic, DNS/internet through
   the intended gateway path, and a usable independent management/recovery path.
   Disconnect the redundant uplink before testing a bridge to avoid a loop.
4. Keep the tested peer link and client AP active while recording on each router.
   The command checks live `ubus` radio/interface binding, encrypted configuration,
   `iw` peer presence/authorization and four-address or established mesh state.
   These local checks complement the explicit client checks; they do not measure
   client DHCP, packet loss or throughput for the operator.

## Record the completed checks

Run through existing trusted root administration on the **gateway**, replacing
the uppercase placeholders with observed values. Include a `--checked-*` flag
only after completing that check. There is no HTTP/helper-socket operation that
creates or edits a receipt.

```sh
/usr/libexec/openrhp-helper verify-wireless \
  --radio GATEWAY_RADIO --interface GATEWAY_PEER_INTERFACE --mode wds \
  --peer-fingerprint NODE_TLS_SHA256 --peer-mac NODE_WIRELESS_MAC \
  --valid-for 24h \
  --checked-encryption --checked-client-addresses --checked-single-dhcp \
  --checked-management-recovery --checked-concurrent-ap
```

Then run the equivalent on the **node**, with the gateway as the peer:

```sh
/usr/bin/openrhp-node verify-wireless \
  --radio NODE_RADIO --interface NODE_PEER_INTERFACE --mode wds \
  --peer-fingerprint GATEWAY_TLS_SHA256 --peer-mac GATEWAY_WIRELESS_MAC \
  --valid-for 24h \
  --checked-encryption --checked-client-addresses --checked-single-dhcp \
  --checked-management-recovery --checked-concurrent-ap
```

For a tested SAE mesh pair, use `--mode mesh` on both devices. The active peer
interface must be the mesh interface. Paths default to the packaged helper state
and service identity directories; trusted custom installations can supply
`--state-dir` and `--identity-dir`. Receipts stay in root-owned 0700 helper
directories as 0600 `wireless-verification.json` files. No Wi-Fi key, private
identity key or raw UCI export is stored in the receipt or printed by this command.

## Use managed setup

Refresh **Coverage → Set up connection**. A matching pair offers Wi-Fi first.
Choose the detected main-router home AP and approve its use. Its existing password
is transferred from the local root helper to the paired node through the private
coordinator and pinned TLS; it never traverses the browser. Each router prepares
its own recovery snapshot before changes start.

The gateway applies first, then the node. After real client checks, confirmation
remains pending until both participants are reconciled. A lost response is not
reported as success. Each router retains its own rollback process and deadline;
the gateway keeps a compensation snapshot until node confirmation is known.

If verification expires or a binding changes, new wireless setup becomes
unavailable. This does not intentionally tear down an already confirmed link.
Recheck the pair and record new evidence through trusted local administration;
do not edit JSON fields or copy receipts from another router.
