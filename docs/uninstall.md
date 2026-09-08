# Stop, recover and remove

Use the router's existing trusted administrator access. Keep LAN management
available throughout. OpenRHP never needs a firmware flash or router factory reset
for its own removal.

Stopping the controller preserves the configured traffic restrictions:

```sh
/etc/init.d/openrhp stop
```

The root helper installs the persistent guard before its managed stop. The UI may
show a guarded or paused network after restart; reapply and confirm the intended
path through the same API/UI transaction flow. An interrupted apply is recovered
by the detached watchdog from the durable root-owned journal.

## Remove the controller while keeping protection

```sh
/usr/libexec/openrhp-helper decommission --state-dir /etc/openrhp-helper --policy preserve-closed
/etc/init.d/openrhp stop
opkg remove openrhp
```

On an apk-based release, use `apk del openrhp` instead. Keep `openrhp-guard`
installed. Its root helper, persistent nft include and policy-routing blackhole
continue to block protected external traffic while preserving LAN management.
Configuration and credentials remain available for a later reinstall. Do not use
an automatic dependency cleanup that removes the guard.

## Explicitly restore ordinary direct routing

This operation authorizes previously protected clients to use the router's normal
WAN. Choose it deliberately when that is the desired removal policy:

```sh
/etc/init.d/openrhp stop
/usr/libexec/openrhp-helper decommission --state-dir /etc/openrhp-helper --policy restore-direct
/usr/libexec/openrhp-helper can-remove --state-dir /etc/openrhp-helper
opkg remove openrhp openrhp-guard
```

On apk systems, the final command is `apk del openrhp openrhp-guard`. The helper
removes only its own policy rules, routes and firewall processing. It never rewrites
WAN/LAN, DHCP, PPPoE or SSID configuration. The guard package refuses removal while
a protected configuration or pending transaction remains.

If decommission fails partway, the guard remains in place. Repeat the same command
after resolving the reported platform or ownership conflict. Do not fix it with
`nft flush ruleset` or by deleting arbitrary routing rules. The helper refuses to
take over a foreign object in its reserved namespace.

A confirmed transaction can be inspected from the API. Pending transactions must
be confirmed or rolled back before decommission. The helper command `recover`
retries an expired or incomplete rollback; it does not silently open direct access.

## Node agent and personal data

Removing the node agent does not automatically undo a confirmed access-point
configuration or change the shared Wi-Fi key. First revoke its management identity
through the gateway, then decide whether the access point should keep providing
coverage. A pending node change must be confirmed or rolled back while its
independent helper is still installed. Stop and remove `openrhp-node` only after
that transaction is resolved.

Package removal retains configuration directories. Back up or explicitly erase
`/etc/openrhp`, `/etc/openrhp-helper`, `/etc/openrhp-node` and
`/etc/openrhp-node-helper` only after the corresponding services are decommissioned.
These directories contain credentials and private identity keys. Removing an
engine package is a separate administrator choice; the controller does not remove
engines managed by another application.
