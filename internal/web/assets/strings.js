// Runtime messages are kept separate for additional locales. Static English copy
// is in index.html; there is no remote translation/font dependency.
window.RouteHarborStrings = Object.freeze({
  requestFailed: 'The request could not be completed.',
  disconnected: 'Connection lost. Your settings remain on the gateway.',
  saved: 'Settings saved.',
  added: 'Access method added. Check it before enabling selection.',
  queued: 'Checks queued. Results will appear here as they finish.',
  removed: 'Access method removed.',
  noPath: 'No path selected',
  noMeasurement: 'Not measured',
  never: 'Not checked',
  sourceTypes: {
    direct: 'Direct access',
    socks5: 'SOCKS5 proxy',
    'http-connect': 'HTTP CONNECT proxy',
    'sing-box': 'sing-box',
    xray: 'Xray',
    interface: 'Tunnel interface',
    'packet-engine': 'DPI packet engine',
  },
  typeHints: {
    direct:
      'Uses your regular WAN connection. Selective routing excludes direct from bypass selection; it can carry traffic to your private relay.',
    socks5: 'Connect through a SOCKS5 proxy you already control.',
    'http-connect': 'Connect through an HTTP CONNECT proxy you already control.',
    'sing-box': 'Paste one supported outbound object, not a full engine configuration.',
    xray: 'Paste a supported VLESS connection link or a safe Xray outbound object.',
    interface:
      'Use a tunnel already managed by OpenWrt. RouteHarbor does not take over its lifecycle.',
    'packet-engine':
      'Requires a verified nfqws installation and isolated queue support. Availability is checked on the router.',
  },
  removeConfirm: 'Remove this access method? Its stored connection credentials will be deleted.',
  mode: { off: 'Off', auto: 'Automatic', manual: 'Fixed path' },
  check: 'Check',
  remove: 'Remove',
  enabled: 'Enabled',
  auto: 'Use in auto',
  ready: 'Connected to gateway',
  invalidJSON: 'The connection configuration is not valid JSON.',
  routingOff: 'Traffic routing is not applied.',
  routingOn: 'Gateway routing is applied.',
  routingHint:
    'Checks and selection run on this gateway. Applying a network plan is a separate step.',
  routingOnHint: 'Verify internet, DNS and local management from a device on your LAN.',
  noSwitches: 'No path changes have been recorded.',
  noMetrics: 'No measurements yet',
  fresh: 'ago',
  nodeAdded: 'Device identity verified and paired.',
  resourceAdded: 'Resource added. Checks only visit resources you configure.',
  resourceRemoved: 'Resource removed.',
  unsupported:
    'Network routing requires a compatible OpenWrt gateway. You can configure and check methods on this host.',
  preparing: 'Routing plan prepared. Review and apply only with a recovery path available.',
  txnApplied:
    'Routing applied with a rollback deadline. Verify LAN management, DHCP, DNS and internet before confirming.',
  txnConfirmed: 'Connectivity confirmed. The routing plan is now retained.',
  txnRolledBack: 'Rollback requested. Inspect the gateway and transaction state.',
  planSaved: 'Gateway plan saved. Prepare it before applying routing.',
});
