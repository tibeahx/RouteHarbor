'use strict';
(() => {
  const S = window.OpenRHPStrings,
    $ = (id) => document.getElementById(id);
  let token = '',
    cfg = null,
    state = null,
    caps = null,
    poll = null,
    refreshing = false,
    transaction = null;
  const id = () => crypto.randomUUID();
  const el = (tag, text, className) => {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (className) e.className = className;
    return e;
  };

  function notice(message, error = false) {
    $('notice').textContent = message;
    $('notice').className = 'notice' + (error ? ' error' : '');
    $('notice').hidden = false;
  }

  async function api(path, { method = 'GET', data, cas = false, key } = {}) {
    const headers = { Authorization: 'Bearer ' + token };
    if (data !== undefined) headers['Content-Type'] = 'application/json';
    if (
      method !== 'GET' &&
      !['config/validate', 'config/plan', 'config/export', 'nodes/discover'].includes(path) &&
      !path.endsWith('/plan')
    )
      headers['Idempotency-Key'] = key || id();
    if (cas) headers['If-Match'] = '"' + cfg.revision + '"';
    const r = await fetch('/api/v1/' + path, {
      method,
      headers,
      body: data === undefined ? undefined : JSON.stringify(data),
      cache: 'no-store',
      credentials: 'omit',
    });
    let v;
    try {
      v = await r.json();
    } catch {
      throw Error(S.requestFailed);
    }
    if (!r.ok) {
      if (r.status === 401 && path !== 'status') signout();
      throw Error(v.error?.message || S.requestFailed);
    }
    if (v?.state === 'failed') throw Error(v.error_code || S.requestFailed);
    return v;
  }

  async function action(fn, message) {
    try {
      await fn();
      if (message) notice(message);
      await refresh(true);
    } catch (e) {
      notice(e.message, true);
      await refresh(true).catch(() => {});
    }
  }

  function signout() {
    token = '';
    cfg = null;
    state = null;
    clearInterval(poll);
    poll = null;
    closeCoverage();
    $('node-form').reset();
    $('workspace').hidden = true;
    $('login').hidden = false;
    $('signout').hidden = true;
    $('access-key').value = '';
    $('connection').textContent = 'Local management';
    for (const d of document.querySelectorAll('dialog')) d.close();
  }

  function switchTab() {
    const tab = ['overview', 'sources', 'coverage'].includes(location.hash.slice(1))
      ? location.hash.slice(1)
      : 'overview';
    for (const n of ['overview', 'sources', 'coverage']) $(n).hidden = n !== tab;
    document.querySelectorAll('[data-tab]').forEach((a) => {
      if (a.dataset.tab === tab) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }

  function timeAgo(at) {
    if (!at || at.startsWith('0001')) return S.never;
    const sec = Math.max(0, Math.floor((Date.now() - Date.parse(at)) / 1000));
    return sec < 60 ? sec + 's ago' : Math.floor(sec / 60) + 'm ago';
  }

  function speed(v) {
    return v == null ? '—' : (v / 1000000).toFixed(1) + ' Mbps';
  }

  function healthFor(source) {
    return (state?.health || []).find((h) => h.source_id === source.id);
  }

  function quality(h) {
    if (!h) return 'neutral';
    return ['healthy', 'ready'].includes(h.state)
      ? 'good'
      : ['failed', 'unhealthy', 'down'].includes(h.state)
        ? 'bad'
        : 'warning';
  }

  function renderOverview() {
    const d = state.decision || {},
      src = cfg.sources.find((s) => s.id === d.selected),
      h = src && healthFor(src);
    $('decision-state').textContent = d.state || S.never;
    $('decision-dot').className = 'dot ' + quality(h);
    $('active-name').textContent = src?.name || S.noPath;
    $('decision-reason').textContent = d.reason || 'Add an access method and a resource to check.';
    $('latency').textContent =
      h?.last_at && !h.last_at.startsWith('0001') ? Math.round(h.latency_ms) + ' ms' : '—';
    $('speed').textContent = speed(h?.speed_bps);
    $('freshness').textContent = h ? timeAgo(h.last_at) : '—';
    const banner = $('routing-banner');
    banner.replaceChildren(
      el('strong', state.network_applied ? S.routingOn : S.routingOff),
      el('span', state.network_applied ? S.routingOnHint : S.routingHint),
    );
    $('mode-label').textContent = S.mode[cfg.policy.mode] || cfg.policy.mode;
    const history = $('history-list');
    history.replaceChildren();
    for (const e of [...(state.switches || [])].reverse()) {
      history.append(el('li', timeAgo(e.at) + ' — ' + e.reason));
    }
    if (!history.childElementCount) history.append(el('li', S.noSwitches));
  }

  function renderForms() {
    $('selection-mode').value = cfg.policy.mode;
    $('fallback').value = cfg.policy.fallback;
    $('improvement').value = cfg.policy.improvement_percent;
    $('confirmations').value = cfg.policy.confirmations;
    $('pinned-source').replaceChildren();
    for (const s of cfg.sources.filter((s) => s.enabled)) {
      $('pinned-source').append(new Option(s.name, s.id));
    }
    $('pinned-source').value = cfg.policy.pinned || '';
    $('pinned-field').hidden = cfg.policy.mode !== 'manual';
    $('lan-devices').value = cfg.network.lan_interfaces.join(', ');
    $('wan-device').value = cfg.network.wan_interface || '';
    $('local-prefixes').value = cfg.network.local_prefixes.join(', ');
    $('network-enabled').checked = cfg.network.enabled;
    $('dns-mode').value = cfg.network.dns;
    $('dns-resolver').value = cfg.network.dns_resolver || '';
  }

  function renderSources() {
    const list = $('source-list');
    list.replaceChildren();
    $('sources-empty').hidden = cfg.sources.length > 0;
    $('source-count').textContent = cfg.sources.length;
    for (const s of cfg.sources) {
      const h = healthFor(s),
        row = el('article', undefined, 'source-item'),
        name = el('div', undefined, 'source-name'),
        dot = el('span', undefined, 'dot ' + quality(h)),
        text = el('div');
      text.append(el('h3', s.name), el('small', S.sourceTypes[s.type] || s.type));
      name.append(dot, text);
      row.append(name);
      const m = el('div', undefined, 'source-measurement');
      m.append(
        el('div', h ? Math.round(h.latency_ms) + ' ms · ' + speed(h.speed_bps) : S.noMetrics),
        el('small', h ? timeAgo(h.last_at) : S.never),
      );
      row.append(m);
      const options = el('div', undefined, 'source-options');
      for (const [field, title] of [
        ['enabled', S.enabled],
        ['auto', S.auto],
      ]) {
        const l = el('label', undefined, 'check'),
          input = el('input');
        input.type = 'checkbox';
        input.checked = s[field];
        input.setAttribute('aria-label', title + ' ' + s.name);
        input.addEventListener('change', () =>
          action(
            () =>
              api('sources/' + encodeURIComponent(s.id), {
                method: 'PATCH',
                data: { [field]: input.checked },
                cas: true,
              }),
            S.saved,
          ),
        );
        l.append(input, el('span', title));
        options.append(l);
      }
      row.append(options);
      const actions = el('div', undefined, 'source-actions'),
        check = el('button', S.check, 'secondary'),
        remove = el('button', S.remove, 'quiet danger');
      check.disabled = !s.enabled;
      check.addEventListener('click', () =>
        action(
          () =>
            api('sources/' + encodeURIComponent(s.id) + '/probe', {
              method: 'POST',
              data: { speed: true },
            }),
          S.queued,
        ),
      );
      remove.addEventListener('click', () => {
        if (confirm(S.removeConfirm))
          action(
            () => api('sources/' + encodeURIComponent(s.id), { method: 'DELETE', cas: true }),
            S.removed,
          );
      });
      actions.append(check, remove);
      row.append(actions);
      if (h?.resources?.some((r) => !r.success)) {
        const detail = el(
          'small',
          h.resources
            .filter((r) => !r.success)
            .map((r) => r.target_id + ': ' + (r.error_code || 'Unexpected HTTP status'))
            .join('; '),
        );
        row.append(detail);
      }
      list.append(row);
    }
  }

  function renderTargets() {
    const list = $('target-list');
    list.replaceChildren();
    $('targets-empty').hidden = cfg.targets.length > 0;
    for (const t of cfg.targets) {
      const row = el('li'),
        info = el('div', undefined, 'resource-info');
      info.append(
        el('strong', t.url),
        el(
          'small',
          (t.required ? 'Required' : 'Optional') + ' · HTTP ' + t.status_codes.join(', '),
        ),
      );
      const b = el('button', 'Remove', 'quiet');
      b.setAttribute('aria-label', 'Remove resource ' + t.url);
      b.addEventListener('click', () =>
        action(
          () =>
            api('targets', {
              method: 'PUT',
              cas: true,
              data: cfg.targets.filter((v) => v.id !== t.id),
            }),
          S.resourceRemoved,
        ),
      );
      row.append(info, b);
      list.append(row);
    }
  }

  async function refresh(forms = false) {
    if (!token || refreshing) return;
    refreshing = true;
    try {
      const previous = cfg?.revision;
      const [c, s] = await Promise.all([api('config'), api('status')]);
      cfg = c;
      state = s;
      renderOverview();
      renderSources();
      renderTargets();
      if (forms || previous !== cfg.revision) renderForms();
      $('connection').textContent = S.ready;
      $('version').textContent = s.version || 'development';
    } catch (e) {
      if (token) notice(e.message || S.disconnected, true);
      throw e;
    } finally {
      refreshing = false;
    }
  }

  async function loadCapabilities() {
    caps = await api('capabilities');
    const p = caps.platform;
    $('platform-message').textContent = p.supported
      ? 'Detected ' + p.os + ' ' + p.version + ' · ' + p.package_arch
      : S.unsupported;
    const list = p.interfaces || [];
    $('discovered-interfaces').textContent = list
      .map((i) => i.name + ': ' + i.device + ' (' + i.role + ')')
      .join('; ');
    $('prepare-network').disabled = !caps.network_helper || !p.supported;
  }

  function sourceFields() {
    const t = $('source-type').value;
    $('source-type-hint').textContent = S.typeHints[t];
    $('proxy-fields').hidden = !['socks5', 'http-connect'].includes(t);
    $('interface-field').hidden = t !== 'interface';
    $('import-field').hidden = !['sing-box', 'xray'].includes(t);
  }

  function openSource() {
    sourceFields();
    $('source-dialog').showModal();
    $('source-name').focus();
  }
  let coverage = null,
    coverageClock = null,
    gatewayCoverage = null;
  const nodeResult = (v) => v?.result || v;

  function compatibleNodeModes(peer) {
    const g = gatewayCoverage || {},
      m = [];
    if (!g.openwrt || !peer?.openwrt) return m;
    if (
      g.encrypted_backhaul &&
      peer.encrypted_backhaul &&
      g.ap &&
      peer.ap &&
      g.gateway_backhaul_ready
    ) {
      if (g.wds && peer.wds) m.push('wds');
      if (g.mesh && peer.mesh) m.push('mesh');
    }
    if (g.ethernet && peer.ethernet) m.push('ethernet');
    return m;
  }

  function closeCoverage() {
    clearInterval(coverageClock);
    coverageClock = null;
    coverage = null;
    $('coverage-wizard').hidden = true;
    $('coverage-form').reset();
    $('coverage-password').value = '';
  }

  function coverageFacts(target, entries) {
    const list = $(target);
    list.replaceChildren();
    for (const [label, value] of entries) {
      list.append(el('dt', label), el('dd', String(value || 'Not detected')));
    }
  }

  function renderCoverageLink() {
    const h = coverage?.nodeLink,
      metric = (v, unit = '') =>
        v === null || v === undefined ? 'Unavailable' : Number(v).toLocaleString() + unit;
    $('coverage-link-summary').textContent =
      h?.reason ||
      'No current uplink measurements are available. Missing measurements are not treated as a healthy connection.';
    coverageFacts('coverage-link-facts', [
      ['Interface', h?.interface || 'Not identified'],
      [
        'Carrier',
        h?.carrier === true ? 'Link up' : h?.carrier === false ? 'Link down' : 'Unavailable',
      ],
      ['Received / sent bytes', metric(h?.rx_bytes) + ' / ' + metric(h?.tx_bytes)],
      ['Receive / transmit errors', metric(h?.rx_errors) + ' / ' + metric(h?.tx_errors)],
      ['Receive / transmit drops', metric(h?.rx_dropped) + ' / ' + metric(h?.tx_dropped)],
      ['Wi-Fi signal', metric(h?.signal_dbm, ' dBm')],
      [
        'Receive / transmit radio rate',
        metric(h?.rx_bitrate_mbps, ' Mbit/s') + ' / ' + metric(h?.tx_bitrate_mbps, ' Mbit/s'),
      ],
      ['Observed', h?.observed_at ? new Date(h.observed_at).toLocaleString() : 'Unavailable'],
    ]);
  }

  function coverageBridge() {
    return coverage?.setup?.bridges?.find((b) => b.interface === $('coverage-bridge').value);
  }

  function coverageTransactionActive() {
    return ['prepared', 'applying', 'applied', 'rolling-back'].includes(
      coverage?.transaction?.state,
    );
  }

  function syncCoverageButtons() {
    if (!coverage) return;
    const busy = coverage.busy,
      tr = coverage.transaction,
      active = coverageTransactionActive(),
      ready = !!coverageBridge() && coverage.modes.length > 0;
    $('coverage-preview').disabled = busy || !ready || active;
    $('coverage-prepare').disabled = busy || !coverage.draft || active;
    $('coverage-apply').disabled = busy || tr?.state !== 'prepared';
    $('coverage-confirm').disabled =
      busy ||
      tr?.state !== 'applied' ||
      Date.parse(tr.deadline) <= Date.now() ||
      !['management', 'address', 'internet'].every((v) => $('coverage-check-' + v).checked);
    $('coverage-rollback').disabled = busy || !active;
    $('coverage-edit').disabled = busy || active;
    $('coverage-reload').disabled = busy;
    $('coverage-status').disabled = busy;
    $('coverage-link-refresh').disabled = busy;
    $('coverage-close').disabled = busy;
  }

  function renderCoverageTransaction() {
    if (!coverage) return;
    const tr = coverage.transaction,
      active = coverageTransactionActive();
    $('coverage-form').hidden = !!coverage.draft || active;
    $('coverage-review').hidden = !coverage.draft || active;
    $('coverage-transaction').hidden = !tr;
    const step =
      tr?.state === 'applied' || tr?.state === 'confirmed'
        ? 'test'
        : coverage.draft || active
          ? 'review'
          : 'connection';
    document.querySelectorAll('[data-coverage-step]').forEach((item) => {
      if (item.dataset.coverageStep === step) item.setAttribute('aria-current', 'step');
      else item.removeAttribute('aria-current');
    });
    if (tr) {
      const titles = {
        prepared: 'Access point prepared',
        applying: 'Applying the connection',
        applied: 'Test the connection now',
        confirmed: 'Connection confirmed',
        'rolling-back': 'Restoring the previous settings',
        'rolled-back': 'Previous settings restored',
        failed: 'The access point did not apply the plan',
      };
      $('coverage-transaction-title').textContent =
        titles[tr.state] || 'Read the access point status';
      $('coverage-transaction-detail').textContent =
        tr.state === 'prepared'
          ? 'The access point saved its own recovery snapshot. Applying starts its independent rollback timer.'
          : tr.state === 'applied'
            ? 'Connect a device through this access point and complete the checks below before the deadline.'
            : tr.state === 'confirmed'
              ? 'You confirmed the client checks. Future link quality is still reported separately from WAN quality.'
              : tr.state === 'rolled-back'
                ? 'The access point reports that it restored the saved configuration. Verify management and client connectivity.'
                : tr.error_code
                  ? 'The access point reported ' +
                    tr.error_code +
                    '. Read its status before trying again.'
                  : 'The access point owns this operation; closing the panel does not cancel its rollback timer.';
      $('coverage-apply').hidden = tr.state !== 'prepared';
      $('coverage-checks').hidden = tr.state !== 'applied';
      $('coverage-confirm').hidden = tr.state !== 'applied';
      $('coverage-rollback').hidden = !active;
    }
    updateCoverageCountdown();
    syncCoverageButtons();
  }

  function updateCoverageCountdown() {
    if (!coverage) return;
    const tr = coverage.transaction;
    if (tr?.deadline && ['applying', 'applied', 'rolling-back'].includes(tr.state)) {
      const seconds = Math.max(0, Math.ceil((Date.parse(tr.deadline) - Date.now()) / 1000));
      $('coverage-countdown').textContent =
        seconds > 0
          ? 'Confirm within ' +
            seconds +
            ' seconds, or the access point restores its previous settings.'
          : 'The confirmation window has ended. Reading the access point is required to verify rollback.';
    } else $('coverage-countdown').textContent = '';
    syncCoverageButtons();
  }

  async function coverageAction(fn) {
    if (!coverage || coverage.busy) return;
    const current = coverage;
    current.busy = true;
    syncCoverageButtons();
    try {
      await fn(current);
    } catch (e) {
      if (coverage === current) {
        $('coverage-message').textContent = e.message;
        $('coverage-message').className = 'error';
        current.nodeLink = null;
        renderCoverageLink();
      }
    } finally {
      if (coverage === current) {
        current.busy = false;
        renderCoverageTransaction();
      }
    }
  }

  function setCoverageConnection() {
    if (!coverage) return;
    const wifi = $('coverage-connection').value === 'wifi';
    $('coverage-port-label').textContent = wifi
      ? 'Cable uplink port to disconnect from the bridge'
      : 'Port connected to the main router';
    $('coverage-set-wifi').checked = wifi || $('coverage-set-wifi').checked;
    $('coverage-set-wifi').disabled =
      wifi || !(coverage.setup?.radios || []).some((r) => !r.foreign_active);
    $('coverage-wifi-toggle').hidden = wifi;
    $('coverage-radio-fields').hidden = !wifi && !$('coverage-set-wifi').checked;
    $('coverage-wireless-protocol').hidden = !wifi;
    for (const field of [
      'coverage-radio',
      'coverage-ssid',
      'coverage-password',
      'coverage-channel',
    ])
      $(field).required = !$('coverage-radio-fields').hidden;
    $('coverage-compatibility').textContent = wifi
      ? 'The cable uplink will be removed from the bridge before encrypted Wi-Fi backhaul starts. This radio shares airtime with client devices.'
      : coverage.modes.some((m) => m !== 'ethernet')
        ? 'Ethernet keeps one cable uplink and disables any OpenRHP wireless backhaul.'
        : 'Wi-Fi setup is unavailable: both routers must prove encrypted bridge compatibility and the gateway backhaul must already be ready. Ethernet remains available when detected.';
  }

  function fillCoverageBridge() {
    const bridge = coverageBridge();
    $('coverage-port').replaceChildren();
    for (const port of bridge?.ports || []) $('coverage-port').append(new Option(port, port));
    if (bridge?.inactive_ethernet_uplink)
      $('coverage-port').value = bridge.inactive_ethernet_uplink;
    $('coverage-gateway').value =
      bridge?.gateway ||
      (/^(\d{1,3}\.){3}\d{1,3}$/.test(location.hostname) && location.hostname !== '127.0.0.1'
        ? location.hostname
        : '');
    $('coverage-management').textContent = bridge
      ? 'The access point keeps its verified management address: ' + bridge.address + '.'
      : 'A static management bridge was not detected. Read settings again after the node helper is ready.';
    coverageFacts('coverage-detected', [
      ['Access point address', bridge?.address],
      ['Network', bridge?.interface],
      ['Bridge device', bridge?.device],
      ['Cable ports', bridge?.ports?.join(', ')],
      [
        'Settings observed',
        coverage?.setup?.observed_at
          ? new Date(coverage.setup.observed_at).toLocaleString()
          : 'Not detected',
      ],
    ]);
    syncCoverageButtons();
  }

  function fillCoverageSetup() {
    if (!coverage) return;
    const peer = coverage.peer || {},
      setup = coverage.setup || {};
    coverage.modes = compatibleNodeModes(peer);
    $('coverage-bridge').replaceChildren();
    for (const b of setup.bridges || [])
      $('coverage-bridge').append(new Option(b.interface + ' — ' + b.address, b.interface));
    $('coverage-bridge-choice').hidden = (setup.bridges || []).length < 2;
    $('coverage-radio').replaceChildren();
    for (const r of setup.radios || []) {
      const option = new Option(
        r.name + (r.foreign_active ? ' — existing settings need explicit adoption' : ''),
        r.name,
      );
      option.disabled = r.foreign_active;
      $('coverage-radio').append(option);
    }
    const radio = (setup.radios || []).find((r) => !r.foreign_active);
    if (radio) {
      $('coverage-radio').value = radio.name;
      $('coverage-channel').value = radio.channel || '';
    } else {
      $('coverage-set-wifi').disabled = true;
      $('coverage-set-wifi').checked = false;
    }
    $('coverage-protocol').replaceChildren();
    for (const mode of coverage.modes.filter((m) => m !== 'ethernet'))
      $('coverage-protocol').append(
        new Option(mode === 'wds' ? 'WDS / four-address bridge' : '802.11s encrypted mesh', mode),
      );
    const wifi = coverage.modes.some((m) => m !== 'ethernet');
    $('coverage-connection').querySelector('[value="wifi"]').disabled = !wifi;
    $('coverage-connection').querySelector('[value="ethernet"]').disabled =
      !coverage.modes.includes('ethernet');
    $('coverage-connection').value = wifi ? 'wifi' : 'ethernet';
    $('coverage-capability-evidence').textContent = [
      gatewayCoverage?.reason,
      peer.reason,
      ...(setup.wireless_evidence || []).map(
        (e) => e.phy + ' advertises ' + e.advertised_modes.join(', ') + '. ' + e.reason,
      ),
    ]
      .filter(Boolean)
      .join(' ');
    fillCoverageBridge();
    setCoverageConnection();
    $('coverage-message').className = '';
    $('coverage-message').textContent = (setup.issues || []).length
      ? setup.issues.join(' ')
      : coverage.modes.length
        ? 'Detected settings are ready for review. No network changes have been made.'
        : 'No managed connection mode is verified for both routers. Check the compatibility report and existing administrator access.';
    renderCoverageTransaction();
  }

  async function readCoverageStatus(current, initialize = false) {
    const status = await api('nodes/' + encodeURIComponent(current.node.id) + '/status');
    if (coverage !== current) return;
    if (status.capabilities) current.peer = status.capabilities;
    if (status.setup) current.setup = status.setup;
    current.nodeLink = status.node_link || null;
    renderCoverageLink();
    if (status.transaction) current.transaction = status.transaction;
    else if (initialize) current.transaction = null;
    if (initialize) {
      fillCoverageSetup();
      if (status.setup_issue) {
        $('coverage-message').textContent = status.setup_issue;
        $('coverage-message').className = 'error';
      }
    } else renderCoverageTransaction();
  }

  async function openCoverage(node) {
    closeCoverage();
    coverage = {
      node,
      peer: node.capabilities,
      setup: null,
      modes: [],
      draft: null,
      transaction: null,
      nodeLink: null,
      busy: false,
      lastPoll: 0,
    };
    $('coverage-wizard').hidden = false;
    $('coverage-wizard-title').textContent = 'Set up ' + (node.name || 'your access point');
    $('coverage-wizard-title').focus();
    $('coverage-message').className = '';
    $('coverage-message').textContent = 'Reading the access point’s current settings.';
    $('coverage-form').hidden = false;
    $('coverage-review').hidden = true;
    $('coverage-transaction').hidden = true;
    renderCoverageLink();
    await coverageAction((c) => readCoverageStatus(c, true));
    if (!coverage || coverage.node !== node) return;
    coverageClock = setInterval(() => {
      if (!coverage) return;
      updateCoverageCountdown();
      if (
        !$('coverage').hidden &&
        !coverage.busy &&
        Date.now() - coverage.lastPoll > (coverageTransactionActive() ? 5000 : 10000)
      ) {
        coverage.lastPoll = Date.now();
        coverageAction((c) => readCoverageStatus(c));
      }
    }, 1000);
  }

  function collectCoveragePlan() {
    const bridge = coverageBridge();
    if (!bridge)
      throw Error('Read the access point’s detected settings before preparing a connection.');
    const wifi = $('coverage-connection').value === 'wifi',
      setWiFi = wifi || $('coverage-set-wifi').checked;
    const p = {
      name: coverage.node.name || 'Coverage node',
      mode: wifi ? $('coverage-protocol').value : 'ethernet',
      management_interface: bridge.interface,
      bridge_section: bridge.section,
      bridge_device: bridge.device,
      lan_ports: [...bridge.ports],
      uplink: wifi ? 'orhp-backhaul' : $('coverage-port').value,
      management_address: bridge.address,
      gateway_address: $('coverage-gateway').value.trim(),
      share_radio: wifi,
      dhcp_server: false,
      nat: false,
      router_advertisements: false,
      preserve_management_path: $('coverage-management-confirm').checked,
    };
    if (wifi) p.ethernet_uplink = $('coverage-port').value;
    if (setWiFi) {
      p.radio = $('coverage-radio').value;
      p.ssid = $('coverage-ssid').value;
      p.passphrase = $('coverage-password').value;
      p.channel = Number($('coverage-channel').value);
    }
    return p;
  }

  async function renderNodes() {
    const nodes = await api('nodes');
    try {
      const report = await api('nodes/discover', { method: 'POST', data: {} });
      gatewayCoverage = report.gateway_capabilities || null;
    } catch {
      gatewayCoverage = null;
    }
    $('node-list').replaceChildren();
    for (const n of Array.isArray(nodes) ? nodes : nodes.nodes || []) {
      const item = el('article', undefined, 'node-item'),
        head = el('div', undefined, 'section-heading'),
        actions = el('div', undefined, 'coverage-actions'),
        setup = el('button', 'Set up connection', 'secondary'),
        remove = el('button', 'Unpair', 'quiet danger');
      head.append(el('h3', n.name || n.id));
      item.append(
        head,
        el(
          'p',
          'Identity paired. Client traffic and uplink quality have not been verified by pairing.',
        ),
      );
      setup.setAttribute('aria-label', 'Set up connection for ' + (n.name || n.id));
      setup.addEventListener('click', () => openCoverage(n));
      remove.setAttribute('aria-label', 'Unpair ' + (n.name || n.id));
      remove.addEventListener('click', () => {
        if (
          confirm('Revoke control of this access point? Its Wi-Fi password will remain unchanged.')
        )
          action(async () => {
            await api('nodes/' + encodeURIComponent(n.id), { method: 'DELETE' });
            if (coverage?.node.id === n.id) closeCoverage();
            await renderNodes();
          }, 'Access point control revoked.');
      });
      actions.append(setup, remove);
      item.append(actions);
      $('node-list').append(item);
    }
  }
  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const b = e.submitter;
    b.disabled = true;
    token = $('access-key').value.trim();
    $('login-error').textContent = '';
    try {
      await refresh(true);
      $('access-key').value = '';
      $('login').hidden = true;
      $('workspace').hidden = false;
      $('signout').hidden = false;
      switchTab();
      await loadCapabilities();
      await renderNodes();
      poll = setInterval(() => refresh().catch(() => {}), 5000);
    } catch (err) {
      token = '';
      $('login-error').textContent = err.message;
    } finally {
      b.disabled = false;
    }
  });
  $('signout').addEventListener('click', signout);
  window.addEventListener('hashchange', switchTab);
  document
    .querySelectorAll('.close')
    .forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));
  $('add-source').addEventListener('click', openSource);
  $('add-first-source').addEventListener('click', openSource);
  $('source-type').addEventListener('change', sourceFields);
  $('source-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(async () => {
      const type = $('source-type').value;
      let settings = {};
      if (['socks5', 'http-connect'].includes(type)) {
        settings = {
          server: $('proxy-server').value.trim(),
          server_port: Number($('proxy-port').value),
        };
        if ($('proxy-user').value) settings.username = $('proxy-user').value;
        if ($('proxy-password').value) settings.password = $('proxy-password').value;
      } else if (type === 'interface') settings = { name: $('interface-name').value.trim() };
      else if (type === 'packet-engine') settings = { strategy: 'multisplit-v1' };
      else if (['sing-box', 'xray'].includes(type)) {
        const raw = $('source-import').value.trim();
        if (type === 'xray' && raw.startsWith('vless://')) settings = { link: raw };
        else {
          try {
            settings = JSON.parse(raw);
          } catch {
            throw Error(S.invalidJSON);
          }
        }
      }
      await api('sources', {
        method: 'POST',
        cas: true,
        data: {
          id: 'path-' + id(),
          name: $('source-name').value.trim(),
          type,
          enabled: true,
          auto: $('source-auto').checked,
          settings,
        },
      });
      $('source-dialog').close();
      $('source-form').reset();
    }, S.added);
  });
  $('add-resource').addEventListener('click', () => {
    $('resource-dialog').showModal();
    $('resource-url').focus();
  });
  $('resource-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(async () => {
      const target = {
        id: 'resource-' + id(),
        url: $('resource-url').value.trim(),
        required: $('resource-required').checked,
        status_codes: [Number($('resource-status').value)],
        max_bytes: Number($('resource-limit').value),
      };
      await api('targets', { method: 'PUT', cas: true, data: [...cfg.targets, target] });
      $('resource-dialog').close();
      $('resource-form').reset();
    }, S.resourceAdded);
  });
  $('selection-mode').addEventListener('change', () => {
    $('pinned-field').hidden = $('selection-mode').value !== 'manual';
  });
  $('policy-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(() => {
      const policy = {
        ...cfg.policy,
        mode: $('selection-mode').value,
        fallback: $('fallback').value,
        improvement_percent: Number($('improvement').value),
        confirmations: Number($('confirmations').value),
      };
      policy.pinned = policy.mode === 'manual' ? $('pinned-source').value : '';
      return api('policy', { method: 'PUT', cas: true, data: policy });
    }, S.saved);
  });
  $('check-all').addEventListener('click', () =>
    action(() => api('probes', { method: 'POST', data: { speed: true } }), S.queued),
  );
  $('network-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(
      () =>
        api('network', {
          method: 'PUT',
          cas: true,
          data: {
            ...cfg.network,
            enabled: $('network-enabled').checked,
            dns: $('dns-mode').value,
            dns_resolver: $('dns-resolver').value.trim(),
            lan_interfaces: $('lan-devices')
              .value.split(',')
              .map((v) => v.trim())
              .filter(Boolean),
            wan_interface: $('wan-device').value.trim(),
            local_prefixes: $('local-prefixes')
              .value.split(',')
              .map((v) => v.trim())
              .filter(Boolean),
          },
        }),
      S.planSaved,
    );
  });
  $('prepare-network').addEventListener('click', () =>
    action(async () => {
      const op = await api('transactions', {
        method: 'POST',
        cas: true,
        data: { confirm_timeout_seconds: 120 },
      });
      transaction = op.result?.id || op.result?.transaction?.id;
      $('transaction-panel').hidden = false;
      $('transaction-detail').textContent = JSON.stringify(op.result);
      if (!transaction) throw Error('The helper did not return a transaction identifier.');
    }, S.preparing),
  );
  for (const [button, method, message] of [
    ['apply-network', 'apply', S.txnApplied],
    ['confirm-network', 'confirm', S.txnConfirmed],
    ['rollback-network', 'rollback', S.txnRolledBack],
  ])
    $(button).addEventListener('click', () =>
      action(async () => {
        if (!transaction) throw Error('Prepare a routing transaction first.');
        const op = await api('transactions/' + encodeURIComponent(transaction) + '/' + method, {
          method: 'POST',
          data: {},
        });
        $('transaction-detail').textContent = JSON.stringify(op.result);
      }, message),
    );
  $('download-diagnostics').addEventListener('click', () =>
    action(async () => {
      const v = await api('diagnostics'),
        blob = new Blob([JSON.stringify(v, null, 2)], { type: 'application/json' }),
        u = URL.createObjectURL(blob),
        a = el('a');
      a.href = u;
      a.download = 'openrhp-diagnostics.json';
      a.click();
      setTimeout(() => URL.revokeObjectURL(u), 1000);
    }),
  );
  $('pair-node').addEventListener('click', () => {
    $('node-dialog').showModal();
    $('node-name').focus();
  });
  $('node-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(async () => {
      const result = nodeResult(
        await api('nodes/pair', {
          method: 'POST',
          data: {
            name: $('node-name').value.trim(),
            address: $('node-address').value.trim(),
            fingerprint: $('node-fingerprint').value.trim(),
            code: $('node-code').value,
          },
        }),
      );
      $('node-dialog').close();
      $('node-form').reset();
      await renderNodes();
      if (result.node?.id) await openCoverage(result.node);
    }, S.nodeAdded);
  });
  $('coverage-close').addEventListener('click', closeCoverage);
  $('coverage-reload').addEventListener('click', () =>
    coverageAction((c) => readCoverageStatus(c, true)),
  );
  $('coverage-status').addEventListener('click', () =>
    coverageAction((c) => readCoverageStatus(c)),
  );
  $('coverage-link-refresh').addEventListener('click', () =>
    coverageAction((c) => readCoverageStatus(c)),
  );
  $('coverage-bridge').addEventListener('change', fillCoverageBridge);
  $('coverage-connection').addEventListener('change', setCoverageConnection);
  $('coverage-set-wifi').addEventListener('change', setCoverageConnection);
  $('coverage-radio').addEventListener('change', () => {
    const radio = coverage?.setup?.radios?.find((r) => r.name === $('coverage-radio').value);
    $('coverage-channel').value = radio?.channel || '';
  });
  for (const check of ['management', 'address', 'internet'])
    $('coverage-check-' + check).addEventListener('change', syncCoverageButtons);
  $('coverage-form').addEventListener('submit', (e) => {
    e.preventDefault();
    coverageAction(async (c) => {
      const p = collectCoveragePlan();
      await api('nodes/' + encodeURIComponent(c.node.id) + '/plan', { method: 'POST', data: p });
      if (coverage !== c) return;
      c.draft = { plan: p, key: id() };
      c.transaction = null;
      $('coverage-message').textContent =
        'Review the connection before saving a recovery snapshot on the access point.';
      $('coverage-message').className = '';
      coverageFacts('coverage-review-facts', [
        ['Access point', c.node.name],
        ['Connection', p.mode === 'ethernet' ? 'Ethernet cable' : 'Encrypted Wi-Fi bridge'],
        ['Main router', p.gateway_address],
        ['Access point address', p.management_address],
        [
          'Cable uplink',
          p.mode === 'ethernet' ? p.uplink : p.ethernet_uplink + ' will leave the bridge',
        ],
        [
          'Wi-Fi settings',
          p.radio ? p.ssid + ' (password hidden)' : 'Keep existing Wi-Fi settings',
        ],
        ['Address server and routing', 'Main router only'],
      ]);
    });
  });
  $('coverage-edit').addEventListener('click', () => {
    if (!coverage || coverageTransactionActive()) return;
    coverage.draft = null;
    renderCoverageTransaction();
  });
  $('coverage-prepare').addEventListener('click', () =>
    coverageAction(async (c) => {
      if (!c.draft) throw Error('Review a connection first.');
      const result = nodeResult(
        await api('nodes/' + encodeURIComponent(c.node.id) + '/prepare', {
          method: 'POST',
          key: c.draft.key,
          data: { key: c.draft.key, plan: c.draft.plan },
        }),
      );
      if (coverage !== c) return;
      if (!result.transaction?.id)
        throw Error(
          'The access point did not return a transaction identifier. Read its status before retrying.',
        );
      c.transaction = result.transaction;
      c.draft.plan.passphrase = '';
      $('coverage-password').value = '';
      $('coverage-message').textContent =
        'The access point prepared its own recovery snapshot. Review the connection, then apply when you are ready to test it.';
      $('coverage-message').className = '';
    }),
  );
  for (const [button, method] of [
    ['coverage-apply', 'apply'],
    ['coverage-confirm', 'confirm'],
    ['coverage-rollback', 'rollback'],
  ])
    $(button).addEventListener('click', () =>
      coverageAction(async (c) => {
        if (!c.transaction?.id) throw Error('Prepare the access point first.');
        const result = nodeResult(
          await api('nodes/' + encodeURIComponent(c.node.id) + '/' + method, {
            method: 'POST',
            data: { id: c.transaction.id, ...(method === 'apply' ? { timeout_seconds: 90 } : {}) },
          }),
        );
        if (coverage !== c) return;
        if (result.transaction) c.transaction = result.transaction;
        else await readCoverageStatus(c);
        if (method === 'apply')
          for (const check of ['management', 'address', 'internet'])
            $('coverage-check-' + check).checked = false;
        if (['confirm', 'rollback'].includes(method)) c.draft = null;
        $('coverage-message').className = '';
        $('coverage-message').textContent =
          method === 'apply'
            ? 'Settings applied. Test a client connection before confirming.'
            : method === 'confirm'
              ? 'The access point accepted your connectivity confirmation.'
              : 'The access point reported its rollback result.';
      }),
    );
})();
