'use strict';
(() => {
  const S = window.OpenRHPStrings,
    $ = (id) => document.getElementById(id);
  let token = '',
    cfg = null,
    state = null,
    routingState = null,
    caps = null,
    poll = null,
    refreshing = false,
    transaction = null,
    backupBusy = false,
    backupLoad = 0,
    backupPreview = null;
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

  async function api(
    path,
    { method = 'GET', data, cas = false, key, revision, allowFailed = false, signal } = {},
  ) {
    const headers = { Authorization: 'Bearer ' + token };
    if (data !== undefined) headers['Content-Type'] = 'application/json';
    if (
      method !== 'GET' &&
      !['config/validate', 'config/plan', 'config/export', 'nodes/discover'].includes(path) &&
      !path.endsWith('/plan')
    )
      headers['Idempotency-Key'] = key || id();
    if (cas) headers['If-Match'] = '"' + (revision ?? cfg.revision) + '"';
    const r = await fetch('/api/v1/' + path, {
      method,
      headers,
      body: data === undefined ? undefined : JSON.stringify(data),
      cache: 'no-store',
      credentials: 'omit',
      signal,
    });
    let v;
    try {
      v = await r.json();
    } catch {
      const error = Error(S.requestFailed);
      error.status = r.status;
      error.location = r.headers.get('Location');
      throw error;
    }
    if (!r.ok) {
      if (r.status === 401 && path !== 'status') signout();
      const error = Error(v.error?.message || S.requestFailed);
      error.status = r.status;
      error.location = r.headers.get('Location');
      error.code = v.error?.code;
      error.retryable = v.error?.retryable === true;
      throw error;
    }
    if (!allowFailed && v?.state === 'failed') throw Error(v.error_code || S.requestFailed);
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
    routingState = null;
    $('routing-check-result').textContent = '';
    gatewayCoverage = null;
    gatewaySetup = null;
    gatewayFingerprint = '';
    clearInterval(poll);
    poll = null;
    closeCoverage();
    $('node-form').reset();
    $('workspace').hidden = true;
    $('login').hidden = false;
    $('signout').hidden = true;
    $('access-key').value = '';
    $('connection').textContent = 'Local management';
    backupPreview = null;
    backupLoad++;
    setBackupBusy(false);
    $('backup-list').replaceChildren();
    $('backup-config').textContent = '';
    $('backup-source-preview').replaceChildren();
    $('backup-settings').open = false;
    resetMaintenance();
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
    if (state.network_applied && !state.network?.confirmed_for_current_config) {
      banner.append(
        el(
          'span',
          'Saved changes are pending. Prepare and confirm routing to use the updated settings.',
        ),
      );
    }
    if (state.network?.last_error) {
      const message =
        state.network.last_error === 'conntrack_delete_failed'
          ? 'Routing is active, but clearing old connection tracking failed. Inspect the routing transaction and retry confirmation.'
          : 'Routing needs attention: ' + state.network.last_error;
      banner.append(el('span', message));
    }
    $('mode-label').textContent = S.mode[cfg.policy.mode] || cfg.policy.mode;
    const history = $('history-list');
    history.replaceChildren();
    for (const e of [...(state.switches || [])].reverse()) {
      history.append(el('li', timeAgo(e.at) + ' — ' + e.reason));
    }
    if (!history.childElementCount) history.append(el('li', S.noSwitches));
  }

  function renderForms() {
    const selective = cfg.routing?.mode === 'selective';
    const fixedBypassPolicy = selective || cfg.continuity?.enabled === true;
    $('selection-mode').value = cfg.policy.mode;
    $('fallback').value = cfg.policy.fallback;
    $('fallback').disabled = fixedBypassPolicy;
    $('fallback').querySelector('option[value="direct"]').disabled = fixedBypassPolicy;
    $('fallback-label').textContent = selective
      ? 'When no healthy bypass remains'
      : 'When no healthy path remains';
    $('fallback-selective-help').hidden = !selective;
    $('improvement').value = cfg.policy.improvement_percent;
    $('confirmations').value = cfg.policy.confirmations;
    $('break-existing').checked = cfg.policy.break_existing;
    $('break-existing').disabled =
      cfg.routing?.mode === 'selective' || cfg.continuity?.enabled === true;
    $('pinned-source').replaceChildren();
    for (const s of cfg.sources.filter(
      (s) =>
        s.enabled &&
        (s.type !== 'direct' || cfg.routing?.mode !== 'selective' || cfg.continuity?.enabled),
    )) {
      $('pinned-source').append(new Option(s.name, s.id));
    }
    $('pinned-source').value = cfg.policy.pinned || '';
    $('pinned-field').hidden = cfg.policy.mode !== 'manual';
    $('lan-devices').value = cfg.network.lan_interfaces.join(', ');
    $('wan-device').value = cfg.network.wan_interface || '';
    $('local-prefixes').value = cfg.network.local_prefixes.join(', ');
    $('network-enabled').checked = cfg.network.enabled;
    $('dns-mode').value = cfg.network.dns;
    $('dns-mode').disabled = selective;
    $('dns-mode-label').textContent = selective ? 'Legacy DNS policy' : 'DNS policy';
    $('dns-selective-help').hidden = !selective;
    $('dns-resolver-label').textContent = selective
      ? 'DNS resolver IP (required for managed DNS)'
      : 'DNS resolver IP (required for selected path)';
    $('dns-resolver').value = cfg.network.dns_resolver || '';
    const continuity = cfg.continuity || {};
    $('continuity-enabled').checked = continuity.enabled === true;
    $('continuity-relay').value = continuity.relay_address || '';
    $('continuity-pin').value = continuity.relay_fingerprint || '';
    $('continuity-buffer').value = (continuity.buffer_bytes ?? 33554432) / 1048576;
    $('continuity-udp-reserve').value = (continuity.udp_reserve_bytes ?? 4194304) / 1048576;
    $('continuity-grace').value = continuity.disconnected_grace_seconds ?? 30;
    continuityRequired();
    const routing = cfg.routing || {};
    $('routing-mode').value = routing.mode || 'legacy-all';
    $('routing-registry').checked = routing.registry?.enabled === true;
    $('routing-detection').checked = routing.detection?.enabled === true;
    $('routing-controls').value = (routing.detection?.control_target_ids || []).join(', ');
    $('routing-rules').replaceChildren();
    for (const rule of routing.exceptions || []) addRoutingRule(rule);
  }

  function addRoutingRule(rule = { action: 'bypass' }) {
    const row = el('fieldset'),
      legend = el('legend', 'Exception'),
      actionLabel = el('label', 'Route'),
      action = el('select'),
      domainLabel = el('label', 'Domain, IP or CIDR'),
      destination = el('input'),
      subLabel = el('label', 'Include subdomains'),
      sub = el('input'),
      remove = el('button', 'Remove exception', 'quiet');
    action.append(new Option('Direct WAN', 'direct'), new Option('Selected bypass', 'bypass'));
    action.value = rule.action;
    action.dataset.ruleAction = '';
    actionLabel.append(action);
    destination.value = rule.domain || rule.cidr || '';
    destination.required = true;
    destination.maxLength = 253;
    destination.dataset.ruleDestination = '';
    domainLabel.append(destination);
    sub.type = 'checkbox';
    sub.checked = rule.include_subdomains === true;
    sub.dataset.ruleSubdomains = '';
    subLabel.className = 'check';
    subLabel.prepend(sub);
    remove.type = 'button';
    remove.addEventListener('click', () => row.remove());
    row.append(legend, actionLabel, domainLabel, subLabel, remove);
    $('routing-rules').append(row);
  }

  function renderSelectiveRouting() {
    const r = routingState || {},
      registry = r.registry || {},
      detection = r.detection || {};
    $('selective-state').textContent = r.state || 'Unavailable';
    $('selective-emergency').hidden = r.state !== 'emergency-direct';
    $('selective-legacy').hidden = cfg.routing?.mode === 'selective';
    $('selective-detail').textContent =
      r.state === 'unavailable' || !r.state
        ? 'No classifier readiness measurement is available.'
        : r.state === 'inactive'
          ? 'Routing is not active. Review and confirm a network transaction.'
          : r.state === 'emergency-direct'
            ? 'Classifier or managed DNS failure: emergency direct.'
            : cfg.routing?.mode === 'selective'
              ? 'Ordinary destinations use direct WAN. Bypass rules use the selected method.'
              : 'Legacy routing applies the selected method to all external destinations.';
    const count = (value) => (Number.isFinite(value) ? String(value) : '—');
    const metrics = [
      ['Bypass method', r.selected || '—'],
      [
        'List source',
        registry.provider === 'antifilter'
          ? 'Antifilter · third-party registry publication'
          : registry.provider || '—',
      ],
      [
        'List freshness',
        registry.updated_at
          ? timeAgo(registry.updated_at) + (registry.stale ? ' · Stale' : '')
          : registry.stale
            ? 'Stale · no current snapshot'
            : '—',
      ],
      ['Registry domains', count(registry.domain_count)],
      ['Explicit IP ranges', count(registry.cidr_count)],
      ['Detected restriction rules', count(detection.learned_count)],
      ['Pending comparisons', count(detection.pending_count)],
      ['Published generation', count(r.published_generation)],
      ['Verified engine generation', count(r.verified_generation)],
      ['List update issue', registry.last_error || '—'],
      ['Detection issue', detection.last_error || '—'],
    ];
    $('selective-metrics').replaceChildren();
    for (const [label, value] of metrics)
      $('selective-metrics').append(el('dt', label), el('dd', value));
  }

  async function routingOperation(path, data) {
    let op = await api(path, { method: 'POST', cas: true, data });
    for (let i = 0; ['pending', 'running'].includes(op.state) && i < 120; i++) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      if (!token) return;
      op = await api('operations/' + op.id);
    }
    if (['pending', 'running'].includes(op.state))
      throw Error('The operation is still running. Check the operation journal before retrying.');
    const result = op.result?.routing || {};
    $('routing-check-result').textContent = path.endsWith('/check')
      ? [
          'Route: ' + (result.action || 'Unknown'),
          'Reason: ' + (result.reason || 'Unknown'),
          'Path: ' + (result.route || 'Unknown'),
          result.expires_at ? 'Expires: ' + result.expires_at : '',
        ]
          .filter(Boolean)
          .join(' · ')
      : 'Registry refresh completed. Review snapshot freshness and published generation.';
  }

  function continuityRequired() {
    const enabled = $('continuity-enabled').checked;
    $('continuity-relay').required = enabled;
    $('continuity-pin').required = enabled;
  }

  function renderContinuity() {
    const enabled = cfg.continuity?.enabled === true,
      c = state.continuity || {},
      status = enabled ? c.status || 'Unavailable' : 'Disabled';
    $('continuity-state').textContent = status;
    const paths = (c.paths || []).map((p) => p.name + ': ' + (p.ready ? 'ready' : 'not ready'));
    $('continuity-detail').textContent = !enabled
      ? 'Session continuity is disabled.'
      : [
          c.degraded_reason || (c.status ? '' : 'No worker readiness measurement is available.'),
          ...paths,
        ]
          .filter(Boolean)
          .join(' · ') || 'Readiness reported by the continuity worker.';
    $('continuity-qualification').textContent =
      c.qualified === true
        ? 'A measured qualification is available for the current device and path profile; runtime conditions may change.'
        : 'Switch latency has not been qualified for this device and path profile.';
    $('continuity-fingerprint').textContent = c.worker_fingerprint || 'Not provisioned';
    const number = (n, suffix = '') => (Number.isFinite(n) ? String(n) + suffix : '—'),
      bytes = (n) =>
        !Number.isFinite(n)
          ? '—'
          : n < 1024
            ? n + ' B'
            : n < 1048576
              ? (n / 1024).toFixed(2) + ' KiB'
              : (n / 1048576).toFixed(2) + ' MiB',
      values = [
        ['Active path', c.active_path || '—'],
        ['Standby path', c.standby_path || '—'],
        ['Buffered traffic', bytes(c.queue_bytes)],
        ['UDP queued', bytes(c.udp_queue_bytes)],
        ['Control queued', bytes(c.control_queue_bytes)],
        ['TCP flows', number(c.tcp_flows)],
        ['UDP flows', number(c.udp_flows)],
        ['Replayed frames', number(c.replayed_frames)],
        ['Expired UDP', number(c.expired_udp)],
        ['Dropped UDP', number(c.dropped_udp)],
        ['Path switches', number(c.switches)],
        [
          'Last path change to acknowledgement',
          c.switches > 0 ? number(c.last_switch_pause_ms, ' ms') : '—',
        ],
      ];
    $('continuity-metrics').replaceChildren();
    for (const [name, value] of values)
      $('continuity-metrics').append(el('dt', name), el('dd', value));
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
      if (state.network?.unavailable_sources?.includes(s.id)) {
        row.append(
          el(
            'small',
            'Unavailable when routing was applied. After recovery, review and apply routing again to use this source.',
          ),
        );
      }
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

  function setBackupBusy(value) {
    backupBusy = value;
    for (const button of document.querySelectorAll('#backup-settings button, #restore-backup')) {
      button.disabled = value;
    }
  }

  async function loadBackups() {
    const access = token,
      load = ++backupLoad;
    const result = await api('config/backups');
    if (!access || access !== token || load !== backupLoad) return;
    const list = $('backup-list');
    list.replaceChildren();
    $('backup-summary').textContent = result.backups.length
      ? result.backups.length + ' of ' + result.max_backups + ' backups saved · 2 MiB total limit'
      : 'No backups yet. Save your current settings before making changes.';
    for (const backup of result.backups) {
      const row = el('li'),
        info = el('div'),
        actions = el('div', undefined, 'backup-actions');
      row.dataset.backupId = backup.id;
      info.append(
        el('strong', 'Revision ' + backup.revision),
        el(
          'small',
          new Date(backup.created_at).toLocaleString() +
            ' · ' +
            backup.source_count +
            ' methods · ' +
            backup.target_count +
            ' resources',
        ),
      );
      const preview = el('button', 'Preview', 'secondary');
      preview.addEventListener('click', () =>
        previewBackup(backup.id).catch((e) => notice(e.message, true)),
      );
      const remove = el('button', 'Delete', 'quiet danger');
      remove.addEventListener('click', () => {
        if (!confirm('Delete this saved backup? Your current settings will stay unchanged.'))
          return;
        backupAction(
          () =>
            api('config/backups/' + encodeURIComponent(backup.id), { method: 'DELETE', cas: true }),
          'Backup deleted. Current settings are unchanged.',
        );
      });
      actions.append(preview, remove);
      row.append(info, actions);
      list.append(row);
    }
    setBackupBusy(backupBusy);
  }

  async function previewBackup(id) {
    if (backupBusy) return;
    const access = token,
      revision = cfg.revision;
    setBackupBusy(true);
    try {
      const result = await api('config/backups/' + encodeURIComponent(id));
      if (!access || access !== token) return;
      backupPreview = { id, revision };
      $('backup-preview-error').textContent = '';
      $('backup-detail').textContent =
        'Saved revision ' +
        result.backup.revision +
        ' · ' +
        new Date(result.backup.created_at).toLocaleString();
      $('backup-config').textContent = JSON.stringify(result.configuration, null, 2);
      const sources = $('backup-source-preview');
      sources.replaceChildren();
      for (const source of result.configuration.sources) {
        sources.append(el('li', source.name + ' · ' + (S.sourceTypes[source.type] || source.type)));
      }
      if (!sources.childElementCount) sources.append(el('li', 'No access methods in this backup.'));
      $('backup-dialog').showModal();
      $('restore-backup').focus();
    } finally {
      if (access === token) setBackupBusy(false);
    }
  }

  async function backupAction(fn, message) {
    if (backupBusy) return;
    const access = token;
    setBackupBusy(true);
    try {
      await fn();
      if (access !== token) return;
      notice(message);
      await refresh(true);
      await loadBackups();
    } catch (e) {
      if (access !== token) return;
      notice(e.message, true);
      if ($('backup-dialog').open)
        $('backup-preview-error').textContent =
          e.message + ' Close and reopen this preview if the current settings have changed.';
      await refresh(true).catch(() => {});
      await loadBackups().catch(() => {});
    } finally {
      if (access === token) setBackupBusy(false);
    }
  }

  const maintenanceComponents = [
    'openrhp',
    'openrhp-sing-box',
    'openrhp-xray',
    'openrhp-conntrack',
    'openrhp-continuity',
  ];
  const maintenanceID = /^[0-9a-f]{32}$/;
  const maintenanceActive = ['prepared', 'running', 'verifying'];
  const maintenanceTerminal = ['completed', 'failed', 'interrupted'];
  let maintenance = {};

  function resetMaintenance() {
    clearTimeout(maintenance.timer);
    maintenance = {
      review: null,
      attempted: false,
      rejected: false,
      busy: false,
      reading: false,
      job: null,
      timer: null,
    };
    $('maintenance-form').reset();
    $('maintenance-settings').open = false;
    $('maintenance-plan').hidden = true;
    $('maintenance-progress').hidden = true;
    $('maintenance-feedback').textContent = '';
    $('maintenance-operation-id').value = '';
    $('maintenance-local-command').hidden = true;
    $('maintenance-local-command').textContent = '';
    maintenanceControls();
  }

  async function maintenanceAPI(path, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.method === 'POST' ? 30000 : 10000);
    try {
      return await api('maintenance/' + path, {
        ...options,
        signal: controller.signal,
        allowFailed: true,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  function maintenanceFinished(m) {
    return (
      maintenanceTerminal.includes(m.job?.state) && (!m.attempted || m.job.id === m.operationID)
    );
  }

  function maintenanceControls() {
    const m = maintenance;
    const terminal = maintenanceFinished(m);
    const locked =
      m.uncertainStatus ||
      (m.attempted && !m.rejected && !terminal) ||
      maintenanceActive.includes(m.job?.state);
    for (const input of $('maintenance-form').elements) input.disabled = !!m.busy || locked;
    $('maintenance-reload').disabled = !!m.busy || locked;
    $('maintenance-start').disabled = !!m.busy || !m.review || m.attempted;
    $('maintenance-retry').hidden = !m.attempted || terminal || !m.review;
    $('maintenance-retry').disabled = !!m.busy;
    $('maintenance-edit').disabled = !!m.busy || locked;
    $('maintenance-status').disabled = !!m.reading;
    const removing = $('maintenance-action').value === 'remove';
    $('maintenance-bundle-field').hidden = removing;
    $('maintenance-removal-field').hidden = !removing;
    $('maintenance-direct-consent-field').hidden =
      !removing || $('maintenance-removal-policy').value !== 'restore-direct';
    $('maintenance-self-removal').hidden =
      !removing ||
      !document.querySelector('#maintenance-components input[value="openrhp"]').checked;
  }

  function invalidateMaintenanceReview(message = '') {
    if (maintenance.attempted && !maintenance.rejected && !maintenanceFinished(maintenance)) return;
    maintenance.review = null;
    maintenance.attempted = false;
    maintenance.rejected = false;
    $('maintenance-plan').hidden = true;
    $('maintenance-feedback').textContent = message;
    maintenanceControls();
  }

  async function loadMaintenance() {
    const m = maintenance;
    if (m.busy || (m.attempted && !m.rejected && !maintenanceFinished(m))) return;
    m.busy = true;
    maintenanceControls();
    const results = await Promise.allSettled([
      maintenanceAPI('capabilities'),
      maintenanceAPI('bundles'),
    ]);
    if (m !== maintenance || !token) return;
    const [capability, bundles] = results;
    $('maintenance-availability').textContent =
      capability.status === 'fulfilled'
        ? 'Architecture: ' +
          (capability.value.architecture || 'unknown') +
          '. ' +
          (capability.value.available === false
            ? 'Maintenance is unavailable: ' +
              (capability.value.reason || 'required package service or safety package is missing') +
              '. '
            : '') +
          (capability.value.trusted_key_available === false
            ? 'A trusted verification key is unavailable. '
            : '') +
          (capability.value.active
            ? 'A package operation is active. Read its status before continuing.'
            : 'Review a plan to check the staged bundle and installed packages.')
        : capability.reason.message;
    const selection = $('maintenance-bundle'),
      previous = selection.value;
    selection.replaceChildren(new Option('Select a staged signed bundle', ''));
    if (bundles.status === 'fulfilled') {
      for (const bundle of bundles.value || []) {
        if (maintenanceID.test(bundle.id))
          selection.add(
            new Option(bundle.version + ' · ' + bundle.architecture + ' · ' + bundle.id, bundle.id),
          );
      }
      selection.value = previous;
      if (!selection.value) selection.value = '';
      if (selection.options.length === 1)
        $('maintenance-availability').textContent +=
          ' No signed bundles are staged; installation and upgrades require trusted local staging.';
    } else $('maintenance-availability').textContent += ' ' + bundles.reason.message;
    if (selection.value !== previous)
      invalidateMaintenanceReview('Bundle availability changed. Review a fresh plan.');
    m.busy = false;
    maintenanceControls();
    const activeID = capability.status === 'fulfilled' && capability.value.active_operation_id;
    if (maintenanceID.test(activeID || '') && !$('maintenance-operation-id').value)
      readMaintenanceStatus(activeID);
  }

  function maintenanceRequest() {
    const request = {
      action: $('maintenance-action').value,
      components: [...document.querySelectorAll('#maintenance-components input:checked')]
        .map((input) => input.value)
        .sort(),
      expected_installed_digest: '',
    };
    if (
      !request.components.length ||
      request.components.some((name) => !maintenanceComponents.includes(name))
    )
      throw Error('Select at least one supported software component.');
    if (request.action === 'remove') {
      request.removal_policy = $('maintenance-removal-policy').value;
      if (request.removal_policy === 'restore-direct' && !$('maintenance-direct-consent').checked)
        throw Error('Explicitly allow direct internet access before reviewing this removal plan.');
    } else {
      request.bundle_id = $('maintenance-bundle').value;
      if (!maintenanceID.test(request.bundle_id))
        throw Error('Select a staged signed bundle first.');
    }
    return request;
  }

  async function reviewMaintenance() {
    const m = maintenance;
    if (m.busy || (m.attempted && !m.rejected && !maintenanceFinished(m))) return;
    m.busy = true;
    maintenanceControls();
    $('maintenance-feedback').textContent = '';
    try {
      const request = maintenanceRequest(),
        revision = cfg.revision;
      const plan = await maintenanceAPI('plan', { method: 'POST', data: request });
      if (m !== maintenance || !token) return;
      const canonical = plan.request;
      if (
        !/^[0-9a-f]{64}$/.test(plan.installed_digest) ||
        canonical?.expected_installed_digest !== plan.installed_digest ||
        canonical.action !== request.action ||
        (canonical.bundle_id || '') !== (request.bundle_id || '') ||
        (canonical.removal_policy || '') !== (request.removal_policy || '') ||
        JSON.stringify([...(canonical.components || [])].sort()) !==
          JSON.stringify(request.components)
      )
        throw Error(
          'The package service returned an inconsistent plan. Refresh software availability.',
        );
      if (cfg.revision !== revision)
        throw Error('Configuration changed during review. Review a fresh software plan.');
      const frozen = { ...request, expected_installed_digest: plan.installed_digest };
      m.review = {
        request: Object.freeze({ ...frozen, components: Object.freeze([...frozen.components]) }),
        revision,
        key: id(),
      };
      clearTimeout(m.timer);
      m.attempted = false;
      m.rejected = false;
      m.uncertainStatus = false;
      m.job = null;
      m.operationID = '';
      m.statusID = '';
      $('maintenance-progress').hidden = true;
      $('maintenance-operation-id').value = '';
      $('maintenance-local-command').hidden = true;
      history.replaceState(null, '', '#overview');
      $('maintenance-plan').hidden = false;
      $('maintenance-plan-detail').textContent =
        request.action +
        ' · ' +
        request.components.join(', ') +
        ' · configuration revision ' +
        revision +
        (request.removal_policy ? ' · ' + request.removal_policy : '');
      $('maintenance-packages').replaceChildren(
        ...(plan.packages || []).map((pkg) =>
          el('li', pkg.name + ' · ' + pkg.version + ' · ' + pkg.architecture),
        ),
      );
      $('maintenance-warnings').replaceChildren(
        ...(plan.warnings || []).map((warning) => el('li', warning)),
      );
      $('maintenance-request-reference').textContent =
        'Installed inventory: ' +
        plan.installed_digest +
        '. Request key: ' +
        m.review.key +
        '. Retrying will reuse this exact reviewed request and revision.';
    } catch (error) {
      if (m === maintenance) {
        m.review = null;
        $('maintenance-plan').hidden = true;
        $('maintenance-feedback').textContent = error.message;
      }
    } finally {
      if (m === maintenance) {
        m.busy = false;
        maintenanceControls();
      }
    }
  }

  function maintenanceReference(operationID) {
    if (!maintenanceID.test(operationID))
      throw Error('The service did not return a valid maintenance operation ID.');
    $('maintenance-operation-id').value = operationID;
    $('maintenance-local-command').textContent =
      '/usr/libexec/openrhp-helper maintenance-status --operation ' + operationID;
    $('maintenance-local-command').hidden = false;
    history.replaceState(null, '', '#overview/maintenance/' + operationID);
    return operationID;
  }

  function showMaintenanceOperation(job, expectedID) {
    if (
      !job ||
      job.id !== expectedID ||
      !maintenanceID.test(job.id) ||
      typeof job.phase !== 'string' ||
      !job.phase ||
      !['install', 'upgrade', 'remove'].includes(job.action) ||
      ![...maintenanceActive, ...maintenanceTerminal].includes(job.state)
    )
      throw Error(
        'The response is not a verified package-service status. Read the maintenance operation by ID; a dispatch acknowledgement does not prove completion.',
      );
    maintenance.job = job;
    maintenance.uncertainStatus = false;
    maintenanceReference(job.id);
    $('maintenance-progress').hidden = false;
    const detail = {
      prepared: 'Maintenance is prepared and waiting for its worker.',
      running: 'Maintenance is running.',
      verifying: 'Installed software is being verified.',
      completed: 'Software maintenance completed.',
      failed:
        'Software maintenance failed. Inspect trusted local status before deciding how to recover.',
      interrupted:
        'Software maintenance was interrupted. Package-manager reconciliation and trusted local operator recovery are required; do not start another operation blindly.',
    };
    $('maintenance-operation-detail').textContent =
      detail[job.state] +
      ' Operation ' +
      job.id +
      ' · phase: ' +
      job.phase.replaceAll('_', ' ') +
      (job.error_code ? ' · ' + job.error_code : '');
    $('maintenance-guard-detail').textContent =
      (job.guard_retained
        ? 'The service reports that the safety package is retained.'
        : 'The service does not report a retained safety package.') +
      ' This field does not establish the active traffic policy. Check the reviewed removal policy and local network status.';
    maintenanceControls();
  }

  async function readMaintenanceStatus(
    operationID = $('maintenance-operation-id').value.trim(),
    busyRetries = 0,
  ) {
    const m = maintenance;
    if (m.reading) return;
    clearTimeout(m.timer);
    if (!maintenanceID.test(operationID)) {
      $('maintenance-feedback').textContent = 'Supply a 32-character maintenance operation ID.';
      return;
    }
    m.reading = true;
    m.statusID = operationID;
    m.uncertainStatus = true;
    maintenanceReference(operationID);
    maintenanceControls();
    try {
      const job = await maintenanceAPI('operations/' + operationID);
      if (m !== maintenance || !token) return;
      if (m.statusID !== operationID) return;
      showMaintenanceOperation(job, operationID);
      $('maintenance-feedback').textContent =
        m.attempted && m.operationID !== operationID
          ? 'This status does not identify the pending reviewed request. Keep its original request key for retry.'
          : '';
      if (maintenanceActive.includes(job.state))
        m.timer = setTimeout(() => readMaintenanceStatus(operationID), 3000);
    } catch (error) {
      if (m === maintenance && token && m.statusID === operationID) {
        if (
          error.status === 503 &&
          error.code === 'maintenance_state_busy' &&
          error.retryable === true &&
          busyRetries < 3
        ) {
          $('maintenance-feedback').textContent =
            'The package service is busy. Retrying this status read (' +
            (busyRetries + 1) +
            ' of 3).';
          m.timer = setTimeout(() => readMaintenanceStatus(operationID, busyRetries + 1), 3000);
          return;
        }
        $('maintenance-feedback').textContent =
          'Maintenance status could not be verified: ' +
          error.message +
          ' Retain operation ' +
          operationID +
          ' and use the trusted local status command if the API is unavailable.';
      }
    } finally {
      if (m === maintenance) {
        m.reading = false;
        maintenanceControls();
      }
    }
  }

  async function startMaintenance() {
    const m = maintenance,
      review = m.review;
    if (m.busy || !review || maintenanceFinished(m)) return;
    if (!m.attempted && cfg.revision !== review.revision) {
      invalidateMaintenanceReview('Configuration changed. Review a fresh software plan.');
      return;
    }
    clearTimeout(m.timer);
    m.statusID = '';
    m.busy = true;
    m.attempted = true;
    m.rejected = false;
    maintenanceControls();
    $('maintenance-feedback').textContent = '';
    try {
      const result = await maintenanceAPI('operations', {
        method: 'POST',
        data: review.request,
        cas: true,
        revision: review.revision,
        key: review.key,
      });
      if (m !== maintenance || !token) return;
      const operationID = maintenanceReference(
        result.result?.maintenance_operation_id || result.id,
      );
      m.operationID = operationID;
      showMaintenanceOperation(result, operationID);
      if (maintenanceActive.includes(result.state))
        m.timer = setTimeout(() => readMaintenanceStatus(operationID), 3000);
    } catch (error) {
      if (m !== maintenance) return;
      const match = /^\/api\/v1\/maintenance\/operations\/([0-9a-f]{32})$/.exec(
        error.location || '',
      );
      if (match) m.operationID = maintenanceReference(match[1]);
      m.rejected = [400, 403, 409, 428].includes(error.status);
      $('maintenance-feedback').textContent =
        error.message +
        (m.rejected
          ? ' The request was rejected. Review again if settings changed.'
          : ' Completion is unverified. Read status by operation ID when available, or retry this same request with its original key.');
    } finally {
      if (m === maintenance) {
        m.busy = false;
        maintenanceControls();
      }
    }
  }

  function resumeMaintenance() {
    const match = /^#overview\/maintenance\/([0-9a-f]{32})$/.exec(location.hash);
    if (!match || !token) return;
    $('maintenance-settings').parentElement.open = true;
    $('maintenance-settings').open = true;
    readMaintenanceStatus(match[1]);
  }

  function renderRoutingTransaction(value) {
    const tr = value?.transaction || value || {};
    const descriptions = {
      prepared: 'Routing is prepared. Apply it when you are ready to test connectivity.',
      applying: 'Routing is being applied. Keep your management connection available.',
      applied:
        'Routing is applied temporarily. Test internet access and local management before confirming.',
      confirmed: 'Routing is confirmed and retained.',
      'rolling-back': 'The gateway is restoring the previous routing plan.',
      'rolled-back': 'The gateway restored the previous routing plan. Check connectivity.',
    };
    let detail = descriptions[tr.state] || 'Read routing status before continuing.';
    if (tr.state === 'applied' && tr.deadline) {
      detail += ' Automatic rollback at ' + new Date(tr.deadline).toLocaleTimeString() + '.';
    }
    if (tr.flow_termination === 'failed') {
      detail +=
        ' Clearing old connection tracking failed. The new routing plan remains active; retry confirmation to retry cleanup.';
    } else if (tr.flow_termination === 'pending') {
      detail += ' Clearing old connection tracking is still pending.';
    }
    $('transaction-detail').textContent = detail;
    $('apply-network').disabled = tr.state !== 'prepared';
    $('confirm-network').disabled =
      tr.state !== 'applied' && !(tr.state === 'confirmed' && tr.flow_termination === 'failed');
    $('rollback-network').disabled = !['prepared', 'applying', 'applied', 'rolling-back'].includes(
      tr.state,
    );
  }

  async function refresh(forms = false) {
    if (!token || refreshing) return;
    refreshing = true;
    try {
      const previous = cfg?.revision;
      const [c, s, routing] = await Promise.all([
        api('config'),
        api('status'),
        api('routing/status').catch(() => ({ state: 'unavailable' })),
      ]);
      cfg = c;
      state = s;
      routingState = routing;
      if (
        maintenance.review &&
        !maintenance.attempted &&
        maintenance.review.revision !== cfg.revision
      )
        invalidateMaintenanceReview('Configuration changed. Review a fresh software plan.');
      renderOverview();
      renderContinuity();
      renderSelectiveRouting();
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
    gatewayCoverage = null,
    gatewaySetup = null,
    gatewayFingerprint = '';
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
      g.gateway_backhaul_managed &&
      gatewaySetup?.managed &&
      g.verified_peer_fingerprint === coverage?.node.fingerprint &&
      peer.verified_peer_fingerprint === gatewayFingerprint &&
      g.verified_mode === peer.verified_mode
    ) {
      const modes = new Set(
        (gatewaySetup.aps || [])
          .filter((ap) => ap.radio === g.verified_radio)
          .flatMap((ap) => ap.candidate_modes || []),
      );
      if (g.wds && peer.wds && g.verified_mode === 'wds' && modes.has('wds')) m.push('wds');
      if (g.mesh && peer.mesh && g.verified_mode === 'mesh' && modes.has('mesh')) m.push('mesh');
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
    return ['preparing', 'prepared', 'applying', 'applied', 'confirming', 'rolling-back'].includes(
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
    $('coverage-rollback').disabled = busy || !active || tr?.state === 'confirming';
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
        preparing: 'Preparing both routers',
        prepared: 'Access point prepared',
        applying: 'Applying the connection',
        applied: 'Test the connection now',
        confirmed: 'Connection confirmed',
        confirming: 'Confirming both routers',
        'rolling-back': 'Restoring the previous settings',
        'rolled-back': 'Previous settings restored',
        failed: 'The access point did not apply the plan',
      };
      $('coverage-transaction-title').textContent =
        titles[tr.state] || 'Read the access point status';
      $('coverage-transaction-detail').textContent =
        tr.state === 'confirming'
          ? 'Confirmation is still being reconciled between the routers. Keep the management path available and refresh status; this is not yet a confirmed connection.'
          : tr.state === 'prepared' && tr.gateway_plan
            ? 'Both routers saved their own recovery snapshots. Applying starts independent rollback timers.'
            : tr.state === 'prepared'
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
    $('coverage-gateway-wifi').hidden = !wifi;
    $('coverage-custom-wifi').hidden = wifi;
    $('coverage-main-ap').required = wifi;
    $('coverage-adopt-main-ap').required = wifi;
    $('coverage-radio').required = !$('coverage-radio-fields').hidden;
    for (const field of ['coverage-ssid', 'coverage-password', 'coverage-channel'])
      $(field).required = !wifi && !$('coverage-radio-fields').hidden;
    $('coverage-compatibility').textContent = wifi
      ? 'The cable uplink will be removed from the bridge before encrypted Wi-Fi backhaul starts. This radio shares airtime with client devices.'
      : coverage.modes.some((m) => m !== 'ethernet')
        ? 'Ethernet keeps one cable uplink and disables any OpenRHP wireless backhaul.'
        : 'Wi-Fi setup is unavailable: both routers must prove encrypted bridge compatibility and the main router must support managed setup. Ethernet remains available when detected.';
  }

  function selectedGatewayAP() {
    return (gatewaySetup?.aps || []).find((ap) => ap.section === $('coverage-main-ap').value);
  }

  function fillGatewayAP() {
    const ap = selectedGatewayAP();
    const previousMode = $('coverage-protocol').value;
    $('coverage-protocol').replaceChildren();
    for (const mode of coverage.modes.filter((m) => ap?.candidate_modes?.includes(m))) {
      $('coverage-protocol').append(
        new Option(mode === 'wds' ? 'WDS / four-address bridge' : '802.11s encrypted mesh', mode),
      );
    }
    if (ap?.candidate_modes?.includes(previousMode)) $('coverage-protocol').value = previousMode;
    $('coverage-main-ap-detail').textContent = ap
      ? ap.ssid + ' · ' + ap.radio + ' · channel ' + ap.channel + '. ' + (ap.reason || '')
      : 'No eligible home Wi-Fi network was detected on the main router.';
    syncCoverageButtons();
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
    const radio = (setup.radios || []).find(
      (r) =>
        !r.foreign_active &&
        (!coverage.modes.some((m) => m !== 'ethernet') || r.name === peer.verified_radio),
    );
    if (radio) {
      $('coverage-radio').value = radio.name;
      $('coverage-channel').value = radio.channel || '';
    } else {
      $('coverage-set-wifi').disabled = true;
      $('coverage-set-wifi').checked = false;
    }
    $('coverage-main-ap').replaceChildren();
    for (const ap of gatewaySetup?.aps || []) {
      if (
        ap.radio === gatewayCoverage?.verified_radio &&
        ap.candidate_modes?.some((mode) => coverage.modes.includes(mode))
      )
        $('coverage-main-ap').append(new Option(ap.ssid + ' — ' + ap.radio, ap.section));
    }
    fillGatewayAP();
    const wifi = coverage.modes.some((m) => m !== 'ethernet');
    $('coverage-connection').querySelector('[value="wifi"]').disabled = !wifi;
    $('coverage-connection').querySelector('[value="ethernet"]').disabled =
      !coverage.modes.includes('ethernet');
    $('coverage-connection').value = wifi ? 'wifi' : 'ethernet';
    $('coverage-capability-evidence').textContent = [
      gatewayCoverage?.reason,
      gatewaySetup?.reason,
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
    if (status.gateway_setup) gatewaySetup = status.gateway_setup;
    if (status.gateway_capabilities) gatewayCoverage = status.gateway_capabilities;
    if (status.gateway_fingerprint) gatewayFingerprint = status.gateway_fingerprint;
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
      if (wifi) {
        if (p.radio !== coverage.peer?.verified_radio)
          throw Error('Select the access point radio verified for this router pair.');
        const ap = selectedGatewayAP();
        if (!ap || !ap.candidate_modes?.includes(p.mode) || !$('coverage-adopt-main-ap').checked)
          throw Error(
            'Choose an eligible home Wi-Fi network and approve its use for this paired access point.',
          );
        p.gateway_plan = {
          mode: p.mode,
          ap_section: ap.section,
          network: ap.network,
          peer_fingerprint: coverage.node.fingerprint,
          adopt_existing_ap: true,
          preserve_management_path: p.preserve_management_path,
        };
      } else {
        p.ssid = $('coverage-ssid').value;
        p.passphrase = $('coverage-password').value;
        p.channel = Number($('coverage-channel').value);
      }
    }
    return p;
  }

  async function renderNodes() {
    const nodes = await api('nodes');
    try {
      const report = await api('nodes/discover', { method: 'POST', data: {} });
      gatewayCoverage = report.gateway_capabilities || null;
      gatewaySetup = report.gateway_setup || null;
      gatewayFingerprint = report.gateway_fingerprint || '';
    } catch {
      gatewayCoverage = null;
      gatewaySetup = null;
      gatewayFingerprint = '';
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
      resumeMaintenance();
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
        break_existing: $('break-existing').checked,
      };
      policy.pinned = policy.mode === 'manual' ? $('pinned-source').value : '';
      return api('policy', { method: 'PUT', cas: true, data: policy });
    }, S.saved);
  });
  $('check-all').addEventListener('click', () =>
    action(() => api('probes', { method: 'POST', data: { speed: true } }), S.queued),
  );
  $('routing-add-rule').addEventListener('click', () => addRoutingRule());
  $('selective-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(() => {
      const exceptions = [...$('routing-rules').children].map((row) => {
        const destination = row.querySelector('[data-rule-destination]').value.trim().toLowerCase();
        const rule = { action: row.querySelector('[data-rule-action]').value };
        if (
          destination.includes('/') ||
          destination.includes(':') ||
          /^\d+(\.\d+){3}$/.test(destination)
        )
          rule.cidr = destination;
        else {
          rule.domain = destination;
          rule.include_subdomains = row.querySelector('[data-rule-subdomains]').checked;
        }
        return rule;
      });
      return api('routing', {
        method: 'PUT',
        cas: true,
        data: {
          mode: $('routing-mode').value,
          failure_policy: 'direct',
          registry: { enabled: $('routing-registry').checked, provider: 'antifilter' },
          detection: {
            enabled: $('routing-detection').checked,
            control_target_ids: $('routing-controls')
              .value.split(',')
              .map((v) => v.trim())
              .filter(Boolean),
          },
          exceptions,
        },
      });
    }, 'Routing settings saved. Prepare and confirm routing to activate the saved plan.');
  });
  $('routing-refresh').addEventListener('click', () =>
    action(() => routingOperation('routing/refresh', {})),
  );
  $('routing-check-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(() =>
      routingOperation('routing/check', {
        domain: $('routing-check-domain').value.trim().toLowerCase(),
      }),
    );
  });
  $('continuity-enabled').addEventListener('change', continuityRequired);
  $('continuity-form').addEventListener('submit', (e) => {
    e.preventDefault();
    action(
      () =>
        api('continuity', {
          method: 'PUT',
          cas: true,
          data: {
            enabled: $('continuity-enabled').checked,
            relay_address: $('continuity-relay').value.trim(),
            relay_fingerprint: $('continuity-pin').value.trim().toLowerCase(),
            buffer_bytes: Number($('continuity-buffer').value) * 1048576,
            udp_reserve_bytes: Number($('continuity-udp-reserve').value) * 1048576,
            disconnected_grace_seconds: Number($('continuity-grace').value),
          },
        }),
      'Continuity settings saved. Prepare and confirm routing to activate the saved plan.',
    );
  });
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
            dns: cfg.routing?.mode === 'selective' ? cfg.network.dns : $('dns-mode').value,
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
      renderRoutingTransaction(op.result);
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
        renderRoutingTransaction(op.result);
      }, message),
    );
  resetMaintenance();
  $('maintenance-settings').addEventListener('toggle', () => {
    if ($('maintenance-settings').open && token)
      loadMaintenance().catch((error) => {
        $('maintenance-feedback').textContent = error.message;
      });
  });
  $('maintenance-reload').addEventListener('click', () =>
    loadMaintenance().catch((error) => {
      $('maintenance-feedback').textContent = error.message;
    }),
  );
  $('maintenance-form').addEventListener('change', (event) => {
    if (['maintenance-action', 'maintenance-removal-policy'].includes(event.target.id))
      $('maintenance-direct-consent').checked = false;
    invalidateMaintenanceReview();
  });
  $('maintenance-form').addEventListener('submit', (event) => {
    event.preventDefault();
    reviewMaintenance();
  });
  $('maintenance-start').addEventListener('click', startMaintenance);
  $('maintenance-retry').addEventListener('click', startMaintenance);
  $('maintenance-edit').addEventListener('click', () => invalidateMaintenanceReview());
  $('maintenance-status').addEventListener('click', () => readMaintenanceStatus());
  $('backup-settings').addEventListener('toggle', () => {
    if ($('backup-settings').open && token) loadBackups().catch((e) => notice(e.message, true));
  });
  $('refresh-backups').addEventListener('click', () =>
    loadBackups().catch((e) => notice(e.message, true)),
  );
  $('create-backup').addEventListener('click', () =>
    backupAction(
      () => api('config/backups', { method: 'POST', data: {}, cas: true }),
      'Backup saved privately on this device.',
    ),
  );
  $('restore-backup').addEventListener('click', () => {
    if (!backupPreview) return;
    const preview = backupPreview,
      access = token;
    backupAction(async () => {
      await api('config/backups/' + encodeURIComponent(preview.id) + '/restore', {
        method: 'POST',
        data: {},
        cas: true,
        revision: preview.revision,
      });
      if (access !== token) return;
      $('backup-dialog').close();
      backupPreview = null;
    }, 'Saved settings restored. Prepare, apply, test and confirm a fresh routing plan.');
  });
  $('backup-dialog').addEventListener('close', () => {
    backupPreview = null;
    $('backup-config').textContent = '';
    $('backup-source-preview').replaceChildren();
  });
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
  $('coverage-main-ap').addEventListener('change', () => {
    $('coverage-adopt-main-ap').checked = false;
    fillGatewayAP();
  });
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
          p.gateway_plan
            ? selectedGatewayAP()?.ssid + ' (use the main router settings privately)'
            : p.radio
              ? p.ssid + ' (password hidden)'
              : 'Keep existing Wi-Fi settings',
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
      const { gateway_plan, ...plan } = c.draft.plan;
      const result = nodeResult(
        await api('nodes/' + encodeURIComponent(c.node.id) + '/prepare', {
          method: 'POST',
          key: c.draft.key,
          data: { key: c.draft.key, plan, ...(gateway_plan ? { gateway_plan } : {}) },
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
              ? c.transaction?.state === 'confirmed'
                ? 'The connection is confirmed on every participating router.'
                : 'Confirmation is still in progress. Refresh status before making another change.'
              : 'The access point reported its rollback result.';
      }),
    );
})();
