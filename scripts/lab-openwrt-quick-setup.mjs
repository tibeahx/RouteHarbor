#!/usr/bin/env node
// Manual full-boot browser acceptance; never included in the ordinary UI fixture suite.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const container = 'openrhp-openwrt-boot-lab';
const port = 8787; // Exact guest Host/Origin policy; no header rewriting or extra allowed hosts.
const origin = `http://127.0.0.1:${port}`;
const tokenFile = '/root/openrhp-lab/admin.token';
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const digest = (value) => createHash('sha256').update(value).digest('hex');

function command(executable, args, input = '', timeout = 90_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = [];
    let bytes = 0;
    // Never print command output on error: some commands intentionally read a credential.
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.stdout.on('data', (value) => {
      bytes += value.length;
      if (bytes > 2 * 1024 * 1024) child.kill('SIGKILL');
      else chunks.push(value);
    });
    child.stderr.resume();
    child.stdin.on('error', () => {});
    child.on('error', () => {
      clearTimeout(timer);
      reject(Error('Lab command could not start'));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 || bytes > 2 * 1024 * 1024)
        reject(Error('Lab command failed or exceeded its bound'));
      else resolve(Buffer.concat(chunks).toString('utf8'));
    });
    child.stdin.end(input);
  });
}

const docker = (args, input = '', timeout) =>
  command('docker', ['exec', '-i', container, ...args], input, timeout);
const guest = (script) => docker(['python3', '/lab/vmctl.py', 'exec'], `set -eu\n${script}\n`);
const apiRead = async (resource) => {
  assert.match(resource, /^\/api\/v1\/(config|status|capabilities)$/);
  return JSON.parse(
    await guest(`/usr/bin/openrhp api --token-file ${tokenFile} --path ${resource}`),
  );
};

async function startRelay(listenPort, connect) {
  const peers = new Map();
  const server = net.createServer({ allowHalfOpen: false }, (socket) => {
    if (peers.size >= 24) return socket.destroy();
    const child = connect();
    const done = new Promise((resolve) => child.once('close', resolve));
    peers.set(socket, { child, done });
    child.stderr.resume();
    socket.pipe(child.stdin);
    child.stdout.pipe(socket);
    const close = () => {
      socket.destroy();
      child.stdin.destroy();
      child.kill('SIGTERM');
    };
    socket.on('error', close);
    socket.on('close', close);
    child.stdin.on('error', close);
    child.stdout.on('error', close);
    child.once('error', close);
    child.once('close', () => {
      peers.delete(socket);
      socket.destroy();
    });
    socket.setTimeout(60_000, close);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    async close() {
      const active = [...peers.values()];
      const stopped = new Promise((resolve) => server.close(resolve));
      for (const [socket, { child }] of peers) {
        socket.destroy();
        child.kill('SIGTERM');
      }
      const drained = Promise.all(active.map(({ done }) => done));
      await Promise.race([drained, delay(2000)]);
      for (const { child } of peers.values()) child.kill('SIGKILL');
      await Promise.all([stopped, drained]);
    },
  };
}

function connectSSH(id) {
  return spawn(
    'docker',
    [
      'exec',
      '-i',
      '-e',
      'OPENRHP_QUICK_SETUP_RELAY=' + id,
      container,
      'ssh',
      '-i',
      '/state/identity',
      '-o',
      'BatchMode=yes',
      '-o',
      'IdentitiesOnly=yes',
      '-o',
      'StrictHostKeyChecking=yes',
      '-o',
      'UserKnownHostsFile=/state/known_hosts',
      '-o',
      'ConnectTimeout=3',
      '-o',
      'LogLevel=ERROR',
      '-W',
      `127.0.0.1:${port}`,
      'root@10.44.0.1',
    ],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  );
}

async function selfTest() {
  const children = [];
  const relay = await startRelay(0, () => {
    const child = spawn(process.execPath, ['-e', 'process.stdin.pipe(process.stdout)'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    children.push(child);
    return child;
  });
  const socket = net.createConnection({ host: '127.0.0.1', port: relay.port });
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.once('connect', () => socket.write('unchanged Host/Origin bytes'));
    socket.once('data', (value) => {
      assert.equal(value.toString(), 'unchanged Host/Origin bytes');
      resolve();
    });
  });
  await relay.close();
  assert(children.every((child) => child.exitCode !== null || child.signalCode !== null));
  console.log('PASS loopback relay preserves bytes and drains child processes without VM access');
}

async function main() {
  const id = randomUUID().replaceAll('-', '');
  const directory = `/tmp/openrhp-quick-setup-${id}`;
  const guestCA = `/etc/ssl/certs/openrhp-quick-setup-${id}.pem`;
  const output = path.join(root, 'test-results', `openwrt-quick-setup-${id}`);
  const evidence = {
    schema: 1,
    environment: 'isolated full-system OpenWrt VM',
    fixture: 'private synthetic WAN; real TLS and LAN traffic; no API response interception',
    trace_policy:
      'allowlisted actions and response method/path/status; no HAR, raw trace, headers or bodies',
    events: [],
    screenshots: [],
    result: 'incomplete',
  };
  let token = '',
    browser,
    page,
    relay,
    server,
    caInstalled = false,
    fixtureCreated = false;
  let phase = 'preflight';
  const event = (kind, value) =>
    evidence.events.push({ at: new Date().toISOString(), kind, ...value });
  const step = async (name, action) => {
    phase = name;
    event('step', { name, state: 'started' });
    await action();
    event('step', { name, state: 'passed' });
    console.log(`PASS ${name}`);
  };
  const screenshot = async (name) => {
    // Hidden login input is not painted; never capture a visible credential.
    const key = page.getByLabel('Access key', { exact: true });
    if ((await key.isVisible()) && (await key.inputValue()))
      throw Error('Credential screenshot refused');
    const filename = name + '.png';
    const bytes = await page.screenshot({ path: path.join(output, filename), fullPage: true });
    evidence.screenshots.push({ file: filename, sha256: digest(bytes) });
  };
  const readClient = async (selectedDNS = false) =>
    JSON.parse(
      await docker([
        'ip',
        'netns',
        'exec',
        'openrhp-client',
        'python3',
        directory + '/network.py',
        'client',
        directory,
        ...(selectedDNS ? ['selected-path'] : []),
      ]),
    );
  try {
    await fs.mkdir(output, { recursive: true, mode: 0o700 });
    const inspect = JSON.parse(await command('docker', ['inspect', container]))[0];
    assert.equal(inspect.Config.Labels?.['org.openrhp.lab'], 'full-boot');
    assert.equal(inspect.HostConfig.NetworkMode, 'none');
    assert.equal(Object.keys(inspect.HostConfig.PortBindings || {}).length, 0);
    assert.equal((inspect.HostConfig.Devices || []).length, 0);
    await docker(['python3', '/lab/vmctl.py', 'info']);
    const initial = await apiRead('/api/v1/config');
    assert.equal(initial.network.enabled, false, 'Requires a clean installed routing-off baseline');
    assert.equal(initial.policy.mode, 'off');
    assert.equal(initial.sources.length, 0, 'Never overwrite a previous manual configuration');
    assert.equal(initial.targets.length, 0);
    const initialState = await apiRead('/api/v1/status');
    assert.equal(initialState.network_applied, false);
    assert.equal(initialState.network.maintenance_hold, false);
    const capabilities = await apiRead('/api/v1/capabilities');
    assert.equal(capabilities.network_helper, true);
    assert.equal(capabilities.platform.supported, true);
    const interfaces = capabilities.platform.interfaces;
    const lan = interfaces.find((item) => item.name === 'lan')?.device;
    const wan = interfaces.find((item) => item.name === 'wan')?.device;
    assert.equal(lan, 'br-lan');
    assert.equal(wan, 'eth1');
    evidence.build = (await guest('sha256sum /usr/bin/openrhp /usr/libexec/openrhp-helper')).trim();
    evidence.platform = {
      os: capabilities.platform.os,
      version: capabilities.platform.version,
      architecture: capabilities.platform.package_arch,
      lan,
      wan,
    };
    const originalHashes = await guest(
      'sha256sum /etc/config/network /etc/config/firewall /etc/config/dhcp',
    );
    const require = createRequire(path.join(root, 'tests/browser/package.json'));
    const { chromium, expect } = require('@playwright/test');
    browser = await chromium.launch({ headless: true });
    evidence.browser = {
      chromium: browser.version(),
      node: process.version,
      playwright: require('@playwright/test/package.json').version,
    };
    const context = await browser.newContext({ viewport: { width: 1440, height: 1080 } });
    page = await context.newPage();
    page.setDefaultTimeout(45_000);
    const pageErrors = [];
    page.on('pageerror', () => pageErrors.push('uncaught browser error'));
    // Headers and payloads deliberately never enter evidence. This also proves
    // actual server response status without substituting route fixtures.
    page.on('response', (response) => {
      const url = new URL(response.url());
      if (url.origin === origin && url.pathname.startsWith('/api/v1/')) {
        event('response', {
          method: response.request().method(),
          path: url.pathname,
          status: response.status(),
        });
      }
    });
    // Refuse occupied fixture ports; never kill another task's WAN responder.
    const listeners = await docker(['ip', 'netns', 'exec', 'openrhp-wan', 'ss', '-H', '-lntup']);
    assert(!/:(443|53|18081)\s/.test(listeners), 'Synthetic WAN fixture ports are occupied');
    relay = await startRelay(port, () => connectSSH(id)); // Fail on occupied port before any guest write.
    await step('verified isolated guest and pinned SSH loopback relay', async () => {
      const response = await page.goto(origin);
      assert.equal(response.status(), 200);
      await expect(page.getByRole('heading', { name: 'Connect to your gateway' })).toBeVisible();
      await screenshot('01-login');
    });
    await step('temporary private WAN HTTPS fixture and trusted lab CA', async () => {
      await docker(['mkdir', '-m', '0700', directory]);
      fixtureCreated = true;
      await docker(
        [
          'python3',
          '-c',
          'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())',
          directory + '/network.py',
        ],
        await fs.readFile(path.join(root, 'scripts/testdata/quick-setup-network.py')),
      );
      await docker([
        'openssl',
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=OpenRHP isolated browser lab CA',
        '-keyout',
        directory + '/ca.key',
        '-out',
        directory + '/ca.pem',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
      ]);
      await docker([
        'openssl',
        'req',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-subj',
        '/CN=OpenRHP isolated browser lab',
        '-keyout',
        directory + '/server.key',
        '-out',
        directory + '/server.csr',
      ]);
      await docker(
        [
          'python3',
          '-c',
          'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.stdin.read())',
          directory + '/extensions',
        ],
        'subjectAltName=IP:8.8.8.8,IP:2001:4860:4860::8888\nextendedKeyUsage=serverAuth\n',
      );
      await docker([
        'openssl',
        'x509',
        '-req',
        '-in',
        directory + '/server.csr',
        '-CA',
        directory + '/ca.pem',
        '-CAkey',
        directory + '/ca.key',
        '-CAcreateserial',
        '-out',
        directory + '/server.pem',
        '-days',
        '1',
        '-extfile',
        directory + '/extensions',
      ]);
      await guest(`test ! -e ${guestCA}`);
      // Unique new file only. The system bundle and existing roots are untouched.
      caInstalled = true;
      await docker(['python3', '/lab/vmctl.py', 'put', directory + '/ca.pem', guestCA]);
      await guest(`chmod 0644 ${guestCA}\n/etc/init.d/openrhp restart`);
      server = spawn(
        'docker',
        [
          'exec',
          '-i',
          container,
          'ip',
          'netns',
          'exec',
          'openrhp-wan',
          'python3',
          directory + '/network.py',
          'server',
          directory,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      server.stderr.resume();
      await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(Error('Synthetic WAN responder did not become ready')),
          10_000,
        );
        server.once('error', () => {
          clearTimeout(timer);
          reject(Error('WAN fixture failed to start'));
        });
        server.once('close', () => {
          clearTimeout(timer);
          reject(Error('WAN fixture exited before readiness'));
        });
        server.stdout.once('data', (value) => {
          clearTimeout(timer);
          if (value.toString().trim() !== 'READY')
            reject(Error('Unexpected WAN fixture readiness'));
          else resolve();
        });
      });
      await expect
        .poll(
          async () => {
            try {
              return (await apiRead('/api/v1/status')).network_applied === false;
            } catch {
              return false;
            }
          },
          { timeout: 60_000 },
        )
        .toBe(true);
      const baseline = await readClient();
      assert.equal(Object.keys(baseline).length, 10);
      assert(
        Object.values(baseline).every(Boolean),
        'LAN baseline must prove all intended paths work first',
      );
      event('traffic', { phase: 'before-routing', matrix: baseline });
    });
    await step('connect using the real administrator access key', async () => {
      token = (await guest(`cat ${tokenFile}`)).trim();
      assert(token.length >= 32 && token.length <= 256 && !/\s/.test(token));
      await page.getByLabel('Access key', { exact: true }).fill(token);
      await page.getByRole('button', { name: 'Connect', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Your network', exact: true })).toBeVisible();
      await expect(page.locator('#routing-banner')).toContainText('Traffic routing is not applied');
    });
    await step('add a Direct access method through ordinary UI fields', async () => {
      await page.getByRole('link', { name: /Access methods/ }).click();
      await page.getByRole('button', { name: 'Add access method', exact: true }).first().click();
      await page.getByLabel('Name', { exact: true }).first().fill('Private lab WAN');
      await page.getByLabel('Connection type', { exact: true }).selectOption('direct');
      await page.getByRole('button', { name: 'Add method', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Private lab WAN', exact: true }),
      ).toBeVisible();
      await screenshot('02-access-method');
    });
    await step('add a real HTTPS resource and measure the Direct path', async () => {
      await page.getByRole('link', { name: 'Overview', exact: true }).click();
      await page.getByRole('button', { name: 'Add resource', exact: true }).click();
      await page.getByLabel('HTTPS address', { exact: true }).fill('https://8.8.8.8/quick-setup');
      await page.getByLabel('Required for a usable path', { exact: true }).check();
      await page
        .locator('#resource-form')
        .getByRole('button', { name: 'Add resource', exact: true })
        .click();
      await expect(page.locator('#target-list')).toContainText('https://8.8.8.8/quick-setup');
      await page.getByRole('button', { name: 'Check all methods', exact: true }).click();
      await expect(page.locator('#notice')).toContainText('Checks queued');
      await expect
        .poll(
          async () => {
            const status = await apiRead('/api/v1/status');
            const measured = status.health?.[0];
            return Boolean(
              measured?.success_rate === 1 &&
              measured.resources?.length === 1 &&
              measured.state === 'healthy' &&
              measured.resources[0].status_code === 200 &&
              !measured.resources[0].error_code,
            );
          },
          { timeout: 60_000 },
        )
        .toBe(true);
    });
    await step('save Keep one method with explicit closed fallback', async () => {
      await page.getByLabel('Selection mode', { exact: true }).selectOption('manual');
      await page
        .getByLabel('Access method', { exact: true })
        .selectOption({ label: 'Private lab WAN' });
      await page.getByRole('button', { name: 'Save selection', exact: true }).click();
      await expect(page.locator('#mode-label')).toHaveText('Fixed path');
      await expect(page.locator('#active-name')).toHaveText('Private lab WAN');
      const saved = await apiRead('/api/v1/config');
      assert.equal(saved.policy.fallback, 'closed');
      assert.equal(saved.policy.break_existing, false);
      await screenshot('03-measured-selection');
    });
    await step('save detected gateway devices, local prefixes and protected DNS', async () => {
      await page.getByText('Gateway setup and diagnostics', { exact: true }).click();
      await expect(page.locator('#platform-message')).toContainText('OpenWrt');
      await expect(page.locator('#discovered-interfaces')).toContainText(lan);
      await expect(page.locator('#discovered-interfaces')).toContainText(wan);
      await page.getByLabel('LAN devices', { exact: true }).fill(lan);
      await page.getByLabel('WAN device', { exact: true }).fill(wan);
      await page
        .getByLabel('Local subnets (comma separated)', { exact: true })
        .fill('10.44.0.0/24, fd44:1::/64');
      await page.getByLabel('DNS policy', { exact: true }).selectOption('selected-path');
      await page
        .getByLabel('DNS resolver IP (required for selected path)', { exact: true })
        .fill('8.8.8.8');
      await page.getByLabel('Enable this gateway plan', { exact: true }).check();
      await page.getByRole('button', { name: 'Save gateway plan', exact: true }).click();
      await expect(page.locator('#notice')).toContainText('Gateway plan saved');
      assert.equal((await apiRead('/api/v1/config')).network.ipv6, 'block');
    });
    await step('prepare and apply with the independent rollback timer', async () => {
      await page.getByRole('button', { name: 'Prepare routing', exact: true }).click();
      await expect(page.locator('#transaction-detail')).toContainText('Routing is prepared');
      await screenshot('04-prepared-routing');
      await page.getByRole('button', { name: 'Apply with rollback timer', exact: true }).click();
      await expect(page.locator('#transaction-detail')).toContainText('Automatic rollback at');
    });
    await step('verify actual LAN connectivity and policy before confirmation', async () => {
      const result = await readClient(true);
      assert.deepEqual(result, {
        '4-https': true,
        '4-udp': true,
        '4-port53-udp': true,
        '4-port53-tcp': true,
        '4-management': true,
        '6-https': false,
        '6-udp': false,
        '6-port53-udp': false,
        '6-port53-tcp': false,
        '6-management': true,
      });
      event('traffic', { phase: 'applied-before-confirmation', matrix: result });
      await screenshot('05-applied-timer');
    });
    await step(
      'confirm tested routing and sign out without persistent browser credentials',
      async () => {
        await page
          .getByRole('button', { name: 'Confirm tested connectivity', exact: true })
          .click();
        await expect(page.locator('#transaction-detail')).toHaveText(
          'Routing is confirmed and retained.',
        );
        await expect(page.locator('#routing-banner')).toContainText('Gateway routing is applied');
        await expect(page.locator('#confirm-network')).toBeDisabled();
        const status = await apiRead('/api/v1/status');
        assert.equal(status.network.confirmed_for_current_config, true);
        assert.equal(status.network_applied, true);
        assert.equal(
          await guest('sha256sum /etc/config/network /etc/config/firewall /etc/config/dhcp'),
          originalHashes,
        );
        assert.deepEqual(pageErrors, []);
        assert.deepEqual(
          evidence.events.filter((item) => item.kind === 'response' && item.status >= 400),
          [],
          'Unexpected API error response during the manual flow',
        );
        await screenshot('06-confirmed-routing');
        await page.setViewportSize({ width: 390, height: 844 });
        assert(
          await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        );
        await screenshot('07-confirmed-mobile');
        assert.equal(
          await page.evaluate(
            () => Object.keys(localStorage).length + Object.keys(sessionStorage).length,
          ),
          0,
        );
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await expect(page.getByLabel('Access key', { exact: true })).toHaveValue('');
        await screenshot('08-signed-out');
      },
    );
    evidence.result = 'passed';
  } catch (error) {
    evidence.result = 'failed';
    // Locator errors may include a filled value. Exact credential removal comes
    // before truncation; command stderr and browser console are never recorded.
    const message = token
      ? String(error.message).replaceAll(token, '[REDACTED]')
      : String(error.message);
    evidence.failure = { phase, message: message.slice(0, 1500) };
    console.error(`FAIL ${phase}: ${message.slice(0, 1500)}`);
    process.exitCode = 1;
  } finally {
    const cleanup = [];
    const clean = async (name, fn) => {
      try {
        await fn();
        cleanup.push({ name, passed: true });
      } catch {
        cleanup.push({ name, passed: false });
        process.exitCode = 1;
      }
    };
    if (browser) await clean('close browser context', () => browser.close());
    if (relay)
      await clean('drain SSH relay children and close loopback listener', () => relay.close());
    if (relay)
      await clean('verify tagged container SSH relay processes have exited', async () => {
        await docker([
          'python3',
          '-c',
          String.raw`
import os,pathlib,signal,sys,time
marker=('OPENRHP_QUICK_SETUP_RELAY='+sys.argv[1]).encode()
def matches():
    result=[]
    for p in pathlib.Path('/proc').iterdir():
        if not p.name.isdecimal() or p.name==str(os.getpid()): continue
        try:
            env=(p/'environ').read_bytes().split(b'\0')
            args=(p/'cmdline').read_bytes().split(b'\0')
            if marker in env and args[0] in (b'ssh',b'/usr/bin/ssh') and b'-W' in args and b'127.0.0.1:8787' in args:
                result.append(int(p.name))
        except (FileNotFoundError,ProcessLookupError,PermissionError): pass
    return result
for sig in (signal.SIGTERM,signal.SIGKILL):
    for pid in matches():
        try: os.kill(pid,sig)
        except ProcessLookupError: pass
    deadline=time.monotonic()+2
    while matches() and time.monotonic()<deadline: time.sleep(.05)
assert not matches(),'Tagged SSH relay did not exit'
`,
          id,
        ]);
      });
    if (caInstalled)
      await clean(
        'remove only new lab CA and restart controller to discard cached trust',
        async () => {
          await guest(
            `/etc/init.d/openrhp stop\nrm -f ${guestCA}\n/etc/init.d/openrhp start\ntest ! -e ${guestCA}`,
          );
        },
      );
    if (server)
      await clean('stop only this synthetic WAN responder', async () => {
        await docker([
          'python3',
          '-c',
          String.raw`
import os,pathlib,signal,sys,time
filename=sys.argv[1].encode()
def matches():
    result=[]
    for p in pathlib.Path('/proc').iterdir():
        if not p.name.isdecimal() or p.name==str(os.getpid()): continue
        try:
            args=(p/'cmdline').read_bytes().split(b'\0')
            if args[:3]==[b'python3',filename,b'server']: result.append(int(p.name))
        except (FileNotFoundError,ProcessLookupError,PermissionError): pass
    return result
for sig in (signal.SIGTERM,signal.SIGKILL):
    for pid in matches():
        try: os.kill(pid,sig)
        except ProcessLookupError: pass
    deadline=time.monotonic()+2
    while matches() and time.monotonic()<deadline: time.sleep(.05)
assert not matches(),'Synthetic WAN responder did not exit'
`,
          directory + '/network.py',
        ]);
        server.kill('SIGTERM');
      });
    if (fixtureCreated)
      await clean('delete only the unique synthetic certificate directory', () =>
        docker(['rm', '-rf', directory]),
      );
    evidence.cleanup = cleanup;
    evidence.finished_at = new Date().toISOString();
    if (cleanup.some((item) => !item.passed)) evidence.result = 'failed';
    const serialized = JSON.stringify(evidence, null, 2) + '\n';
    assert(!token || !serialized.includes(token), 'Refusing evidence containing an access key');
    token = '';
    await fs.writeFile(path.join(output, 'evidence.json'), serialized, { mode: 0o600 });
    console.log(`Evidence: ${output}`);
  }
}

if (process.argv.length === 3 && process.argv[2] === '--self-test') await selfTest();
else if (process.argv.length === 3 && process.argv[2] === '--run') await main();
else {
  console.error(
    'Manual use after exclusive clean-VM handoff: node scripts/lab-openwrt-quick-setup.mjs --run',
  );
  console.error(
    'Read-only local relay check: node scripts/lab-openwrt-quick-setup.mjs --self-test',
  );
  process.exitCode = 2;
}
