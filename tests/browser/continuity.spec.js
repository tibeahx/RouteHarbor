// Browser fixtures verify the public continuity controls and honest telemetry.
// They do not exercise a worker, relay, physical path, or cutover latency.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');

// Saving settings starts a status refresh. Drain its response transformer before
// Playwright disposes the page's request context, including after a failed test.
test.afterEach(async ({ page }) => {
  await page.unrouteAll({ behavior: 'wait' });
});

const profile = {
  enabled: true,
  relay_address: '8.8.8.8:8443',
  relay_fingerprint: 'ab'.repeat(32),
  buffer_bytes: 33554432,
  udp_reserve_bytes: 4194304,
  disconnected_grace_seconds: 30,
};

async function connect(page) {
  const token = fs.readFileSync(process.env.ROUTEHARBOR_TEST_TOKEN_FILE, 'utf8').trim();
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#workspace')).toBeVisible();
  await page.locator('#continuity-panel > summary').click();
}

function metric(page, title) {
  return page.locator('#continuity-metrics dt').filter({ hasText: title }).locator('+ dd');
}

test('continuity shows measured degradation and queues without inventing a timing guarantee', async ({
  page,
}) => {
  await page.route('**/api/v1/config', async (route) => {
    const response = await route.fetch();
    const config = await response.json();
    config.continuity = profile;
    await route.fulfill({ json: config });
  });
  await page.route('**/api/v1/status', async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    status.continuity = {
      status: 'Degraded',
      qualified: false,
      degraded_reason: 'standby_unavailable',
      worker_fingerprint: 'cd'.repeat(32),
      active_path: 'first',
      standby_path: '',
      paths: [
        { name: 'first', ready: true },
        { name: 'second', ready: false },
      ],
      queue_bytes: 1048576,
      udp_queue_bytes: 524288,
      control_queue_bytes: 256,
      replayed_frames: 9,
      expired_udp: 4,
      dropped_udp: 2,
      switches: 0,
      last_switch_pause_ms: 0,
    };
    await route.fulfill({ json: status });
  });
  await connect(page);
  await expect(page.locator('#continuity-state')).toHaveText('Degraded');
  await expect(page.locator('#continuity-detail')).toContainText('second: not ready');
  await expect(page.locator('#continuity-detail')).toContainText('standby_unavailable');
  await expect(page.locator('#continuity-qualification')).toContainText('has not been qualified');
  await expect(page.locator('#continuity-fingerprint')).toHaveText('cd'.repeat(32));
  await expect(metric(page, 'Buffered traffic')).toHaveText('1.00 MiB');
  await expect(metric(page, 'Control queued')).toHaveText('256 B');
  await expect(metric(page, 'Replayed frames')).toHaveText('9');
  await expect(metric(page, 'Expired UDP')).toHaveText('4');
  await expect(metric(page, 'Last path change to acknowledgement')).toHaveText('—');
  await expect(metric(page, 'TCP flows')).toHaveText('—');
  await page
    .locator('#continuity-panel')
    .screenshot({ path: 'test-results/browser/continuity-desktop.png' });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
    .toBe(true);
  await page
    .locator('#continuity-panel')
    .screenshot({ path: 'test-results/browser/continuity-mobile.png' });
});

test('continuity form sends explicit public settings with CAS and leaves absent metrics unknown', async ({
  page,
}) => {
  let submitted;
  let revision;
  let mutationKey;
  await page.route('**/api/v1/status', async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    delete status.continuity;
    await route.fulfill({ json: status });
  });
  await page.route('**/api/v1/continuity', async (route) => {
    submitted = route.request().postDataJSON();
    revision = route.request().headers()['if-match'];
    mutationKey = route.request().headers()['idempotency-key'];
    await route.fulfill({ json: { state: 'succeeded', revision: 2 } });
  });
  await connect(page);
  await expect(page.locator('#continuity-state')).toHaveText('Disabled');
  await expect(metric(page, 'Buffered traffic')).toHaveText('—');
  await expect(page.locator('#continuity-buffer')).toHaveValue('32');
  await page.getByLabel('Enable session continuity').check();
  await page.getByLabel('Your relay IP and port').fill(profile.relay_address);
  await page
    .getByLabel('Relay certificate fingerprint (SHA256)', { exact: true })
    .fill(profile.relay_fingerprint.toUpperCase());
  await page.getByRole('button', { name: 'Save continuity settings', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('Prepare and confirm routing');
  expect(submitted).toEqual(profile);
  expect(revision).toMatch(/^"[1-9][0-9]*"$/);
  expect(mutationKey.length).toBeGreaterThanOrEqual(8);
});
