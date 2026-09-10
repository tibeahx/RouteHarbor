// Response fixtures verify UI/CAS and honest state, not actual packet routing.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');

async function connect(page) {
  const token = fs.readFileSync(process.env.OPENRHP_TEST_TOKEN_FILE, 'utf8').trim();
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#workspace')).toBeVisible();
  await page.locator('#selective-routing-panel > summary').click();
}

function metric(page, name) {
  return page.locator('#selective-metrics dt').filter({ hasText: name }).locator('+ dd');
}

test('selective routing presents stale registry and emergency direct without inventing engine verification', async ({
  page,
}) => {
  await page.route('**/api/v1/routing/status', (route) =>
    route.fulfill({
      json: {
        mode: 'selective',
        state: 'emergency-direct',
        selected: 'private-path',
        default_action: 'direct',
        failure_policy: 'direct',
        published_generation: 12,
        registry: {
          provider: 'antifilter',
          domain_count: 123,
          cidr_count: 8,
          stale: true,
          updated_at: new Date(Date.now() - 25 * 3600000).toISOString(),
          last_error: 'update_failed',
        },
        detection: { enabled: true, learned_count: 2, pending_count: 1 },
      },
    }),
  );
  await connect(page);
  await expect(page.locator('#selective-state')).toHaveText('emergency-direct');
  await expect(page.locator('#break-existing')).toBeDisabled();
  await expect(page.locator('#selective-emergency')).toContainText('refresh');
  await expect(metric(page, 'List source')).toContainText('third-party');
  await expect(metric(page, 'List freshness')).toContainText('Stale');
  await expect(metric(page, 'Detected restriction rules')).toHaveText('2');
  await expect(metric(page, 'Verified engine generation')).toHaveText('—');
  await expect(page.locator('#selective-metrics')).not.toContainText('example.org');
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
    .toBe(true);
});

test('migration and manual exact exceptions save explicit policy with CAS but do not apply network', async ({
  page,
}) => {
  await page.route('**/api/v1/config', async (route) => {
    const response = await route.fetch();
    const config = await response.json();
    delete config.routing;
    await route.fulfill({ json: config });
  });
  await page.route('**/api/v1/routing/status', (route) =>
    route.fulfill({ json: { mode: 'legacy-all', state: 'inactive' } }),
  );
  let submitted, revision, mutationKey;
  await page.route('**/api/v1/routing', async (route) => {
    submitted = route.request().postDataJSON();
    revision = route.request().headers()['if-match'];
    mutationKey = route.request().headers()['idempotency-key'];
    await route.fulfill({
      json: {
        state: 'succeeded',
        revision: 2,
        result: { configuration_saved: true, network_changes_applied: false },
      },
    });
  });
  let networkRequests = 0;
  await page.route('**/api/v1/transactions**', (route) => {
    networkRequests++;
    return route.abort();
  });
  await connect(page);
  await expect(page.locator('#selective-legacy')).toContainText('explicit migration');
  await expect(page.locator('#dns-mode')).toBeEnabled();
  await expect(page.locator('#fallback')).toBeEnabled();
  await expect(page.locator('#dns-selective-help')).toBeHidden();
  await page.getByLabel('Traffic scope').selectOption('selective');
  await page.getByLabel('Use Antifilter registry lists').check();
  await page.getByRole('button', { name: 'Add exception', exact: true }).click();
  await page.getByLabel('Domain, IP or CIDR', { exact: true }).fill('Example.org');
  await page.getByRole('button', { name: 'Save selective routing settings', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('Prepare and confirm routing');
  expect(submitted).toEqual({
    mode: 'selective',
    failure_policy: 'direct',
    registry: { enabled: true, provider: 'antifilter' },
    detection: { enabled: false, control_target_ids: [] },
    exceptions: [{ action: 'bypass', domain: 'example.org', include_subdomains: false }],
  });
  expect(revision).toMatch(/^"[1-9][0-9]*"$/);
  expect(mutationKey.length).toBeGreaterThanOrEqual(8);
  expect(networkRequests).toBe(0);
});

test('destination check shows explicit action and reason while missing classifier stays unavailable', async ({
  page,
}) => {
  await page.route('**/api/v1/routing/status', (route) =>
    route.fulfill({
      status: 503,
      json: { error: { message: 'Selective routing observations are unavailable' } },
    }),
  );
  let requested;
  await page.route('**/api/v1/routing/check', (route) => {
    requested = route.request().postDataJSON();
    return route.fulfill({ status: 202, json: { id: 'test-check', state: 'running' } });
  });
  await page.route('**/api/v1/operations/test-check', (route) =>
    route.fulfill({
      json: {
        id: 'test-check',
        state: 'succeeded',
        result: {
          routing: { action: 'bypass', reason: 'Detected restriction', route: 'private-path' },
        },
      },
    }),
  );
  await connect(page);
  await expect(page.locator('#selective-state')).toHaveText('unavailable');
  await expect(page.locator('#selective-detail')).toContainText(
    'No classifier readiness measurement',
  );
  await page.getByLabel('Destination domain to check').fill('Example.org');
  await page.getByRole('button', { name: 'Check destination', exact: true }).click();
  await expect(page.locator('#routing-check-result')).toContainText('Detected restriction');
  await expect(page.locator('#routing-check-result')).toContainText('private-path');
  expect(requested).toEqual({ domain: 'example.org' });
});

test('selective gateway settings show managed DNS and retain the saved legacy DNS value', async ({
  page,
}) => {
  await page.route('**/api/v1/config', async (route) => {
    const response = await route.fetch();
    const config = await response.json();
    config.network.dns = 'selected-path';
    await route.fulfill({ json: config });
  });
  let submitted;
  await page.route('**/api/v1/network', async (route) => {
    if (route.request().method() !== 'PUT') return route.continue();
    submitted = route.request().postDataJSON();
    await route.fulfill({ json: { state: 'succeeded', revision: 2 } });
  });
  await connect(page);
  await page.getByText('Gateway setup and diagnostics', { exact: true }).click();
  await expect(page.locator('#dns-mode')).toBeDisabled();
  await expect(page.locator('#dns-mode')).toHaveValue('selected-path');
  await expect(page.locator('#dns-mode-label')).toHaveText('Legacy DNS policy');
  await expect(page.locator('#dns-selective-help')).toHaveText(
    'Managed FakeIP DNS; legacy DNS policy applies only in legacy mode.',
  );
  await expect(page.locator('#dns-resolver-label')).toContainText('required for managed DNS');
  await expect(page.locator('#fallback')).toBeDisabled();
  await expect(page.locator('#fallback')).toHaveValue('closed');
  await expect(page.locator('#fallback-label')).toHaveText('When no healthy bypass remains');
  await expect(page.locator('#break-existing')).toBeDisabled();
  await expect(page.locator('#break-existing')).not.toBeChecked();
  await page.locator('#dns-mode').evaluate((element) => {
    element.value = 'block';
  });
  await page.getByRole('button', { name: 'Save gateway plan', exact: true }).click();
  await expect.poll(() => submitted?.dns).toBe('selected-path');
});
