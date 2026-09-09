// Package-service response fixtures exercise the UI contract only. No packages
// are installed, upgraded or removed by these browser tests. Router lifecycle
// acceptance is recorded separately in the OpenWrt VM evidence.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const token = fs.readFileSync(process.env.OPENRHP_TEST_TOKEN_FILE, 'utf8').trim();
const headers = { Authorization: 'Bearer ' + token };
const bundleID = 'a'.repeat(32);
const operationID = 'b'.repeat(32);
const installedDigest = 'c'.repeat(64);
const packageFixture = {
  name: 'openrhp-xray',
  version: '26.3.27-1',
  architecture: 'aarch64_generic',
  sha256: 'd'.repeat(64),
  bytes: 100,
};

function job(state, action = 'install') {
  return {
    id: operationID,
    state,
    phase: state === 'completed' ? 'verified' : 'package_manager',
    action,
    components: action === 'remove' ? ['openrhp'] : ['openrhp-xray'],
    guard_retained: true,
    retryable: false,
    ...(state === 'failed' ? { error_code: 'package_verification_failed' } : {}),
  };
}

async function fixture(page, callbacks = {}) {
  await page.route('**/api/v1/maintenance/**', async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path.endsWith('/capabilities'))
      return route.fulfill({
        json: {
          available: true,
          architecture: 'aarch64_generic',
          installed_digest: installedDigest,
          trusted_key_available: true,
          guard_replacement: false,
          node_update: false,
          active: false,
          ...callbacks.capabilities,
        },
      });
    if (path.endsWith('/bundles'))
      return route.fulfill({
        json: [
          {
            id: bundleID,
            version: 'test-reviewed',
            architecture: 'aarch64_generic',
            packages: [packageFixture],
          },
        ],
      });
    if (path.endsWith('/plan')) {
      const input = request.postDataJSON();
      callbacks.plan?.(input);
      return route.fulfill({
        json: {
          request: { ...input, expected_installed_digest: installedDigest },
          installed_digest: installedDigest,
          digest: 'e'.repeat(64),
          packages: [packageFixture],
          warnings: [
            input.removal_policy === 'restore-direct'
              ? 'Direct internet access will be restored. The safety package remains installed.'
              : 'Local administrator access must remain available.',
          ],
        },
      });
    }
    if (path.endsWith('/operations') && request.method() === 'POST') return callbacks.start(route);
    if (path.endsWith('/operations/' + operationID)) return callbacks.status(route);
    throw Error('Unexpected maintenance endpoint: ' + path);
  });
}

async function login(page) {
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your network', exact: true })).toBeVisible();
}

async function openMaintenance(page) {
  await page.goto('/');
  await login(page);
  await page.getByText('Gateway setup and diagnostics', { exact: true }).click();
  await page.getByText('Software maintenance', { exact: true }).click();
  await expect(page.locator('#maintenance-bundle option')).toHaveCount(2);
  await expect(page.locator('#maintenance-review')).toBeEnabled();
}

test('maintenance UI retries the frozen request and resumes authoritative status after reload', async ({
  page,
  request,
}) => {
  const sent = [],
    errors = [];
  let reads = 0;
  page.on('pageerror', (error) => errors.push(error.message));
  await fixture(page, {
    start: async (route) => {
      sent.push({
        body: route.request().postData(),
        key: route.request().headers()['idempotency-key'],
        revision: route.request().headers()['if-match'],
      });
      if (sent.length === 1)
        return route.fulfill({
          status: 503,
          headers: { Location: '/api/v1/maintenance/operations/' + operationID },
          json: { error: { message: 'Dispatch acknowledgement was lost.' } },
        });
      if (sent.length > 2)
        return route.fulfill({
          status: 503,
          json: { error: { message: 'Response unavailable.' } },
        });
      return route.fulfill({ status: 202, json: job('running') });
    },
    status: async (route) => {
      reads++;
      return route.fulfill({ json: job('completed') });
    },
  });
  await openMaintenance(page);
  await page.getByLabel('Xray adapter', { exact: true }).check();
  await page.getByLabel('Staged signed bundle', { exact: true }).selectOption(bundleID);
  await page.getByRole('button', { name: 'Review software plan', exact: true }).click();
  await expect(page.locator('#maintenance-plan')).toBeVisible();
  await page.getByRole('button', { name: 'Start reviewed maintenance', exact: true }).click();
  await expect(page.locator('#maintenance-feedback')).toContainText('Completion is unverified');
  await expect(page.locator('#maintenance-operation-id')).toHaveValue(operationID);
  await expect(page.locator('#maintenance-local-command')).toContainText(
    'maintenance-status --operation ' + operationID,
  );
  await expect(page.locator('#maintenance-edit')).toBeDisabled();
  await expect(page.locator('#maintenance-progress')).toBeHidden();

  // An unrelated real API edit is observed by the page's normal background
  // refresh. The uncertain maintenance retry must still use its old revision.
  const configuration = await (await request.get('/api/v1/config', { headers })).json();
  configuration.policy.confirmations = configuration.policy.confirmations === 3 ? 4 : 3;
  const changed = await request.put('/api/v1/policy', {
    headers: {
      ...headers,
      'If-Match': '"' + configuration.revision + '"',
      'Idempotency-Key': randomUUID(),
    },
    data: configuration.policy,
  });
  expect(changed.ok()).toBeTruthy();
  await expect(page.locator('#confirmations')).toHaveValue(
    String(configuration.policy.confirmations),
    { timeout: 12000 },
  );
  await page.getByRole('button', { name: 'Retry the same request', exact: true }).click();
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Maintenance is running',
  );
  await expect(page.locator('#maintenance-operation-detail')).not.toContainText('completed');
  expect(sent).toHaveLength(2);
  expect(sent[1]).toEqual(sent[0]);
  expect(JSON.parse(sent[0].body).expected_installed_digest).toBe(installedDigest);
  expect(sent[0].revision).toBe('"' + configuration.revision + '"');
  expect(sent[0].key).toMatch(/^[0-9a-f-]{36}$/);
  await page.getByRole('button', { name: 'Read maintenance status', exact: true }).click();
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Software maintenance completed',
  );
  await expect(page.locator('#maintenance-retry')).toBeHidden();
  await page.reload();
  await login(page);
  await expect(page.locator('#maintenance-settings')).toHaveAttribute('open', '');
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Software maintenance completed',
  );
  expect(sent).toHaveLength(2);
  expect(reads).toBeGreaterThanOrEqual(2);

  // A terminal record from an older operation cannot settle a fresh request
  // whose dispatch response did not identify a root job.
  await page.getByLabel('Xray adapter', { exact: true }).check();
  await page.getByLabel('Staged signed bundle', { exact: true }).selectOption(bundleID);
  await page.getByRole('button', { name: 'Review software plan', exact: true }).click();
  await page.getByRole('button', { name: 'Start reviewed maintenance', exact: true }).click();
  await expect(page.locator('#maintenance-feedback')).toContainText('Completion is unverified');
  await expect(page.locator('#maintenance-operation-id')).toHaveValue('');
  await page.getByLabel('Maintenance operation ID', { exact: true }).fill(operationID);
  await page.getByRole('button', { name: 'Read maintenance status', exact: true }).click();
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Software maintenance completed',
  );
  await expect(page.locator('#maintenance-edit')).toBeDisabled();
  await expect(page.locator('#maintenance-retry')).toBeVisible();
  await expect(page.locator('#maintenance-feedback')).toContainText(
    'does not identify the pending reviewed request',
  );
  expect(errors).toEqual([]);
});

test('maintenance removal review requires explicit direct consent and stops on interrupted status', async ({
  page,
}) => {
  const plans = [];
  let reads = 0;
  await fixture(page, {
    plan: (input) => plans.push(input),
    start: (route) => route.fulfill({ json: job('interrupted', 'remove') }),
    status: (route) => {
      reads++;
      return route.fulfill({ json: job('interrupted', 'remove') });
    },
  });
  await openMaintenance(page);
  await page.clock.install();
  await page.getByLabel('Software action', { exact: true }).selectOption('remove');
  await page.getByLabel('OpenRHP controller', { exact: true }).check();
  await expect(page.locator('#maintenance-removal-policy')).toHaveValue('preserve-closed');
  await expect(page.locator('#maintenance-self-removal')).toBeVisible();
  await page.getByRole('button', { name: 'Review software plan', exact: true }).click();
  await expect(page.locator('#maintenance-plan')).toBeVisible();
  expect(plans[0].removal_policy).toBe('preserve-closed');
  expect(plans[0].bundle_id).toBeUndefined();
  await page
    .getByLabel('Traffic policy after removal', { exact: true })
    .selectOption('restore-direct');
  await expect(page.locator('#maintenance-plan')).toBeHidden();
  await page.getByRole('button', { name: 'Review software plan', exact: true }).click();
  await expect(page.locator('#maintenance-feedback')).toContainText(
    'Explicitly allow direct internet',
  );
  expect(plans).toHaveLength(1);
  await page.locator('#maintenance-direct-consent').check();
  await page.getByRole('button', { name: 'Review software plan', exact: true }).click();
  await expect(page.locator('#maintenance-warnings')).toContainText(
    'Direct internet access will be restored',
  );
  expect(plans[1].removal_policy).toBe('restore-direct');
  await page.getByRole('button', { name: 'Start reviewed maintenance', exact: true }).click();
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'operator recovery are required',
  );
  await expect(page.locator('#maintenance-operation-id')).toHaveValue(operationID);
  await expect(page.locator('#maintenance-retry')).toBeHidden();
  await expect(page.locator('#maintenance-guard-detail')).toContainText(
    'does not establish the active traffic policy',
  );
  await page.clock.runFor(5000);
  expect(reads).toBe(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({
    path: '../../test-results/maintenance-interrupted-mobile.png',
    fullPage: true,
  });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('maintenance UI never treats a generic successful dispatch or failed root job as completion', async ({
  page,
}) => {
  await fixture(page, {
    start: (route) =>
      route.fulfill({
        json: {
          id: operationID,
          state: 'succeeded',
          result: { maintenance_operation_id: operationID, dispatch_accepted: true },
        },
      }),
    status: (route) => route.fulfill({ json: job('failed') }),
  });
  await openMaintenance(page);
  await page.getByLabel('Xray adapter', { exact: true }).check();
  await page.getByLabel('Staged signed bundle', { exact: true }).selectOption(bundleID);
  await page.getByRole('button', { name: 'Review software plan', exact: true }).click();
  await page.getByRole('button', { name: 'Start reviewed maintenance', exact: true }).click();
  await expect(page.locator('#maintenance-feedback')).toContainText(
    'dispatch acknowledgement does not prove completion',
  );
  await expect(page.locator('#maintenance-progress')).toBeHidden();
  await expect(page.locator('#maintenance-operation-id')).toHaveValue(operationID);
  await page.getByRole('button', { name: 'Read maintenance status', exact: true }).click();
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Software maintenance failed',
  );
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'package_verification_failed',
  );
  await expect(page.locator('#maintenance-retry')).toBeHidden();
});

test('maintenance capabilities recover the active root operation without dispatching work', async ({
  page,
}) => {
  let starts = 0;
  await fixture(page, {
    capabilities: { active: true, active_operation_id: operationID },
    start: (route) => {
      starts++;
      return route.fulfill({ json: job('running') });
    },
    status: (route) => route.fulfill({ json: job('running') }),
  });
  await page.goto('/');
  await login(page);
  await page.getByText('Gateway setup and diagnostics', { exact: true }).click();
  await page.getByText('Software maintenance', { exact: true }).click();
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Maintenance is running',
  );
  await expect(page.locator('#maintenance-operation-id')).toHaveValue(operationID);
  await expect(page.locator('#maintenance-review')).toBeDisabled();
  expect(starts).toBe(0);
});

test('busy maintenance status retries only reads and accepts authoritative completion', async ({
  page,
}) => {
  let reads = 0,
    starts = 0;
  await page.clock.install();
  await fixture(page, {
    start: (route) => {
      starts++;
      return route.fulfill({ json: job('running') });
    },
    status: (route) => {
      reads++;
      return reads === 1
        ? route.fulfill({
            status: 503,
            json: {
              error: {
                code: 'maintenance_state_busy',
                message: 'Package service is busy.',
                retryable: true,
              },
            },
          })
        : route.fulfill({ json: job('completed') });
    },
  });
  await openMaintenance(page);
  await page.getByLabel('Maintenance operation ID', { exact: true }).fill(operationID);
  await page.getByRole('button', { name: 'Read maintenance status', exact: true }).click();
  await expect(page.locator('#maintenance-feedback')).toContainText(
    'Retrying this status read (1 of 3)',
  );
  await expect(page.locator('#maintenance-operation-detail')).not.toContainText(
    'Software maintenance completed',
  );
  await page.clock.runFor(3100);
  await expect(page.locator('#maintenance-operation-detail')).toContainText(
    'Software maintenance completed',
  );
  expect(reads).toBe(2);
  expect(starts).toBe(0);
});

test('busy maintenance status stops after three automatic retries', async ({ page }) => {
  let reads = 0;
  await page.clock.install();
  await fixture(page, {
    start: () => {
      throw Error('A status read must not dispatch work');
    },
    status: (route) => {
      reads++;
      return route.fulfill({
        status: 503,
        json: {
          error: {
            code: 'maintenance_state_busy',
            message: 'Package service is busy.',
            retryable: true,
          },
        },
      });
    },
  });
  await openMaintenance(page);
  await page.getByLabel('Maintenance operation ID', { exact: true }).fill(operationID);
  await page.getByRole('button', { name: 'Read maintenance status', exact: true }).click();
  for (let attempt = 1; attempt <= 3; attempt++) {
    await expect(page.locator('#maintenance-feedback')).toContainText(
      `Retrying this status read (${attempt} of 3)`,
    );
    await page.clock.runFor(3100);
  }
  await expect(page.locator('#maintenance-feedback')).toContainText(
    'Maintenance status could not be verified',
  );
  // Jump past the retry window without issuing 30 seconds of unrelated
  // dashboard polls against the shared real API in a fraction of a second.
  await page.clock.fastForward(30000);
  expect(reads).toBe(4);
  await expect(page.locator('#maintenance-operation-detail')).not.toContainText(
    'Software maintenance completed',
  );
  await expect(page.locator('#maintenance-operation-id')).toHaveValue(operationID);
});

for (const errorCase of [
  { name: 'other error code', status: 503, code: 'maintenance_rejected', retryable: true },
  {
    name: 'nonretryable busy error',
    status: 503,
    code: 'maintenance_state_busy',
    retryable: false,
  },
  { name: 'different HTTP status', status: 422, code: 'maintenance_state_busy', retryable: true },
]) {
  test(`maintenance status does not automatically retry ${errorCase.name}`, async ({ page }) => {
    let reads = 0;
    await page.clock.install();
    await fixture(page, {
      start: () => {
        throw Error('A status read must not dispatch work');
      },
      status: (route) => {
        reads++;
        return route.fulfill({
          status: errorCase.status,
          json: { error: { ...errorCase, message: 'Status could not be read.' } },
        });
      },
    });
    await openMaintenance(page);
    await page.getByLabel('Maintenance operation ID', { exact: true }).fill(operationID);
    await page.getByRole('button', { name: 'Read maintenance status', exact: true }).click();
    await expect(page.locator('#maintenance-feedback')).toContainText(
      'Maintenance status could not be verified',
    );
    await page.clock.fastForward(30000);
    expect(reads).toBe(1);
    await expect(page.locator('#maintenance-operation-detail')).not.toContainText(
      'Software maintenance completed',
    );
  });
}
