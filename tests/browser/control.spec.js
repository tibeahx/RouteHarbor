const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const tokenFile = process.env.OPENRHP_TEST_TOKEN_FILE;
if (!tokenFile)
  throw new Error('OPENRHP_TEST_TOKEN_FILE must point to a private local test credential.');
const token = fs.readFileSync(tokenFile, 'utf8').trim();
test.beforeEach(async ({ request }) => {
  const headers = { Authorization: 'Bearer ' + token };
  const r = await request.get('/api/v1/config', { headers });
  const c = await r.json();
  c.sources = [];
  c.targets = [];
  c.policy.mode = 'off';
  c.policy.pinned = '';
  c.policy.break_existing = false;
  c.routing = null; // This suite exercises legacy all-traffic selection and resets.
  const saved = await request.put('/api/v1/config', {
    headers: {
      ...headers,
      'If-Match': '\"' + c.revision + '\"',
      'Idempotency-Key': require('node:crypto').randomUUID(),
    },
    data: c,
  });
  expect(saved.ok()).toBeTruthy();
});
async function login(page) {
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your network', exact: true })).toBeVisible();
}

test('resetting old connection tracking requires an explicit saved opt-in', async ({
  page,
  request,
}) => {
  await login(page);
  await page.getByText('Selection thresholds and fallback', { exact: true }).click();
  const reset = page.getByLabel('Reset old connection tracking when switching paths', {
    exact: true,
  });
  await expect(reset).not.toBeChecked();
  await reset.check();
  await page.getByRole('button', { name: 'Save selection', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('Settings saved');
  const response = await request.get('/api/v1/config', {
    headers: { Authorization: 'Bearer ' + token },
  });
  expect((await response.json()).policy.break_existing).toBe(true);
  await page.reload();
  await login(page);
  await page.getByText('Selection thresholds and fallback', { exact: true }).click();
  await expect(reset).toBeChecked();
  await expect(page.locator('#routing-banner')).toContainText('Traffic routing is not applied');
});

test('manual user adds, checks, selects and removes a path through the public API', async ({
  page,
}) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await page.screenshot({ path: '../../test-results/login-desktop.png', fullPage: true });
  await login(page);
  await page.getByRole('link', { name: /Access methods/ }).click();
  await page.getByRole('button', { name: 'Add access method', exact: true }).first().click();
  await page.getByLabel('Name', { exact: true }).first().fill('Home WAN');
  await page.getByLabel('Connection type').selectOption('direct');
  await page.getByRole('button', { name: 'Add method', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Home WAN', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Overview', exact: true }).click();
  await page.getByRole('button', { name: 'Add resource', exact: true }).click();
  await page.getByLabel('HTTPS address', { exact: true }).fill('https://example.com/');
  await page
    .locator('#resource-form')
    .getByRole('button', { name: 'Add resource', exact: true })
    .click();
  await expect(page.locator('#target-list')).toContainText('https://example.com/');
  await page.getByRole('button', { name: 'Check all methods', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('Checks queued');
  await page.getByLabel('Selection mode', { exact: true }).selectOption('auto');
  await page.getByRole('button', { name: 'Save selection', exact: true }).click();
  await expect(page.locator('#mode-label')).toHaveText('Automatic');
  await expect(page.locator('#routing-banner')).toContainText('Traffic routing is not applied');
  await page.screenshot({ path: '../../test-results/overview-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '../../test-results/overview-mobile.png', fullPage: true });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
  await page.getByRole('link', { name: 'Coverage', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'One gateway. More coverage.' })).toBeVisible();
  await page.screenshot({ path: '../../test-results/coverage-mobile.png', fullPage: true });
  await page.getByRole('link', { name: 'Overview', exact: true }).click();
  await page.getByLabel('Selection mode', { exact: true }).selectOption('off');
  await page.getByRole('button', { name: 'Save selection', exact: true }).click();
  await expect(page.locator('#mode-label')).toHaveText('Off');
  await page.getByRole('button', { name: 'Remove resource https://example.com/' }).click();
  await expect(page.locator('#targets-empty')).toBeVisible();
  await page.getByRole('link', { name: /Access methods/ }).click();
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Start with your first path' })).toBeVisible();
  expect(errors).toEqual([]);
});
test('untrusted names are text, secret key is not kept in browser storage', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: /Access methods/ }).click();
  await page.getByRole('button', { name: 'Add access method', exact: true }).first().click();
  const name = '<img src=x onerror=window.compromised=true>';
  await page.getByLabel('Name', { exact: true }).first().fill(name);
  await page.getByRole('button', { name: 'Add method', exact: true }).click();
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  expect(await page.evaluate(() => !!window.compromised)).toBe(false);
  expect(
    await page.evaluate(
      () => Object.keys(localStorage).length + Object.keys(sessionStorage).length,
    ),
  ).toBe(0);
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Start with your first path' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByLabel('Access key', { exact: true })).toHaveValue('');
});
