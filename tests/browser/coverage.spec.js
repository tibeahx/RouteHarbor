const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const tokenFile = process.env.OPENRHP_TEST_TOKEN_FILE;
if (!tokenFile)
  throw new Error('OPENRHP_TEST_TOKEN_FILE must point to a private local test credential.');
const token = fs.readFileSync(tokenFile, 'utf8').trim();

async function login(page) {
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your network', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Coverage', exact: true }).click();
}

test('coverage explains its real capability gate and rejects an unverified identity through the API', async ({
  page,
}) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await login(page);
  await expect(
    page.getByText(
      'Wireless setup stays unavailable until both devices prove encrypted bridge compatibility and the main router supports managed setup.',
      { exact: false },
    ),
  ).toBeVisible();
  await expect(page.locator('#coverage-wizard')).toBeHidden();
  await page.getByRole('button', { name: 'Add an access point', exact: true }).click();
  const form = page.getByRole('dialog', { name: 'Add an access point', exact: true });
  await form.getByLabel('Name', { exact: true }).fill('Unverified access point');
  await form.getByLabel('Node HTTPS address', { exact: true }).fill('https://127.0.0.1:9');
  await form.getByLabel('Verified SHA-256 fingerprint', { exact: true }).fill('unverified');
  await form
    .getByLabel('One-time pairing code', { exact: true })
    .fill('test-code-without-authority');
  await form.getByRole('button', { name: 'Verify and pair', exact: true }).click();
  await expect(page.locator('#notice')).toContainText(/identity|pairing|fingerprint|capability/i);
  await expect(page.locator('#node-list')).not.toContainText('Unverified access point');
  await expect(page.locator('#coverage-wizard')).toBeHidden();
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '../../test-results/coverage-gate-mobile.png', fullPage: true });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBeTruthy();
  expect(
    await page.evaluate(
      () => Object.keys(localStorage).length + Object.keys(sessionStorage).length,
    ),
  ).toBe(0);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.locator('#node-code')).toHaveValue('');
  await expect(page.locator('#coverage-password')).toHaveValue('');
  expect(errors).toEqual([]);
});

// No browser route mocks or fabricated successful operations. This test runs
// only when an isolated, already paired OpenWrt lab is explicitly configured.
test('paired lab access point follows detected-field prepare, apply and rollback', async ({
  page,
}) => {
  test.skip(
    process.env.OPENRHP_COVERAGE_APPLY_LAB !== '1',
    'Requires an explicitly configured isolated OpenWrt coverage lab; no physical device is modified by the default suite.',
  );
  const name = process.env.OPENRHP_COVERAGE_NODE_NAME;
  const port = process.env.OPENRHP_COVERAGE_UPLINK_PORT;
  const gateway = process.env.OPENRHP_COVERAGE_GATEWAY;
  if (!name || !port || !gateway)
    throw new Error(
      'Set the known lab node name, uplink port and gateway; the test never guesses network wiring.',
    );
  await login(page);
  await page.getByRole('button', { name: 'Set up connection for ' + name, exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Set up ' + name, exact: true })).toBeVisible();
  await page.getByLabel('Connect to the main router by', { exact: true }).selectOption('ethernet');
  await page.getByLabel('Port connected to the main router', { exact: true }).selectOption(port);
  await page.getByLabel("Main router's LAN address", { exact: true }).fill(gateway);
  await page
    .getByLabel(
      'I can still reach the access point through a separate trusted management connection.',
      { exact: true },
    )
    .check();
  await page.getByRole('button', { name: 'Review setup', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Ready to prepare', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Prepare access point', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Access point prepared', exact: true }),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'Apply with a 90-second rollback timer', exact: true })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Test the connection now', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Confirm tested connection', exact: true }),
  ).toBeDisabled();
  await expect(page.locator('#coverage-countdown')).toContainText('Confirm within');
  await page.screenshot({ path: '../../test-results/coverage-transaction.png', fullPage: true });
  await page.getByRole('button', { name: 'Roll back', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Previous settings restored', exact: true }),
  ).toBeVisible();
});
