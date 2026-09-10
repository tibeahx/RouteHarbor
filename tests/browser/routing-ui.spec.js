// UI response fixtures only; actual scoped conntrack deletion is tested in Linux.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');

test('confirmed routing stays visible when optional connection cleanup needs a retry', async ({
  page,
}) => {
  const token = fs.readFileSync(process.env.ROUTEHARBOR_TEST_TOKEN_FILE, 'utf8').trim();
  await page.route('**/api/v1/capabilities', async (route) => {
    const response = await route.fetch();
    const capabilities = await response.json();
    capabilities.network_helper = true;
    capabilities.platform.supported = true;
    await route.fulfill({ json: capabilities });
  });
  let confirmations = 0;
  await page.route('**/api/v1/transactions**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const transaction = { id: 'a'.repeat(32), state: 'prepared' };
    if (path.endsWith('/apply')) {
      transaction.state = 'applied';
      transaction.deadline = new Date(Date.now() + 120_000).toISOString();
    } else if (path.endsWith('/confirm')) {
      transaction.state = 'confirmed';
      transaction.flow_termination = ++confirmations === 1 ? 'failed' : 'completed';
    }
    await route.fulfill({ json: { state: 'succeeded', result: transaction } });
  });
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await page
    .locator('details')
    .filter({ has: page.locator('#prepare-network') })
    .locator(':scope > summary')
    .click();
  await page.getByRole('button', { name: 'Prepare routing', exact: true }).click();
  await expect(page.locator('#transaction-detail')).toContainText('Routing is prepared');
  await expect(page.locator('#confirm-network')).toBeDisabled();
  await page.getByRole('button', { name: 'Apply with rollback timer', exact: true }).click();
  await expect(page.locator('#transaction-detail')).toContainText('Automatic rollback at');
  await page.getByRole('button', { name: 'Confirm tested connectivity', exact: true }).click();
  await expect(page.locator('#transaction-detail')).toContainText(
    'new routing plan remains active',
  );
  await expect(page.locator('#rollback-network')).toBeDisabled();
  await expect(page.locator('#confirm-network')).toBeEnabled();
  await page.locator('#confirm-network').click();
  await expect(page.locator('#transaction-detail')).toHaveText(
    'Routing is confirmed and retained.',
  );
  await expect(page.locator('#confirm-network')).toBeDisabled();
});
