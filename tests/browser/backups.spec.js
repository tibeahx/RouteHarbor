const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const tokenFile = process.env.OPENRHP_TEST_TOKEN_FILE;
if (!tokenFile)
  throw new Error('OPENRHP_TEST_TOKEN_FILE must identify the private local test credential.');
const token = fs.readFileSync(tokenFile, 'utf8').trim();
const headers = { Authorization: 'Bearer ' + token };
const canary = 'BROWSER-BACKUP-PRIVATE-CANARY';

test('private backup is created, previewed, restored and deleted through the actual API', async ({
  page,
  request,
}) => {
  const initial = await request.get('/api/v1/config', { headers });
  const configuration = await initial.json();
  configuration.sources = [
    {
      id: 'backup-browser-source',
      name: 'Private backup source',
      type: 'socks5',
      enabled: false,
      auto: false,
      settings: { server: '1.1.1.1', server_port: 1080, username: 'owner', password: canary },
    },
  ];
  configuration.targets = [];
  configuration.policy.mode = 'off';
  configuration.policy.pinned = '';
  configuration.policy.confirmations = 3;
  configuration.network.enabled = false;
  const saved = await request.put('/api/v1/config', {
    headers: {
      ...headers,
      'If-Match': '"' + configuration.revision + '"',
      'Idempotency-Key': randomUUID(),
    },
    data: configuration,
  });
  expect(saved.ok()).toBeTruthy();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your network', exact: true })).toBeVisible();
  await page.getByText('Gateway setup and diagnostics', { exact: true }).click();
  await page.getByText('Configuration backups', { exact: true }).click();
  await expect(page.locator('#backup-summary')).toContainText('No backups yet');
  const createdResponse = page.waitForResponse(
    (r) => r.url().endsWith('/api/v1/config/backups') && r.request().method() === 'POST',
  );
  await page.getByRole('button', { name: 'Create backup', exact: true }).click();
  const created = await createdResponse;
  expect(created.ok()).toBeTruthy();
  const operation = await created.json();
  expect(operation.result.backup.id).toBe(operation.id);
  expect(JSON.stringify(operation)).not.toContain(canary);
  const row = page.locator('[data-backup-id="' + operation.id + '"]');
  await expect(row).toBeVisible();

  await page.getByText('Selection thresholds and fallback', { exact: true }).click();
  await page.getByLabel('Confirming checks', { exact: true }).fill('7');
  await page.getByRole('button', { name: 'Save selection', exact: true }).click();
  await expect(page.locator('#notice')).toContainText('Settings saved');
  let current = await (await request.get('/api/v1/config', { headers })).json();
  expect(current.policy.confirmations).toBe(7);

  const previewResponse = page.waitForResponse((r) =>
    r.url().endsWith('/api/v1/config/backups/' + operation.id),
  );
  await row.getByRole('button', { name: 'Preview', exact: true }).click();
  expect(await (await previewResponse).text()).not.toContain(canary);
  const dialog = page.locator('#backup-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('prepare, apply, test and confirm');
  await expect(dialog).toContainText('Private backup source');
  await dialog.getByText('View masked configuration', { exact: true }).click();
  const masked = JSON.parse(await page.locator('#backup-config').textContent());
  expect(masked.sources[0].settings).toEqual({});
  expect(masked.policy.confirmations).toBe(3);

  // The background poll may learn a new revision, but an open restore preview
  // must remain bound to the revision the user actually reviewed.
  const concurrent = await request.patch('/api/v1/sources/backup-browser-source', {
    headers: {
      ...headers,
      'If-Match': '"' + current.revision + '"',
      'Idempotency-Key': randomUUID(),
    },
    data: { name: 'Changed in another session' },
  });
  expect(concurrent.ok()).toBeTruthy();
  await expect(page.locator('#source-list')).toContainText('Changed in another session', {
    timeout: 12000,
  });
  const staleResponse = page.waitForResponse((r) => r.url().endsWith('/restore'));
  await dialog.getByRole('button', { name: 'Restore saved settings', exact: true }).click();
  expect((await staleResponse).status()).toBe(409);
  await expect(page.locator('#backup-preview-error')).toContainText('Close and reopen');
  current = await (await request.get('/api/v1/config', { headers })).json();
  expect(current.sources[0].name).toBe('Changed in another session');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await row.getByRole('button', { name: 'Preview', exact: true }).click();
  await expect(dialog).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '../../test-results/backup-preview-mobile.png', fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const restoredResponse = page.waitForResponse((r) => r.url().endsWith('/restore'));
  await dialog.getByRole('button', { name: 'Restore saved settings', exact: true }).click();
  const restored = await restoredResponse;
  expect(restored.ok()).toBeTruthy();
  expect((await restored.json()).result.network_changes_applied).toBe(false);
  await expect(dialog).not.toBeVisible();
  await expect(page.locator('#notice')).toContainText(
    'Prepare, apply, test and confirm a fresh routing plan',
  );
  const full = await request.post('/api/v1/config/export', {
    headers,
    data: { include_secrets: true },
  });
  expect(full.ok()).toBeTruthy();
  current = await full.json();
  expect(current.policy.confirmations).toBe(3);
  expect(current.sources[0].name).toBe('Private backup source');
  expect(current.sources[0].settings.password).toBe(canary);
  expect(await page.locator('body').textContent()).not.toContain(canary);
  page.once('dialog', (dialog) => dialog.accept());
  await row.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row).toHaveCount(0);
  await expect(page.locator('#backup-summary')).toContainText('No backups yet');
  const absent = await request.get('/api/v1/config/backups/' + operation.id, { headers });
  expect(absent.status()).toBe(404);
  expect(errors).toEqual([]);
});
