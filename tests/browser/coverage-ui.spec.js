// UI contract fixtures only. This suite does not claim real router or radio
// compatibility; the ordinary browser suite still exercises the actual API.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');

test('managed Wi-Fi uses detected main AP without browser secrets and preserves pending confirmation', async ({
  page,
}) => {
  const token = fs.readFileSync(process.env.ROUTEHARBOR_TEST_TOKEN_FILE, 'utf8').trim();
  const gatewayFingerprint = 'a'.repeat(64);
  const nodeFingerprint = 'b'.repeat(64);
  const capabilities = {
    openwrt: true,
    ethernet: true,
    ap: true,
    wds: true,
    mesh: false,
    encrypted_backhaul: true,
    concurrent_radio: true,
    verified_radio: 'radio0',
    verified_mode: 'wds',
  };
  const gatewaySetup = {
    managed: true,
    aps: [
      {
        section: 'home_ap',
        network: 'lan',
        radio: 'radio0',
        ssid: 'Home Wi-Fi',
        channel: 6,
        encryption: 'psk2+ccmp',
        candidate_modes: ['wds'],
      },
    ],
  };
  const node = {
    id: 'c'.repeat(32),
    name: 'UI fixture access point',
    fingerprint: nodeFingerprint,
  };
  const requests = [];
  let transaction = null;
  await page.route('**/api/v1/nodes**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let result;
    if (path.endsWith('/nodes')) result = [node];
    else if (path.endsWith('/discover'))
      result = {
        gateway_fingerprint: gatewayFingerprint,
        gateway_capabilities: {
          ...capabilities,
          gateway_backhaul_managed: true,
          verified_peer_fingerprint: nodeFingerprint,
        },
        gateway_setup: gatewaySetup,
      };
    else if (path.endsWith('/status'))
      result = {
        capabilities: { ...capabilities, verified_peer_fingerprint: gatewayFingerprint },
        setup: {
          bridges: [
            {
              interface: 'lan',
              section: 'lan_bridge',
              device: 'br-lan',
              address: '192.168.8.2/24',
              gateway: '192.168.8.1',
              ports: ['lan1', 'lan2'],
              inactive_ethernet_uplink: 'lan1',
            },
          ],
          radios: [{ name: 'radio0', channel: 6, foreign_active: false }],
        },
        gateway_setup: gatewaySetup,
        transaction,
      };
    else {
      const data = request.postDataJSON();
      requests.push({ path, data });
      if (path.endsWith('/plan')) result = { valid: true };
      else if (path.endsWith('/prepare')) {
        transaction = { id: 'd'.repeat(32), state: 'prepared', gateway_plan: data.gateway_plan };
        result = { result: { transaction } };
      } else if (path.endsWith('/apply')) {
        transaction = {
          ...transaction,
          state: 'applied',
          deadline: new Date(Date.now() + 90_000).toISOString(),
        };
        result = { result: { transaction } };
      } else if (path.endsWith('/confirm')) {
        transaction = { ...transaction, state: 'confirming' };
        result = { result: { transaction } };
      } else throw new Error('Unexpected UI fixture request: ' + path);
    }
    await route.fulfill({ json: result });
  });
  await page.goto('/');
  await page.getByLabel('Access key', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await page.getByRole('link', { name: 'Coverage', exact: true }).click();
  await page
    .getByRole('button', { name: 'Set up connection for ' + node.name, exact: true })
    .click();
  await expect(page.locator('#coverage-connection')).toHaveValue('wifi');
  await expect(page.locator('#coverage-main-ap')).toHaveValue('home_ap');
  await expect(page.locator('#coverage-password')).toBeHidden();
  await expect(page.locator('#coverage-main-ap-detail')).toContainText('Home Wi-Fi');
  await page.locator('#coverage-adopt-main-ap').check();
  await page.locator('#coverage-management-confirm').check();
  await page.getByRole('button', { name: 'Review setup', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Ready to prepare', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Prepare access point', exact: true }).click();
  await expect(page.locator('#coverage-transaction-detail')).toContainText('Both routers');
  const prepare = requests.find((r) => r.path.endsWith('/prepare')).data;
  expect(prepare.gateway_plan).toEqual({
    mode: 'wds',
    ap_section: 'home_ap',
    network: 'lan',
    peer_fingerprint: nodeFingerprint,
    adopt_existing_ap: true,
    preserve_management_path: true,
  });
  expect(prepare.plan).not.toHaveProperty('gateway_plan');
  for (const request of requests) {
    const plan = request.data.plan || request.data;
    expect(plan).not.toHaveProperty('passphrase');
    expect(plan).not.toHaveProperty('ssid');
    expect(plan).not.toHaveProperty('channel');
  }
  await page
    .getByRole('button', { name: 'Apply with a 90-second rollback timer', exact: true })
    .click();
  await expect(page.locator('#coverage-confirm')).toBeDisabled();
  for (const check of ['management', 'address', 'internet'])
    await page.locator('#coverage-check-' + check).check();
  await page.locator('#coverage-confirm').click();
  await expect(page.locator('#coverage-transaction-title')).toHaveText('Confirming both routers');
  await expect(page.locator('#coverage-message')).toContainText('still in progress');
  await expect(page.locator('#coverage-prepare')).toBeDisabled();
  await expect(page.locator('#coverage-rollback')).toBeDisabled();
  await expect(page.locator('#coverage-form')).toBeHidden();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBeTruthy();
});
