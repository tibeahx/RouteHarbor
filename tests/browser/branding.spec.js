const { test, expect } = require('@playwright/test');

test('RouteHarbor branding remains clear on desktop and small screens', async ({
  page,
  request,
}) => {
  await page.goto('/');
  await expect(page).toHaveTitle('RouteHarbor · Your home network');
  const brand = page.getByRole('link', { name: 'RouteHarbor home', exact: true });
  await expect(brand).toBeVisible();
  await expect(brand.locator('span')).toHaveText('RouteHarborAdaptive routing gateway');
  await expect(brand.locator('small')).toHaveText('Adaptive routing gateway');
  await expect(brand.locator('svg')).toHaveAttribute('aria-hidden', 'true');
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/favicon.svg');

  const favicon = await request.get('/favicon.svg');
  expect(favicon.ok()).toBeTruthy();
  expect(favicon.headers()['content-type']).toContain('image/svg+xml');
  expect(await favicon.text()).toContain('<title>RouteHarbor</title>');

  await page.screenshot({ path: '../../test-results/branding/routeharbor-ui-desktop.png' });
  await page.setViewportSize({ width: 320, height: 740 });
  await expect(brand).toBeVisible();
  await expect(brand.locator('small')).toBeVisible();
  const dimensions = await brand.boundingBox();
  expect(dimensions.x).toBeGreaterThanOrEqual(0);
  expect(dimensions.x + dimensions.width).toBeLessThanOrEqual(320);
  const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(pageWidth).toBeLessThanOrEqual(320);
  await page.screenshot({ path: '../../test-results/branding/routeharbor-ui-mobile.png' });
});
