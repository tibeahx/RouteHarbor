const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.js',
  fullyParallel: false,
  workers: 1,
  use: { baseURL: process.env.ROUTEHARBOR_TEST_URL || 'http://127.0.0.1:8787', headless: true },
  reporter: 'list',
  outputDir: '../../test-results/browser',
});
