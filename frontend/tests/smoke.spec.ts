import { test, expect } from '@playwright/test';

/**
 * Smoke-test e2e: vendored kdbxweb + argon2 + backend round-trip.
 *
 * Vereist: backend draait op localhost:3997 met:
 *   HORSESAFE_CORS_ORIGINS=http://localhost:8000
 *   HORSESAFE_COOKIE_SECURE=false
 *   HORSESAFE_DB_PATH + HORSESAFE_VAULTS_DIR naar tmp-dir
 *
 * Frontend serveert vanaf localhost:8000 (playwright webServer doet python -m http.server).
 */

const TEST_EMAIL = `e2e+${Date.now()}@example.com`;
const ACCOUNT_PW = 'SmokeTest1234Account';
const VAULT_PW = 'VaultPw99!';

test('S1 landing rendert', async ({ page }) => {
  await page.goto('/index.html');
  await expect(page.locator('h1')).toHaveText('HorseSafe');
  await expect(page.locator('.slogan')).toHaveText('Jouw kluis. Niet de onze.');
});

test('register → login → vault aanmaken → entry toevoegen → roundtrip', async ({ page }) => {
  // S1 → register
  await page.goto('/index.html');
  await page.click('#show-register');
  await page.fill('#reg-email', TEST_EMAIL);
  await page.fill('#reg-pw', ACCOUNT_PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await expect(page.locator('#register-success')).toBeVisible({ timeout: 5000 });

  // Redirect naar login
  await page.waitForURL(/login\.html/, { timeout: 5000 });

  // S2 login
  await page.fill('#login-email', TEST_EMAIL);
  await page.fill('#login-pw', ACCOUNT_PW);
  await page.click('#login-submit');

  // Redirect naar vault
  await page.waitForURL(/vault\.html/, { timeout: 5000 });

  // S6 vault unlock — geen vault → create
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');

  // Wachten op vault-section
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('0');

  // S7 add entry
  await page.click('#add-entry');
  await page.fill('#e-title', 'Test entry');
  await page.fill('#e-username', 'alice');
  await page.fill('#e-pw', 'EntrySecret123!');
  await page.fill('#e-url', 'https://example.com');
  await page.fill('#e-notes', 'Smoke-test note');
  await page.click('#edit-form button[type="submit"]');

  // Entry verschijnt
  await expect(page.locator('#entry-count')).toHaveText('1', { timeout: 30_000 });
  await expect(page.locator('#entries-body tr td').first()).toHaveText('Test entry');

  // Klik entry → detail-pane
  await page.click('#entries-body tr.selectable');
  await expect(page.locator('#detail-pane')).toBeVisible();
  await expect(page.locator('#d-title')).toHaveText('Test entry');
  await expect(page.locator('#d-username')).toHaveText('alice');

  // Pw toggle
  await page.click('#d-pw-toggle');
  await expect(page.locator('#d-pw-display')).toHaveText('EntrySecret123!');

  // Lock + unlock = roundtrip-test
  await page.click('#lock-vault');
  await expect(page.locator('#unlock-section')).toBeVisible();
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('1', { timeout: 10_000 });

  // Verkeerd wachtwoord
  await page.click('#lock-vault');
  await page.fill('#vault-pw', 'WrongPwwwwww');
  await page.click('#unlock-submit');
  await expect(page.locator('#unlock-error')).toContainText(/Verkeerd wachtwoord/);
});
