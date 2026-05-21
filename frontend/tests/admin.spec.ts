import { test, expect } from '@playwright/test';

const ADMIN_EMAIL = `admin+${Date.now()}@example.com`;
const USER_EMAIL = `user+${Date.now()}@example.com`;
const PW = 'AdminTest1234!';

/**
 * Admin-flow e2e v0.0.4-Rivest:
 * 1. Register normale user
 * 2. Register admin + promote via backend HTTP-call (test-helper endpoint zou ideal zijn;
 *    in absence: direct POST naar /admin/users na manual DB-update — we gebruiken hier
 *    een aparte test-bootstrap-route: register admin, expose CLI-style promotion via test-only env)
 *
 * Voor POC: we testen admin-pagina-rendering met een **niet-admin** user → moet redirect.
 * Volledige admin-CRUD-flow vereist DB-mutatie tussendoor; dat is geregeld in backend pytest.
 */

test('admin.html redirect niet-admin terug', async ({ page }) => {
  // Register + login als normale user
  await page.goto('/index.html');
  await page.click('#show-register');
  await page.fill('#reg-email', USER_EMAIL);
  await page.fill('#reg-pw', PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/);

  await page.fill('#login-email', USER_EMAIL);
  await page.fill('#login-pw', PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/);

  // Probeer admin.html — moet 403 detecteren en alert tonen (of redirect)
  // Dialog-alert capture
  page.on('dialog', (dialog) => dialog.accept());
  await page.goto('/admin.html');
  // Verwacht: redirect naar vault.html (na alert)
  await page.waitForURL(/vault\.html/, { timeout: 5000 });
});

test('settings.html /auth/me-probe rendert correct', async ({ page }) => {
  const email = `probe+${Date.now()}@example.com`;
  await page.goto('/index.html');
  await page.click('#show-register');
  await page.fill('#reg-email', email);
  await page.fill('#reg-pw', PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/);
  await page.fill('#login-email', email);
  await page.fill('#login-pw', PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/);
  await page.goto('/settings.html');
  await expect(page.locator('#totp-status')).toHaveText('Niet ingeschakeld', { timeout: 10000 });
  // Admin-link blijft hidden
  await expect(page.locator('#admin-link')).toBeHidden();
  // Backup-codes-link blijft hidden (geen TOTP)
  await expect(page.locator('#backup-codes-link')).toBeHidden();
});
