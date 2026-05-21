import { test, expect } from '@playwright/test';

/**
 * MFA-flow e2e v0.0.3-Merkle:
 * 1. Register + login (no TOTP) → vault toegankelijk
 * 2. Settings → TOTP setup → genereer secret + verifieer met code uit /api/test
 * 3. Logout + re-login → mfa_required → mfa.html → enter code → vault
 *
 * We genereren TOTP-codes via backend /auth/totp/setup response + computeTotp in JS.
 */

const EMAIL = `mfa+${Date.now()}@example.com`;
const PW = 'MfaTest12345!';

// Minimale HMAC-SHA1 TOTP-implementatie in test (no extra deps).
async function totpCode(secretBase32: string): Promise<string> {
  // base32 → bytes
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = secretBase32.replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (const c of clean) {
    const idx = ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`bad base32 char: ${c}`);
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  // counter = floor(time / 30)
  const counter = Math.floor(Date.now() / 1000 / 30);
  const counterBuf = new ArrayBuffer(8);
  const dv = new DataView(counterBuf);
  dv.setUint32(4, counter, false);
  // HMAC-SHA1
  const key = await crypto.subtle.importKey(
    'raw', bytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = sig[sig.length - 1] & 0xf;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, '0');
}

test('TOTP setup + re-login MFA-challenge flow', async ({ page, context }) => {
  // 1. Register + login (geen TOTP nog)
  await page.goto('/index.html');
  await page.click('#show-register');
  await page.fill('#reg-email', EMAIL);
  await page.fill('#reg-pw', PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/, { timeout: 5000 });

  await page.fill('#login-email', EMAIL);
  await page.fill('#login-pw', PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/, { timeout: 5000 });

  // 2. Settings → TOTP setup
  await page.goto('/settings.html');
  await expect(page.locator('#totp-status')).toHaveText('Niet ingeschakeld', { timeout: 10000 });

  // Capture setup-response om secret te krijgen
  const setupPromise = page.waitForResponse((r) => r.url().includes('/auth/totp/setup') && r.status() === 200);
  await page.click('#totp-enable-btn');
  const setupRes = await setupPromise;
  const setupBody = await setupRes.json();
  const secret = setupBody.secret as string;
  expect(secret.length).toBeGreaterThan(10);

  // 3. Bereken TOTP-code + verifieer
  const code = await totpCode(secret);
  await page.fill('#setup-code', code);
  await page.click('#totp-verify-form button[type="submit"]');
  await expect(page.locator('#setup-success')).toBeVisible({ timeout: 5000 });

  // 4. Logout
  await page.click('#logout-btn');
  await page.waitForURL(/index\.html/);

  // 5. Re-login → moet redirecten naar mfa.html
  await page.goto('/login.html');
  await page.fill('#login-email', EMAIL);
  await page.fill('#login-pw', PW);
  await page.click('#login-submit');
  await page.waitForURL(/mfa\.html/, { timeout: 5000 });

  // 6. Voer challenge-code in (compute new — kan ander 30s window zijn)
  const challengeCode = await totpCode(secret);
  await page.fill('#totp-code', challengeCode);
  await page.click('#totp-submit');
  await page.waitForURL(/vault\.html/, { timeout: 5000 });

  // 7. Vault-section verschijnt na vault-pw
  await expect(page.locator('#unlock-section')).toBeVisible();
});
