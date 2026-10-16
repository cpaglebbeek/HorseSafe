import { test, expect } from './isolated';

/**
 * HS-BUG-011 (0.4.1-Montgomery): "🔑 Sleutels" leek niets te doen bij een grote kluis — het paneel opende onder
 * alle entries, buiten beeld. Met 300 entries moet het paneel na de klik in beeld staan.
 * Eigen tijdelijke stack per worker (tests/isolated.ts); nooit LIVE.
 */

const EMAIL = `keys+${Date.now()}@example.com`;
const ACCOUNT_PW = 'KeysPanelTest1234Acc';
const VAULT_PW = 'VaultPw99!';

test('Sleutels-paneel staat in beeld bij een kluis met 300 entries', async ({ page }) => {
  await page.setViewportSize({ width: 1400, height: 900 });
  await page.goto('/index.html');
  await page.click('#show-register');
  await page.fill('#reg-email', EMAIL);
  await page.fill('#reg-pw', ACCOUNT_PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/, { timeout: 5000 });
  await page.fill('#login-email', EMAIL);
  await page.fill('#login-pw', ACCOUNT_PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/, { timeout: 5000 });
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });

  // Kluis vullen met 300 entries (zoals database1 met 342)
  await page.evaluate(async (pw) => {
    const w = window as any;
    const list = await w.HorseSafeAPI.listVaults();
    const id = list.data[0].id;
    const cur = await w.HorseSafeAPI.readVault(id);
    const db = await w.HorseSafeCrypto.openDatabase(cur.blob, pw, null);
    const root = db.getDefaultGroup();
    for (let i = 0; i < 300; i++) {
      const e = db.createEntry(root);
      e.fields.set('Title', `Entry ${String(i).padStart(3, '0')}`);
    }
    const blob = await w.HorseSafeCrypto.saveDatabase(db);
    const r = await w.HorseSafeAPI.updateVault(id, blob, cur.etag);
    if (!r.ok) throw new Error('upload ' + r.status);
  }, VAULT_PW);
  await page.click('#lock-vault');
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#entry-count')).toHaveText('300', { timeout: 30_000 });

  await page.evaluate(() => window.scrollTo(0, 0));
  await page.click('#keys-open');
  await expect(page.locator('#keys-section')).toBeVisible();
  await expect(page.locator('#keys-section h2')).toBeInViewport();
  await expect(page.locator('#phone-pair')).toBeAttached();
  await expect(page.locator('#keys-title')).toBeFocused();

  await page.click('#keys-close');
  await expect(page.locator('#keys-section')).toBeHidden();
  await expect(page.locator('#keys-open')).toBeFocused();
});
