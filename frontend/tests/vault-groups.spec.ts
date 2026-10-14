import { test, expect } from './isolated';
import type { Page } from '@playwright/test';

/**
 * v0.3.5-Miller — categorieën (KDBX-groepen) en zoeken in de kluis (S7).
 * Eigen tijdelijke stack per worker (tests/isolated.ts); nooit LIVE.
 */

const EMAIL = `groups+${Date.now()}@example.com`;
const ACCOUNT_PW = 'GroupsTest1234Account';
const VAULT_PW = 'VaultPw99!';

async function unlock(page: Page) {
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
}

const groupBtn = (page: Page, name: string) => page.locator('#group-tree .group-btn', { hasText: name }).first();
const rows = (page: Page) => page.locator('#entries-body tr.selectable');

test('categorieboom, zoeken en nieuwe entry in gekozen categorie', async ({ page }) => {
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
  await unlock(page); // maakt een lege kluis

  // Kluis vullen met groepen + prullenbak, zoals een KeePassXC-database
  await page.evaluate(async (pw) => {
    const w = window as any;
    const list = await w.HorseSafeAPI.listVaults();
    const id = list.data[0].id;
    const cur = await w.HorseSafeAPI.readVault(id);
    const db = await w.HorseSafeCrypto.openDatabase(cur.blob, pw, null);
    const root = db.getDefaultGroup();
    const apps = db.createGroup(root, '5 Eigen apps & diensten');
    const fod = db.createGroup(apps, 'FODMAP');
    const werk = db.createGroup(root, '8 Werk');
    const add = (g: any, title: string, f: Record<string, string> = {}) => {
      const e = db.createEntry(g);
      e.fields.set('Title', title);
      for (const [k, v] of Object.entries(f)) e.fields.set(k, v);
      return e;
    };
    add(fod, 'FODMAP backend', { UserName: 'admin', Password: w.kdbxweb.ProtectedValue.fromString('GeheimZoekwoord') });
    add(apps, 'ArchPortal', { URL: 'https://example.org/archportal/' });
    add(werk, 'Staff Café', { Notes: 'Gebruikt in: staffcloud' });
    add(root, 'Losse entry');
    db.remove(add(werk, 'Weggegooid')); // → prullenbak
    const blob = await w.HorseSafeCrypto.saveDatabase(db);
    const r = await w.HorseSafeAPI.updateVault(id, blob, cur.etag);
    if (!r.ok) throw new Error('upload ' + r.status);
  }, VAULT_PW);

  await page.click('#lock-vault');
  await expect(page.locator('#group-tree li')).toHaveCount(0); // vergrendeld = boom leeg
  await unlock(page);

  // Boom: Alle (4, zonder prullenbak), groepen, prullenbak onderaan
  await expect(groupBtn(page, 'Alle entries')).toContainText('4');
  await expect(page.locator('#entry-count')).toHaveText('4');
  await expect(page.locator('#entry-total')).toHaveText('');
  const top = await page.locator('#group-tree > li > .group-row .group-btn span:first-child').allTextContents();
  expect(top[0]).toBe('Alle entries');
  expect(top[top.length - 1]).toBe('Prullenbak');
  await expect(page.locator('#entries-table th.col-group')).toBeVisible();

  // Categorie kiezen (incl. subgroep)
  await groupBtn(page, '5 Eigen apps').click();
  await expect(page.locator('#list-title')).toHaveText('5 Eigen apps & diensten');
  await expect(page.locator('#entry-count')).toHaveText('2');
  await expect(page.locator('#entry-total')).toHaveText(' van 4');
  await expect(page.locator('#entries-table th.col-group')).toBeHidden();

  // Uitklappen → subgroep
  await page.locator('#group-tree .group-row', { hasText: '5 Eigen apps' }).locator('.group-toggle').click();
  await groupBtn(page, 'FODMAP').click();
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText('FODMAP backend');

  // Prullenbak alleen als je hem kiest
  await page.locator('#group-tree > li').last().locator('.group-btn').click();
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText('Weggegooid');

  // Zoeken: vanuit "8 Werk" standaard in de hele kluis; accenten/hoofdletters tellen niet
  await groupBtn(page, '8 Werk').click();
  await page.fill('#entry-search', 'FODMAP');
  await expect(page.locator('#list-title')).toHaveText('Zoekresultaten');
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText('FODMAP backend');
  await expect(page.locator('#entries-table th.col-group')).toBeVisible();
  await page.check('#search-in-group');
  await expect(page.locator('#entries-body')).toContainText('Niets gevonden');
  await page.uncheck('#search-in-group');
  await page.fill('#entry-search', 'cafe staffcloud');
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText('Staff Café');
  // Nooit in wachtwoorden
  await page.fill('#entry-search', 'GeheimZoekwoord');
  await expect(page.locator('#entries-body')).toContainText('Niets gevonden');
  // Esc maakt leeg; "/" springt naar het zoekveld
  await page.press('#entry-search', 'Escape');
  await expect(page.locator('#entry-search')).toHaveValue('');
  await page.locator('#vault-name').click();
  await page.keyboard.press('/');
  await expect(page.locator('#entry-search')).toBeFocused();

  // Nieuwe entry landt in de gekozen categorie en blijft daar na opnieuw openen
  await groupBtn(page, 'FODMAP').click();
  await page.click('#add-entry');
  await expect(page.locator('#e-group-label')).toHaveText('5 Eigen apps & diensten › FODMAP');
  await page.fill('#e-title', 'FODMAP frontend');
  await page.fill('#e-pw', 'X'.repeat(12));
  await page.click('#edit-form button[type="submit"]');
  await expect(rows(page)).toHaveCount(2, { timeout: 30_000 });
  await page.click('#lock-vault');
  await unlock(page);
  await expect(page.locator('#entry-count')).toHaveText('5');
  await page.fill('#entry-search', 'frontend');
  await expect(rows(page).first().locator('td.col-group')).toHaveText('5 Eigen apps & diensten › FODMAP');
  await page.press('#entry-search', 'Escape');

  // Smal scherm: keuzelijst i.p.v. boom
  await page.setViewportSize({ width: 800, height: 900 });
  await expect(page.locator('#group-select')).toBeVisible();
  await expect(page.locator('#group-tree')).toBeHidden();
  const werkValue = await page.locator('#group-select option', { hasText: '8 Werk' }).getAttribute('value');
  await page.selectOption('#group-select', werkValue!);
  await expect(page.locator('#entry-count')).toHaveText('1');
});
