import { test, expect, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { startStack, freshTotp, PYTHON, type Stack } from './e2e-stack';

/**
 * v0.2.0-Koblitz e2e (reviewronde 3) — magic-link als tweede stap vanuit webmail.
 *
 * Het sessie-cookie is SameSite=Strict. Een klik in webmail is een cross-site navigatie: het cookie
 * gaat dan NIET mee. De link wijst daarom naar mfa.html#ml=<token>; die pagina verzilvert met een
 * same-site POST waarbij het cookie wel meegaat. Links uit oudere mails (GET /auth/magic-link/redeem)
 * sturen zonder bijwerkingen door naar dezelfde pagina.
 *
 * "Webmail" = een pagina op http://127.0.0.1:<poort> (andere site dan localhost) met een gewone link.
 */

const ACCOUNT_PW = 'MagicLinkAccount1234!';

let stack: Stack | null = null;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  stack = await startStack('hs-magiclink-e2e-');
});

test.afterAll(async () => {
  stack?.stop();
});

function latestToken(dbPath: string, email: string): string {
  const r = spawnSync(PYTHON, ['-c', [
    'import sqlite3, sys',
    'c = sqlite3.connect(sys.argv[1])',
    'row = c.execute("SELECT m.token FROM magic_links m JOIN users u ON u.id = m.user_id '
      + 'WHERE u.email = ? ORDER BY m.created_at DESC, m.rowid DESC LIMIT 1", (sys.argv[2],)).fetchone()',
    'print(row[0] if row else "")',
  ].join('\n'), dbPath, email], { encoding: 'utf8' });
  const t = (r.stdout || '').trim();
  if (!t) throw new Error(`geen magic-link-token: ${r.stderr}`);
  return t;
}

/** Account met TOTP; daarna een wachtwoord-login in deze browser → sessie met mfa=false. */
async function passwordSessionWithTotp(page: Page, api: string, email: string): Promise<void> {
  const req = page.request;
  expect((await req.post(`${api}/auth/register`, { data: { email, password: ACCOUNT_PW, ack_data_loss: true } })).status()).toBe(201);
  expect((await req.post(`${api}/auth/login`, { data: { email, password: ACCOUNT_PW } })).ok()).toBeTruthy();
  const secret = (await (await req.post(`${api}/auth/totp/setup`)).json()).secret as string;
  const v = await req.post(`${api}/auth/totp/verify`, { data: { secret, code: await freshTotp(secret, new Set()) } });
  expect(v.ok()).toBeTruthy();
  await req.post(`${api}/auth/logout`);
  const login = await req.post(`${api}/auth/login`, { data: { email, password: ACCOUNT_PW } });
  expect((await login.json()).mfa_required).toBe(true);
  expect((await req.get(`${api}/vault`)).status()).toBe(403);
}

/** Klik een link vanaf een pagina op een ándere site (zoals een webmail). */
async function clickFromOtherSite(page: Page, href: string): Promise<void> {
  await page.goto(`http://127.0.0.1:${stack!.webPort}/index.html`);
  await page.evaluate((h) => {
    const a = document.createElement('a');
    a.id = 'webmail-link';
    a.href = h;
    a.textContent = 'Bevestig je inlog';
    document.body.prepend(a);
  }, href);
  await page.click('#webmail-link');
}

for (const variant of ['mail-link', 'oude GET-link'] as const) {
  test(`magic-link vanuit webmail (${variant}) bevestigt de wachtwoord-login`, async ({ page }) => {
    const { apiPort, webPort, dbPath } = stack!;
    const api = `http://localhost:${apiPort}`;
    const web = `http://localhost:${webPort}`;
    const email = `magic+${variant.replace(/\W/g, '').toLowerCase()}${Date.now()}@example.com`;
    await page.addInitScript((port) => { localStorage.setItem('horsesafe.devApiPort', String(port)); }, apiPort);

    await passwordSessionWithTotp(page, api, email);
    expect((await page.request.post(`${api}/auth/magic-link`, { data: { email } })).ok()).toBeTruthy();
    const token = latestToken(dbPath, email);

    const href = variant === 'mail-link'
      ? `${web}/mfa.html#ml=${token}`
      : `${api}/auth/magic-link/redeem?t=${token}`;

    const posted = page.waitForRequest((r) => r.url() === `${api}/auth/magic-link/redeem` && r.method() === 'POST');
    if (variant === 'oude GET-link') {
      // De cross-site GET krijgt het Strict-cookie niet mee — precies het probleem uit de review.
      const get = page.waitForRequest((r) => r.url().startsWith(`${api}/auth/magic-link/redeem?`));
      await clickFromOtherSite(page, href);
      expect((await (await get).allHeaders()).cookie || '').not.toContain('horsesafe_session');
    } else {
      await clickFromOtherSite(page, href);
    }
    // De same-site POST vanaf mfa.html stuurt het cookie wél mee
    expect((await (await posted).allHeaders()).cookie || '').toContain('horsesafe_session');
    await page.waitForURL(/vault\.html/, { timeout: 15_000 });
    expect(page.url()).not.toContain('ml=');
    const me = await (await page.request.get(`${api}/auth/me`)).json();
    expect(me.mfa_pass).toBe(true);
  });
}

test('magic-link zonder wachtwoord-login: geweigerd, niet verbruikt', async ({ page }) => {
  const { apiPort, webPort, dbPath } = stack!;
  const api = `http://localhost:${apiPort}`;
  const web = `http://localhost:${webPort}`;
  const email = `magic+nologin${Date.now()}@example.com`;
  await page.addInitScript((port) => { localStorage.setItem('horsesafe.devApiPort', String(port)); }, apiPort);
  await passwordSessionWithTotp(page, api, email);
  await page.request.post(`${api}/auth/magic-link`, { data: { email } });
  const token = latestToken(dbPath, email);
  await page.request.post(`${api}/auth/logout`);

  await clickFromOtherSite(page, `${web}/mfa.html#ml=${token}`);
  await page.waitForURL(/login\.html\?error=magic_link_login_first/, { timeout: 15_000 });
  await expect(page.locator('#login-error')).toContainText('Log eerst in deze browser in');
  expect((await page.request.get(`${api}/auth/me`)).status()).toBe(401);

  // Na een wachtwoord-login werkt dezelfde link alsnog
  await page.request.post(`${api}/auth/login`, { data: { email, password: ACCOUNT_PW } });
  await clickFromOtherSite(page, `${web}/mfa.html#ml=${token}`);
  await page.waitForURL(/vault\.html/, { timeout: 15_000 });
});
