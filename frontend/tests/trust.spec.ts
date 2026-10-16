import { test, expect, type Page, type Route } from '@playwright/test';
import { spawn, spawnSync } from 'node:child_process';
import {
  createCipheriv, createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync,
  randomBytes, randomUUID, verify as nodeVerify,
} from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startStack, freshTotp, REPO, PYTHON, type Stack } from './e2e-stack';

/**
 * v0.4.0-Montgomery e2e — vertrouwde browser + telefoonvinger (docs/HARDWARE_KEYS.md §14).
 *
 * Eigen backend (uvicorn, vrije poort, tijdelijke DB) + statische frontend via e2e-stack.ts; NOOIT :3997.
 *
 * Test 1 "nep-API": account, TOTP, kluis, keyfile (rekey) en step-up gaan naar de echte (geïsoleerde) backend;
 *   /trusted-browsers, /auth/browser/* en /vault/{vid}/approvals worden in de test nagebootst. De test speelt
 *   zelf server + telefoon (Node-crypto) en controleert: proof = HMAC(k_bind(CK), bind_t), sig_req en login-sig
 *   (P1363) kloppen met pub_B, step-up bij 403, afteller, goedgekeurd → kluis open, verlopen, annuleren (DELETE),
 *   verouderde kopie, geweigerd → uitgelogd, inloggen met TOTP, "Vergeet deze browser". Draait ook zolang de
 *   backend §14 nog niet heeft.
 *
 * Test 2/3 "neptoestel": volledig tegen de backend met de Python-helper (afspraak met de backend-kant):
 *     python -m backend.tests.fake_device approve --api <base> --state <file> [--decision approve|deny|deny_revoke] [--tamper-label]
 *   Wordt overgeslagen zolang fake_device.py `approve` of de §14-endpoints ontbreken.
 *
 * Omgeving: HS_PYTHON (python met backend-deps), HS_E2E_TMPDIR, HS_E2E_DEBUG, HS_FAKE_DEVICE_MODULE.
 */

const ACCOUNT_PW = 'TrustAccount1234!';
const VAULT_PW = 'VaultPw99!xyz';
const FAKE_MODULE = process.env.HS_FAKE_DEVICE_MODULE || 'backend.tests.fake_device';
const FAKE_PATH = join(REPO, ...FAKE_MODULE.split('.')) + '.py';

let stack: Stack | null = null;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  stack = await startStack('hs-trust-e2e-', (origin) => ({
    HORSESAFE_WEBAUTHN_RP_ID: 'localhost',
    HORSESAFE_WEBAUTHN_ORIGIN: origin,
    HORSESAFE_TEST_DEVICE_ATTESTATION: '1',
  }));
});

test.afterAll(async () => {
  stack?.stop();
});

// ───────────── server/telefoon-kant in Node (§14.2) ─────────────
const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString('base64url');
const unb64u = (s: string) => Buffer.from(s, 'base64url');

function ptCk(ph: string | null, kh: string | null): Buffer {
  const v = (x: string | null) => (x ? `"${x}"` : 'null');
  return Buffer.from(`{"ph":${v(ph)},"kh":${v(kh)}}`, 'utf8');
}

function proofOf(ck: { ph: string | null; kh: string }, vaultId: string, browserId: string, pubB: string, label: string): string {
  const salt = createHash('sha256').update(Buffer.concat([Buffer.from('HSv2 bind salt\0'), Buffer.from(vaultId)])).digest();
  const kb = Buffer.from(hkdfSync('sha256', ptCk(ck.ph, ck.kh), salt, Buffer.from('HSv2 browser bind'), 32));
  const t = Buffer.from(['HSv2 browser', vaultId, browserId, pubB, label].join('\0'), 'utf8');
  return b64u(createHmac('sha256', kb).update(t).digest());
}

function verifyP1363(pubB: string, msg: Buffer, sig: string): boolean {
  const key = createPublicKey({ key: unb64u(pubB), format: 'der', type: 'spki' });
  return nodeVerify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, unb64u(sig));
}

/** Seal_v2(epk_L, CK, "relay", vault_id, approval_id 0 nonce_L), kid = approval_id (§12.5). */
function sealRelay(epkL: string, ck: { ph: string | null; kh: string | null }, vaultId: string, approvalId: string, nonceL: string): string {
  const e = generateKeyPairSync('x25519');
  const epk = unb64u((e.publicKey.export({ format: 'jwk' }) as { x: string }).x);
  const P = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: epkL }, format: 'jwk' });
  const ss = diffieHellman({ privateKey: e.privateKey, publicKey: P });
  const k = Buffer.from(hkdfSync('sha256', ss, Buffer.concat([epk, unb64u(epkL)]), Buffer.from('HorseSafe v2 seal'), 32));
  const iv = randomBytes(12);
  const aad = Buffer.from(['HSv2', 'relay', vaultId, `${approvalId}\0${nonceL}`].join('\0'), 'utf8');
  const c = createCipheriv('aes-256-gcm', k, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(ptCk(ck.ph, ck.kh)), c.final(), c.getAuthTag()]);
  return JSON.stringify({ v: 2, kid: approvalId, epk: b64u(epk), iv: b64u(iv), ct: b64u(ct) });
}

// ───────────── gedeelde stappen ─────────────
async function preparePage(page: Page, apiPort: number) {
  const prodHits: string[] = [];
  await page.context().route(/^https?:\/\/(localhost|127\.0\.0\.1):3997\//, (route) => {
    prodHits.push(route.request().url());
    return route.abort();
  });
  page.on('dialog', (d) => d.accept());
  await page.addInitScript((port) => { localStorage.setItem('horsesafe.devApiPort', String(port)); }, apiPort);
  // Testhaak zonder productiecode (zoals pairing.spec.ts): QR-string uit pairing.js opvangen voor het neptoestel.
  await page.addInitScript(() => {
    let real: any;
    Object.defineProperty(window, 'HorseSafePairing', {
      configurable: true,
      get() { return real; },
      set(v) {
        const start = v.start;
        v.start = async (...a: any[]) => { const s = await start(...a); (window as any).__hsPairQr = s.qr; return s; };
        real = v;
      },
    });
  });
  if (process.env.HS_E2E_DEBUG) {
    page.on('console', (m) => console.log('[page]', m.type(), m.text()));
    page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  }
  return prodHits;
}

async function stepUpIfAsked(page: Page, totpSecret: string, used: Set<string>) {
  const form = page.locator('#stepup-totp-form');
  try {
    await form.waitFor({ state: 'visible', timeout: 8_000 });
  } catch {
    return; // step-up nog geldig
  }
  await page.fill('#stepup-code', await freshTotp(totpSecret, used));
  await page.click('#stepup-totp-form button[type="submit"]');
}

/**
 * Account + TOTP + kluis met wachtwoord, daarna een keyfile erbij (rekey met step-up): vertrouwen kan alleen bij
 * een kluis met keyfile (§11.3.7). Eindigt met open kluis en open sleutelpaneel. Geeft e-mail, TOTP-secret, CK.
 */
async function accountWithKeyfileVault(page: Page, web: string, used: Set<string>) {
  const email = `trust+${Date.now()}@example.com`;
  await page.goto(`${web}/index.html`);
  await page.click('#show-register');
  await page.fill('#reg-email', email);
  await page.fill('#reg-pw', ACCOUNT_PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/, { timeout: 10_000 });
  await expect(page.locator('#trusted-login')).toBeHidden();
  await page.fill('#login-email', email);
  await page.fill('#login-pw', ACCOUNT_PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/, { timeout: 10_000 });

  // Zonder TOTP: knop uit met uitleg (kluis met alleen wachtwoord → eerst de keyfile-uitleg)
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await page.click('#keys-open');
  await expect(page.locator('#trust-add')).toBeDisabled();
  await expect(page.locator('#trust-why')).toContainText('alleen bij een kluis met keyfile');
  await page.click('#lock-vault');

  await page.goto(`${web}/settings.html`);
  await expect(page.locator('#totp-status')).toHaveText('Niet ingeschakeld', { timeout: 10_000 });
  const setupP = page.waitForResponse((r) => r.url().includes('/auth/totp/setup') && r.status() === 200);
  await page.click('#totp-enable-btn');
  const totpSecret = (await (await setupP).json()).secret as string;
  await page.fill('#setup-code', await freshTotp(totpSecret, used));
  await page.click('#totp-verify-form button[type="submit"]');
  await expect(page.locator('#setup-success')).toBeVisible({ timeout: 10_000 });

  await page.goto(`${web}/vault.html`);
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await page.click('#keys-open');
  // Keyfile toevoegen (wachtwoord blijft): rekey
  const keyfile = randomBytes(100);
  await page.setInputFiles('#rekey-keyfile', { name: 'test.keyx', mimeType: 'application/octet-stream', buffer: keyfile });
  await page.click('#rekey-submit');
  await stepUpIfAsked(page, totpSecret, used);
  await expect(page.locator('#rekey-status')).toContainText('Gewijzigd', { timeout: 60_000 });
  const ck = await page.evaluate(() => {
    const s = (window as any).HorseSafeVaultUI.state.secret;
    const enc = (pv: any) => (pv ? btoa(String.fromCharCode(...pv.getBinary())).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : null);
    return { ph: enc(s.ph), kh: enc(s.kh) };
  });
  expect(ck.kh).toBeTruthy();
  expect(ck.ph).toBeTruthy();
  const vaultId = await page.evaluate(() => (window as any).HorseSafeVaultUI.state.vaultId as string);
  return { email, totpSecret, ck: ck as { ph: string; kh: string }, vaultId, keyfile };
}

/** Directe API-aanroep vanuit de pagina (met het sessiecookie). */
async function apiCall(page: Page, method: string, path: string, body?: unknown): Promise<{ status: number; error: string | null }> {
  return page.evaluate(async ([m, p, b]) => {
    const r = await fetch((window as any).HorseSafeAPI.base + p, {
      method: m as string, credentials: 'include',
      headers: b !== null ? { 'Content-Type': 'application/json' } : {},
      body: b !== null ? JSON.stringify(b) : undefined,
    });
    let d: any = null;
    try { d = await r.json(); } catch { /* geen JSON */ }
    return { status: r.status, error: (d && d.detail && d.detail.error) || null };
  }, [method, path, body === undefined ? null : body] as const);
}

async function idbRecords(page: Page): Promise<any[]> {
  return page.evaluate(async () => (await (window as any).HorseSafeTrust.listRecords())
    .map((r: any) => ({ browser_id: r.browser_id, vault_id: r.vault_id, email: r.email, label: r.label, extractable: r.key.extractable })));
}

// ───────────── test 1: nep-API voor §14 ─────────────
test('Montgomery: vertrouwen, ontgrendelen en inloggen tegen nagebootste §14-API (web-kant volledig)', async ({ page }) => {
  test.setTimeout(Number(process.env.HS_E2E_TIMEOUT || 300_000));
  const { apiPort, webPort } = stack!;
  const web = `http://localhost:${webPort}`;
  const used = new Set<string>();
  const prodHits = await preparePage(page, apiPort);

  type Call = { method: string; path: string; body: any };
  const calls: Call[] = [];
  const browsers = new Map<string, any>();
  let trustPosts = 0;
  let ck: { ph: string; kh: string } = { ph: '', kh: '' };
  // decision per verzoek: 'approve' | 'deny' | 'expire' | 'stale' | 'hold'
  let decision = 'approve';
  const approvals = new Map<string, any>();
  const challenges = new Map<string, any>();
  let loginOk = true;
  const mockErrors: string[] = [];
  const cors = {
    'Access-Control-Allow-Origin': web,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  const reply = (route: Route, status: number, json?: unknown) => route.fulfill({
    status, headers: { ...cors, ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: json !== undefined ? JSON.stringify(json) : undefined,
  });
  const now = () => Math.floor(Date.now() / 1000);

  await page.context().route(new RegExp(`^http://localhost:${apiPort}/(trusted-browsers|auth/browser|vault/[^/]+/approvals)(/.*)?(\\?.*)?$`), async (route) => {
    const req = route.request();
    const method = req.method();
    if (method === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
    const url = new URL(req.url());
    const path = url.pathname;
    const body = req.postData() ? req.postDataJSON() : undefined;
    calls.push({ method, path: path + url.search, body });
    let m: RegExpExecArray | null;
    if (path === '/trusted-browsers' && method === 'POST') {
      trustPosts += 1;
      if (trustPosts === 1) return reply(route, 403, { detail: { error: 'stepup_required' } });
      browsers.set(body.browser_id, { ...body, created_at: now(), last_used_at: null });
      return reply(route, 201, { browser_id: body.browser_id, created_at: now() });
    }
    if (path === '/trusted-browsers' && method === 'GET') {
      return reply(route, 200, { browsers: [...browsers.values()].map((b) => ({
        browser_id: b.browser_id, vault_id: b.vault_id, label: b.label, created_at: b.created_at, last_used_at: b.last_used_at,
      })) });
    }
    if ((m = /^\/trusted-browsers\/([^/]+)$/.exec(path)) && method === 'DELETE') {
      browsers.delete(m[1]);
      return reply(route, 204);
    }
    if (path === '/auth/browser/challenge') {
      const id = randomUUID();
      const challenge = b64u(randomBytes(32));
      challenges.set(id, { email: body.email, challenge });
      return reply(route, 200, { challenge_id: id, challenge, expires_at: now() + 120 });
    }
    if (path === '/auth/browser/login') {
      const c = challenges.get(body.challenge_id);
      challenges.delete(body.challenge_id);
      const b = browsers.get(body.browser_id);
      const t = Buffer.from(['HSv2 blogin', body.challenge_id, c?.challenge ?? '', body.browser_id, c?.email ?? ''].join('\0'));
      const ok = !!c && !!b && loginOk && verifyP1363(b.pub_B, t, body.sig) && /^\d{6}$/.test(body.totp);
      return ok ? reply(route, 200, { ok: true, mfa_required: false }) : reply(route, 401, { detail: { error: 'browser_login_failed' } });
    }
    if ((m = /^\/vault\/([^/]+)\/approvals$/.exec(path)) && method === 'POST') {
      const id = randomUUID();
      approvals.set(id, { vaultId: m[1], browser_id: body.browser_id, created_at: now(), status: 'draft', polls: 0 });
      return reply(route, 201, { approval_id: id, created_at: approvals.get(id).created_at });
    }
    if ((m = /^\/vault\/([^/]+)\/approvals\/([^/]+)$/.exec(path))) {
      const a = approvals.get(m[2]);
      if (!a) return reply(route, 404, { detail: { error: 'not_found' } });
      if (method === 'PUT') {
        const b = browsers.get(a.browser_id);
        const t = Buffer.from(['HSv2 approve', m[2], a.vaultId, a.browser_id, body.epk_L, body.nonce_L, String(a.created_at)].join('\0'));
        if (!b || !verifyP1363(b.pub_B, t, body.sig_req)) return reply(route, 400, { detail: { error: 'signature_invalid' } });
        Object.assign(a, { status: 'pending', epk: body.epk_L, nonce: body.nonce_L, expires_at: now() + 120 });
        return reply(route, 200, { expires_at: a.expires_at });
      }
      if (method === 'DELETE') { a.status = 'cancelled'; return reply(route, 204); }
      if (method === 'GET') {
        if (!/^\d+$/.test(url.searchParams.get('wait') || '')) mockErrors.push(`GET zonder wait: ${url.search}`);
        a.polls += 1;
        if (a.status === 'consumed') return reply(route, 410, { detail: { error: 'gone' } });
        if (a.status !== 'pending' || a.polls < 2 || decision === 'hold') {
          await new Promise((r) => setTimeout(r, 300)); // korte "long-poll"
          return reply(route, 200, { status: a.status });
        }
        if (decision === 'deny') { a.status = 'denied'; return reply(route, 200, { status: 'denied' }); }
        if (decision === 'expire') { a.status = 'expired'; return reply(route, 200, { status: 'expired' }); }
        // De telefoon controleert het koppelbewijs met CK (zoals de app na de vinger)
        const b = browsers.get(a.browser_id);
        if (proofOf(ck, a.vaultId, b.browser_id, b.pub_B, b.label) !== b.proof) {
          mockErrors.push('proof klopt niet');
          a.status = 'denied';
          return reply(route, 200, { status: 'denied' });
        }
        const sealCk = decision === 'stale' ? { ph: b64u(randomBytes(32)), kh: ck.kh } : ck;
        a.status = 'consumed';
        return reply(route, 200, { status: 'approved', resp: sealRelay(a.epk, sealCk, a.vaultId, m[2], a.nonce) });
      }
    }
    return reply(route, 404, { detail: { error: 'not_found' } });
  });

  const acct = await accountWithKeyfileVault(page, web, used);
  ck = acct.ck;

  // ── 1. Vertrouwen: 403 → step-up → POST met geldig proof; K_B niet exporteerbaar in IndexedDB ──
  await expect(page.locator('#trust-label')).toHaveValue(/^Chrome – /);
  await page.fill('#trust-label', 'Chrome – testlaptop');
  await expect(page.locator('#trust-add')).toBeEnabled();
  await page.click('#trust-add');
  await stepUpIfAsked(page, acct.totpSecret, used);
  await expect(page.locator('#trust-status')).toContainText('vertrouwd als "Chrome – testlaptop"', { timeout: 20_000 });
  expect(trustPosts).toBe(2);
  const post = calls.filter((c) => c.method === 'POST' && c.path === '/trusted-browsers').at(-1)!.body;
  expect(Object.keys(post).sort()).toEqual(['browser_id', 'label', 'proof', 'pub_B', 'vault_id']);
  expect(post.vault_id).toBe(acct.vaultId);
  expect(post.browser_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect(unb64u(post.pub_B).length).toBe(91);
  expect(post.proof).toBe(proofOf(ck, acct.vaultId, post.browser_id, post.pub_B, 'Chrome – testlaptop'));
  expect(JSON.stringify(calls)).not.toContain(ck.kh);
  const recs = await idbRecords(page);
  expect(recs).toEqual([{ browser_id: post.browser_id, vault_id: acct.vaultId, email: acct.email, label: 'Chrome – testlaptop', extractable: false }]);
  await expect(page.locator(`#trust-body tr[data-browser="${post.browser_id}"]`)).toContainText('(deze browser)');
  await expect(page.locator('#trust-add')).toBeHidden();
  await expect(page.locator('#trust-forget')).toBeVisible();

  // ── 2. Vergrendelen → "Ontgrendel met telefoon" → goedgekeurd → kluis open ──
  await page.click('#lock-vault');
  await expect(page.locator('#phone-unlock-btn')).toBeVisible({ timeout: 10_000 });
  decision = 'approve';
  await page.click('#phone-unlock-btn');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 60_000 });
  const put = calls.filter((c) => c.method === 'PUT').at(-1)!.body;
  expect(Object.keys(put).sort()).toEqual(['epk_L', 'nonce_L', 'sig_req']);
  expect(unb64u(put.nonce_L).length).toBe(32);
  expect(unb64u(put.sig_req).length).toBe(64);
  expect(calls.some((c) => c.method === 'GET' && /approvals\/[^/?]+\?wait=25$/.test(c.path))).toBe(true);

  // ── 3. Annuleren tijdens het wachten → DELETE ──
  await page.click('#lock-vault');
  await expect(page.locator('#phone-unlock-btn')).toBeVisible({ timeout: 10_000 });
  decision = 'hold';
  await page.click('#phone-unlock-btn');
  await expect(page.locator('#phone-unlock-wait')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('#phone-unlock-status')).toContainText('Open HorseSafe op je telefoon');
  await expect(page.locator('#phone-unlock-countdown')).toHaveText(/^(2:00|1:5\d)$/);
  await page.click('#phone-unlock-cancel');
  await expect(page.locator('#phone-unlock-status')).toContainText('geannuleerd');
  await expect.poll(() => calls.filter((c) => c.method === 'DELETE' && /\/approvals\//.test(c.path)).length).toBe(1);

  // ── 4. Verlopen → "Geen reactie, probeer opnieuw" ──
  decision = 'expire';
  await page.click('#phone-unlock-btn');
  await expect(page.locator('#phone-unlock-error')).toContainText('Geen reactie, probeer opnieuw', { timeout: 20_000 });

  // ── 5. Kopie verouderd (CK past niet op de KDBX) → zelfde melding als de hwkeys-flow ──
  decision = 'stale';
  await page.click('#phone-unlock-btn');
  await expect(page.locator('#unlock-error')).toContainText('Kopie verouderd', { timeout: 60_000 });
  await expect(page.locator('#vault-section')).toBeHidden();

  // ── 6. Geweigerd → "Geweigerd op je telefoon" → uitgelogd ──
  decision = 'deny';
  await page.click('#phone-unlock-btn');
  await expect(page.locator('#phone-unlock-error')).toContainText('Geweigerd op je telefoon', { timeout: 20_000 });
  await page.waitForURL(/login\.html\?error=approval_denied/, { timeout: 15_000 });
  await expect(page.locator('#login-error')).toContainText('Geweigerd op je telefoon');

  // ── 7. Inloggen op de vertrouwde browser: e-mail vooringevuld, alleen TOTP ──
  await expect(page.locator('#trusted-login')).toBeVisible();
  await expect(page.locator('#trusted-email')).toHaveValue(acct.email);
  loginOk = false;
  await page.fill('#trusted-code', '000000');
  await page.click('#trusted-submit');
  await expect(page.locator('#trusted-error')).toContainText('Inloggen met deze browser lukte niet');
  loginOk = true;
  await page.fill('#trusted-code', await freshTotp(acct.totpSecret, used));
  await page.click('#trusted-submit');
  await page.waitForURL(/vault\.html/, { timeout: 10_000 });
  const login = calls.filter((c) => c.path === '/auth/browser/login').at(-1)!.body;
  expect(Object.keys(login).sort()).toEqual(['browser_id', 'challenge_id', 'sig', 'totp']);
  expect(calls.filter((c) => c.path === '/auth/browser/challenge').at(-1)!.body).toEqual({ email: acct.email.toLowerCase() });

  // ── 8. Vergeet deze browser: lokaal weg + DELETE (opnieuw inloggen met wachtwoord; mock-login zet geen cookie) ──
  await page.goto(`${web}/login.html`);
  await page.fill('#login-email', acct.email);
  await page.fill('#login-pw', ACCOUNT_PW);
  await page.click('#login-submit');
  await page.waitForURL(/(mfa|vault)\.html/, { timeout: 10_000 });
  if (page.url().includes('mfa.html')) {
    await page.fill('#totp-code', await freshTotp(acct.totpSecret, used));
    await page.click('#totp-submit');
    await page.waitForURL(/vault\.html/, { timeout: 10_000 });
  }
  await expect(page.locator('#phone-unlock-btn')).toBeVisible({ timeout: 10_000 });
  decision = 'approve';
  await page.click('#phone-unlock-btn');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 60_000 });
  await page.click('#keys-open');
  await expect(page.locator('#trust-forget')).toBeVisible({ timeout: 10_000 });
  await page.click('#trust-forget');
  await expect(page.locator('#trust-status')).toContainText('vergeten en ingetrokken');
  expect(calls.some((c) => c.method === 'DELETE' && c.path === `/trusted-browsers/${post.browser_id}`)).toBe(true);
  expect(await idbRecords(page)).toEqual([]);
  await expect(page.locator('#trust-add')).toBeVisible();
  await page.click('#lock-vault');
  await expect(page.locator('#phone-unlock')).toBeHidden();

  await page.context().unrouteAll({ behavior: 'ignoreErrors' });
  expect(mockErrors).toEqual([]);
  expect(prodHits, 'e2e mag nooit de productie-backend op :3997 raken').toEqual([]);
});

// ───────────── test 2/3: echte backend + neptoestel (fake_device.py approve) ─────────────
function fake(args: string[]): any {
  const r = spawnSync(PYTHON, ['-m', FAKE_MODULE, ...args], { cwd: REPO, encoding: 'utf8', timeout: 60_000 });
  if (r.status !== 0) throw new Error(`fake_device ${args[0]} faalde (${r.status}):\n${r.stdout}\n${r.stderr}`);
  return JSON.parse(r.stdout.trim().split('\n').at(-1) || 'null');
}

function fakeAsync(args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    const p = spawn(PYTHON, ['-m', FAKE_MODULE, ...args], { cwd: REPO });
    let out = '';
    let err = '';
    p.stdout.on('data', (b) => { out += b.toString(); });
    p.stderr.on('data', (b) => { err += b.toString(); });
    const timer = setTimeout(() => p.kill('SIGTERM'), 90_000);
    p.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) { reject(new Error(`fake_device ${args[0]} faalde (${code}):\n${out}\n${err}`)); return; }
      try { resolve(JSON.parse(out.trim().split('\n').at(-1) || 'null')); } catch (e) { reject(e); }
    });
  });
}

function backendReady(): string | null {
  if (!existsSync(FAKE_PATH)) return `${FAKE_PATH} ontbreekt`;
  const r = spawnSync(PYTHON, ['-m', FAKE_MODULE, 'approve', '--help'], { cwd: REPO, encoding: 'utf8', timeout: 30_000 });
  if (r.status !== 0) return 'fake_device kent "approve" nog niet (backend-kant §14 niet klaar)';
  return null;
}

async function endpointsReady(apiPort: number): Promise<string | null> {
  const r = await fetch(`http://127.0.0.1:${apiPort}/trusted-browsers`);
  if (r.status === 404) return '/trusted-browsers bestaat nog niet (backend-kant §14 niet klaar)';
  const health = await (await fetch(`http://127.0.0.1:${apiPort}/health`)).json();
  if (health.test_device_attestation !== true) return 'backend draait zonder test_device_attestation';
  return null;
}

/** Telefoon koppelen met het neptoestel (zoals pairing.spec.ts test 2). Kluis open, sleutelpaneel open. */
async function pairFakePhone(page: Page, api: string, state: string, totpSecret: string, used: Set<string>) {
  await page.click('#phone-pair');
  await stepUpIfAsked(page, totpSecret, used);
  await expect(page.locator('#pair-step-qr')).toBeVisible({ timeout: 15_000 });
  const qr = await page.evaluate(() => (window as any).__hsPairQr as string);
  const claimed = fake(['claim', '--api', api, '--qr', qr, '--label', 'Neptoestel', '--model', 'Pixel Test', '--state', state]);
  await expect(page.locator('#pair-sas')).toHaveText(`${claimed.sas.slice(0, 3)} ${claimed.sas.slice(3)}`, { timeout: 15_000 });
  await page.click('#pair-sas-ok');
  await expect(page.locator('#pair-status')).toContainText('gekoppeld', { timeout: 30_000 });
}

async function realSetup(page: Page, web: string, api: string, state: string, used: Set<string>) {
  const acct = await accountWithKeyfileVault(page, web, used);
  await pairFakePhone(page, api, state, acct.totpSecret, used);
  await page.fill('#trust-label', 'Chrome – e2e');
  await page.click('#trust-add');
  await stepUpIfAsked(page, acct.totpSecret, used);
  await expect(page.locator('#trust-status')).toContainText('vertrouwd als "Chrome – e2e"', { timeout: 20_000 });
  return acct;
}

test('Montgomery: vertrouwen → uitloggen → inloggen met TOTP → ontgrendelen met neptoestel; weigeren → uitgelogd', async ({ page }) => {
  const why = backendReady();
  test.skip(!!why, why || '');
  test.setTimeout(Number(process.env.HS_E2E_TIMEOUT || 300_000));
  const { apiPort, webPort } = stack!;
  const notReady = await endpointsReady(apiPort);
  test.skip(!!notReady, notReady || '');
  const api = `http://127.0.0.1:${apiPort}`;
  const web = `http://localhost:${webPort}`;
  const used = new Set<string>();
  const prodHits = await preparePage(page, apiPort);
  const tmp = mkdtempSync(join(process.env.HS_E2E_TMPDIR || tmpdir(), 'hs-fake-trust-'));
  const state = join(tmp, 'device.json');
  try {
    const acct = await realSetup(page, web, api, state, used);

    // Uitloggen → login.html toont de vertrouwde-browserlogin; alleen TOTP
    await page.click('#logout-from-vault');
    await page.goto(`${web}/login.html`);
    await expect(page.locator('#trusted-login')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#trusted-email')).toHaveValue(acct.email);
    await page.fill('#trusted-code', await freshTotp(acct.totpSecret, used));
    await page.click('#trusted-submit');
    await page.waitForURL(/vault\.html/, { timeout: 10_000 });

    // H1: vóór goedkeuring op de telefoon is de sessie beperkt (scope browser_pending)
    expect(await apiCall(page, 'GET', '/auth/me')).toMatchObject({ status: 200 });
    expect(await apiCall(page, 'GET', '/vault')).toMatchObject({ status: 200 });
    expect(await apiCall(page, 'PUT', `/vault/${acct.vaultId}`, {})).toEqual({ status: 403, error: 'phone_approval_required' });
    expect(await apiCall(page, 'GET', '/shares/inbox')).toEqual({ status: 403, error: 'phone_approval_required' });
    expect(await apiCall(page, 'POST', '/auth/totp/setup', {})).toEqual({ status: 403, error: 'phone_approval_required' });
    // vault.html laden doet alleen toegestane aanroepen (geen melding)
    await page.goto(`${web}/vault.html`); // verse pagina: de apiCall's hierboven tonen zelf al de melding
    await expect(page.locator('#phone-unlock-btn')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#hs-session-notice')).toHaveCount(0);
    // Openen met wachtwoord + keyfile kan lokaal, maar opslaan wordt netjes geweigerd tot de telefoon goedkeurt
    await page.fill('#vault-pw', VAULT_PW);
    await page.setInputFiles('#vault-keyfile', { name: 'test.keyx', mimeType: 'application/octet-stream', buffer: acct.keyfile });
    await page.click('#unlock-submit');
    await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
    await page.click('#add-entry');
    await page.fill('#e-title', 'Voor telefoon');
    await page.click('#edit-form button[type="submit"]');
    await expect(page.locator('#global-error')).toContainText('ontgrendel eerst met je telefoon', { timeout: 10_000 });
    await expect(page.locator('#hs-session-notice')).toContainText('Ontgrendel eerst met je telefoon');
    await page.click('#e-cancel');
    await page.click('#lock-vault');

    // Ontgrendelen met de telefoon: neptoestel keurt goed
    await expect(page.locator('#phone-unlock-btn')).toBeVisible({ timeout: 10_000 });
    await page.click('#phone-unlock-btn');
    await expect(page.locator('#phone-unlock-wait')).toBeVisible({ timeout: 15_000 });
    const res = await fakeAsync(['approve', '--api', api, '--state', state, '--decision', 'approve']);
    expect(res).toBeTruthy();
    await expect(page.locator('#vault-section')).toBeVisible({ timeout: 60_000 });

    // Na goedkeuring: volledige sessie (cookie uit de approved-respons)
    expect(await apiCall(page, 'GET', '/shares/inbox')).toMatchObject({ status: 200 });
    const put = await apiCall(page, 'PUT', `/vault/${acct.vaultId}`, {});
    expect(put.error).not.toBe('phone_approval_required');
    expect(put.status).not.toBe(403);
    // Opslaan via de UI werkt nu ook
    await page.click('#add-entry');
    await page.fill('#e-title', 'Na telefoon');
    await page.click('#edit-form button[type="submit"]');
    await expect(page.locator('#entries-body')).toContainText('Na telefoon', { timeout: 15_000 });
    await expect(page.locator('#global-error')).toBeHidden();
    // Beheer blijft dicht voor een vertrouwde-browsersessie
    expect((await apiCall(page, 'GET', '/admin/stats')).status).toBe(403);

    // Weigeren → uitgelogd
    await page.click('#lock-vault');
    await page.click('#phone-unlock-btn');
    await expect(page.locator('#phone-unlock-wait')).toBeVisible({ timeout: 15_000 });
    await fakeAsync(['approve', '--api', api, '--state', state, '--decision', 'deny']);
    await expect(page.locator('#phone-unlock-error')).toContainText('Geweigerd op je telefoon', { timeout: 40_000 });
    await page.waitForURL(/login\.html\?error=approval_denied/, { timeout: 15_000 });
    // Sessie is ingetrokken: vault.html stuurt terug naar inloggen
    const me = await page.evaluate(async () => (await (window as any).HorseSafeAPI.me()).status);
    expect(me).toBe(401);
    expect(prodHits).toEqual([]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('Montgomery: gemanipuleerd label → telefoon weigert → uitgelogd; vergeten na browser-login → uitgelogd', async ({ page }) => {
  const why = backendReady();
  test.skip(!!why, why || '');
  test.setTimeout(Number(process.env.HS_E2E_TIMEOUT || 300_000));
  const { apiPort, webPort } = stack!;
  const notReady = await endpointsReady(apiPort);
  test.skip(!!notReady, notReady || '');
  const api = `http://127.0.0.1:${apiPort}`;
  const web = `http://localhost:${webPort}`;
  const used = new Set<string>();
  const prodHits = await preparePage(page, apiPort);
  const tmp = mkdtempSync(join(process.env.HS_E2E_TMPDIR || tmpdir(), 'hs-fake-trust-'));
  const state = join(tmp, 'device.json');
  try {
    const acct = await realSetup(page, web, api, state, used);
    await page.click('#lock-vault');
    await page.click('#phone-unlock-btn');
    await expect(page.locator('#phone-unlock-wait')).toBeVisible({ timeout: 15_000 });
    await fakeAsync(['approve', '--api', api, '--state', state, '--tamper-label']);
    await expect(page.locator('#phone-unlock-error')).toContainText('Geweigerd op je telefoon', { timeout: 40_000 });
    await page.waitForURL(/login\.html\?error=approval_denied/, { timeout: 15_000 });
    await expect(page.locator('#vault-section')).toHaveCount(0);

    // Opnieuw inloggen via de vertrouwde browser (nieuwe TOTP-tijdstap), kluis openen met wachtwoord + keyfile
    // (telefoon heeft cooldown), dan "Vergeet deze browser" → sessie ingetrokken → terug naar inloggen.
    await expect(page.locator('#trusted-login')).toBeVisible({ timeout: 10_000 });
    await page.fill('#trusted-code', await freshTotp(acct.totpSecret, used));
    await page.click('#trusted-submit');
    await page.waitForURL(/vault\.html/, { timeout: 10_000 });
    await page.fill('#vault-pw', VAULT_PW);
    await page.setInputFiles('#vault-keyfile', { name: 'test.keyx', mimeType: 'application/octet-stream', buffer: acct.keyfile });
    await page.click('#unlock-submit');
    await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
    await page.click('#keys-open');
    await expect(page.locator('#trust-forget')).toBeVisible({ timeout: 10_000 });
    await page.click('#trust-forget');
    await page.waitForURL(/login\.html\?error=session_revoked/, { timeout: 15_000 });
    await expect(page.locator('#login-error')).toContainText('Je bent uitgelogd');
    await expect(page.locator('#trusted-login')).toBeHidden();
    expect(await idbRecords(page)).toEqual([]);
    expect((await page.evaluate(async () => (await (window as any).HorseSafeAPI.me()).status))).toBe(401);
    expect(prodHits).toEqual([]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
