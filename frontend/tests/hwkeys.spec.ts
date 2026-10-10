import { test, expect, type Page, type CDPSession } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * v0.2.0-Koblitz e2e — hardware-sleutels met een CDP virtual authenticator (docs/HARDWARE_KEYS.md §10 acc. 3).
 *
 * Start zelf een backend (uvicorn, vrije poort, tijdelijke DB) en een statische frontend (vrije poort):
 *   HORSESAFE_WEBAUTHN_RP_ID=localhost, HORSESAFE_WEBAUTHN_ORIGIN=http://localhost:<poort>,
 *   HORSESAFE_TEST_ATTESTATION=1 (virtuele authenticator heeft geen Yubico-attestation).
 * De frontend praat met die backend via localStorage 'horsesafe.devApiPort' (alleen dev).
 *
 * Omgeving:
 *   HS_PYTHON       python met de backend-deps (default: python3)
 *   HS_E2E_TMPDIR   map voor de tijdelijke DB/vaults (default: os.tmpdir())
 *
 * Flow: registreren + TOTP → kluis maken → noodsleutel koppelen (S) → Bio koppelen (SU via TOTP, want nog
 * geen Bio) → noodsleutel blokkeren en opheffen (SU alleen Bio) → vergrendelen → ontgrendelen met de Bio
 * → wachtwoord wijzigen (/rekey, SU) → oud wachtwoord faalt, Bio opent de nieuwe kopie, de OUDE kopie
 * opent de kluis niet meer ("Kopie verouderd").
 */

const REPO = resolve(__dirname, '..', '..');
const PYTHON = process.env.HS_PYTHON || 'python3';
const EMAIL = `hwkeys+${Date.now()}@example.com`;
const ACCOUNT_PW = 'HwKeysAccount1234!';
const VAULT_PW = 'VaultPw99!xyz';
const NEW_VAULT_PW = 'NieuwKluisWw-2026!';

let backend: ChildProcess | null = null;
let frontend: ChildProcess | null = null;
let tmp = '';
let apiPort = 0;
let webPort = 0;
let backendLog = '';

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once('error', fail);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      s.close(() => ok(port));
    });
  });
}

async function waitFor(url: string, timeoutMs = 30_000): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      /* nog niet klaar */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`${url} kwam niet op binnen ${timeoutMs} ms.\n--- backend-log ---\n${backendLog}`);
}

// Minimale TOTP (RFC 6238, SHA-1, 30 s) — zelfde aanpak als mfa.spec.ts
async function totpCode(secretBase32: string, at = Date.now()): Promise<string> {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secretBase32.replace(/=+$/, '').toUpperCase()) bits += ALPHABET.indexOf(c).toString(2).padStart(5, '0');
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setUint32(4, Math.floor(at / 1000 / 30), false);
  const key = await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const o = sig[sig.length - 1] & 0xf;
  const code = ((sig[o] & 0x7f) << 24) | (sig[o + 1] << 16) | (sig[o + 2] << 8) | sig[o + 3];
  return (code % 1_000_000).toString().padStart(6, '0');
}

/** Een code uit een nieuw 30-s-venster (servers weigeren vaak hergebruik van dezelfde code). */
async function freshTotp(secret: string, used: Set<string>): Promise<string> {
  for (;;) {
    const c = await totpCode(secret);
    if (!used.has(c)) { used.add(c); return c; }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

async function addAuthenticator(page: Page): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'usb',
      hasResidentKey: false,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, id: authenticatorId };
}

/**
 * De CDP virtual authenticator levert bij attestation:"direct" een packed SELF-attestation (geen x5c).
 * Die weigert de server terecht, ook met HORSESAFE_TEST_ATTESTATION=1 (die staat alleen fmt=none toe,
 * §12.4). Deze testshim laat de pagina ongemoeid, controleert dat de client "direct" vraagt, en zet het
 * verzoek alleen in de test om naar "none" zodat Chromium fmt=none teruggeeft.
 */
async function noneAttestationShim(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const orig = navigator.credentials.create.bind(navigator.credentials);
    (window as any).__hsAttestationRequested = [];
    navigator.credentials.create = (opts?: CredentialCreationOptions) => {
      if (opts && opts.publicKey) {
        (window as any).__hsAttestationRequested.push(opts.publicKey.attestation);
        opts = { ...opts, publicKey: { ...opts.publicKey, attestation: 'none' } };
      }
      return orig(opts);
    };
  });
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  tmp = mkdtempSync(join(process.env.HS_E2E_TMPDIR || tmpdir(), 'hs-hwkeys-e2e-'));
  apiPort = await freePort();
  webPort = await freePort();
  const origin = `http://localhost:${webPort}`;
  backend = spawn(PYTHON, ['-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', String(apiPort)], {
    cwd: REPO,
    env: {
      PATH: process.env.PATH || '/usr/bin:/bin',
      HOME: tmp,
      HORSESAFE_JWT_SECRET: randomBytes(32).toString('hex'),
      HORSESAFE_COOKIE_SECURE: 'false',
      HORSESAFE_CORS_ORIGINS: origin,
      HORSESAFE_RATE_LIMIT_ENABLED: 'false',
      HORSESAFE_DB_PATH: join(tmp, 'horsesafe.db'),
      HORSESAFE_VAULTS_DIR: join(tmp, 'vaults'),
      HORSESAFE_WEBAUTHN_RP_ID: 'localhost',
      HORSESAFE_WEBAUTHN_ORIGIN: origin,
      HORSESAFE_TEST_ATTESTATION: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const log = (b: Buffer) => { backendLog = (backendLog + b.toString()).slice(-20_000); };
  backend.stdout?.on('data', log);
  backend.stderr?.on('data', log);
  frontend = spawn(PYTHON, ['-m', 'http.server', String(webPort), '--bind', '127.0.0.1', '--directory', join(REPO, 'frontend')], {
    stdio: 'ignore',
  });
  await waitFor(`http://127.0.0.1:${apiPort}/health`);
  await waitFor(`http://127.0.0.1:${webPort}/vault.html`);
});

test.afterAll(async () => {
  backend?.kill('SIGTERM');
  frontend?.kill('SIGTERM');
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

test('Koblitz: koppelen, step-up, blokkeren, ontgrendelen, rekey en verouderde kopie', async ({ page }) => {
  test.setTimeout(240_000);
  const web = `http://localhost:${webPort}`;
  const usedCodes = new Set<string>();
  page.on('dialog', (d) => d.accept());
  await page.addInitScript((port) => { localStorage.setItem('horsesafe.devApiPort', String(port)); }, apiPort);
  await noneAttestationShim(page);

  // ── account + TOTP ──
  await page.goto(`${web}/index.html`);
  await addAuthenticator(page);
  await page.click('#show-register');
  await page.fill('#reg-email', EMAIL);
  await page.fill('#reg-pw', ACCOUNT_PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/, { timeout: 10_000 });
  await page.fill('#login-email', EMAIL);
  await page.fill('#login-pw', ACCOUNT_PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/, { timeout: 10_000 });

  await page.goto(`${web}/settings.html`);
  await expect(page.locator('#totp-status')).toHaveText('Niet ingeschakeld', { timeout: 10_000 });
  const setupP = page.waitForResponse((r) => r.url().includes('/auth/totp/setup') && r.status() === 200);
  await page.click('#totp-enable-btn');
  const totpSecret = (await (await setupP).json()).secret as string;
  await page.fill('#setup-code', await freshTotp(totpSecret, usedCodes));
  await page.click('#totp-verify-form button[type="submit"]');
  await expect(page.locator('#setup-success')).toBeVisible({ timeout: 10_000 });

  // ── kluis maken met wachtwoord ──
  await page.goto(`${web}/vault.html`);
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#vault-pw')).toHaveValue('');
  await page.click('#add-entry');
  await page.fill('#e-title', 'Bank');
  await page.fill('#e-pw', 'GeheimBank123!');
  await page.click('#edit-form button[type="submit"]');
  await expect(page.locator('#entry-count')).toHaveText('1', { timeout: 30_000 });

  // Het ontgrendelmateriaal in RAM is {ph, kh} als ProtectedValue — nooit het leesbare wachtwoord
  const secretShape = await page.evaluate(() => {
    const s = (window as any).HorseSafeVaultUI.state.secret;
    return { keys: Object.keys(s), phLen: s.ph.getBinary().length, kh: s.kh, pw: 'pw' in s || 'kf' in s };
  });
  expect(secretShape).toEqual({ keys: ['ph', 'kh'], phLen: 32, kh: null, pw: false });

  // ── noodsleutel koppelen (eerste sleutel: geen step-up) ──
  await page.click('#keys-open');
  await page.fill('#key-label', 'Noodsleutel test');
  const addRec = page.waitForResponse((r) => /\/vault\/[^/]+\/keys$/.test(r.url()) && r.request().method() === 'POST');
  await page.click('#key-add-recovery');
  const recRes = await addRec;
  expect(recRes.status(), await recRes.text()).toBe(201);
  const recKey = await recRes.json();
  expect(recKey.kind).toBe('recovery');
  // De POST bevat attestationObject + clientDataJSON en een Seal_v2-kopie, nooit pw/keyfile
  const recBody = recRes.request().postDataJSON();
  expect(Object.keys(recBody.create)).toEqual(expect.arrayContaining(['challenge_id', 'credential_id', 'client_data_json', 'attestation_object']));
  const sealedObj = JSON.parse(recBody.sealed);
  expect(Object.keys(sealedObj)).toEqual(['v', 'kid', 'epk', 'iv', 'ct']);
  expect(sealedObj.v).toBe(2);
  expect(sealedObj.kid).toBe(recBody.key_id);
  expect(JSON.stringify(recBody)).not.toContain(VAULT_PW);
  await expect(page.locator('#keys-status')).toContainText('gekoppeld');
  await expect(page.locator('#keys-body tr')).toHaveCount(1);

  // ── Bio koppelen: tweede sleutel → step-up; nog geen Bio → TOTP-veld ──
  await page.fill('#key-label', 'YubiKey Bio test');
  await page.click('#key-add-bio');
  await expect(page.locator('#stepup-totp-form')).toBeVisible({ timeout: 15_000 });
  const addBio = page.waitForResponse((r) => /\/vault\/[^/]+\/keys$/.test(r.url()) && r.request().method() === 'POST');
  await page.fill('#stepup-code', await freshTotp(totpSecret, usedCodes));
  await page.click('#stepup-totp-form button[type="submit"]');
  const bioRes = await addBio;
  expect(bioRes.status(), await bioRes.text()).toBe(201);
  await expect(page.locator('#stepup-section')).toBeHidden();
  await expect(page.locator('#keys-body tr')).toHaveCount(2);
  expect(await page.evaluate(() => (window as any).__hsAttestationRequested)).toEqual(['direct', 'direct']);

  // ── noodsleutel blokkeren (S) en opheffen (SU, alleen Bio — TOTP-step-up is niet genoeg) ──
  const recRow = page.locator(`#keys-body tr[data-key="${recKey.id}"]`);
  await recRow.locator('button[data-block]').click();
  await expect(recRow.locator('.key-status')).toContainText('geblokkeerd');
  const unblockOk = page.waitForResponse((r) => r.url().endsWith('/block') && r.request().method() === 'DELETE' && r.ok());
  await recRow.locator('button[data-unblock]').click();
  await unblockOk; // eerste DELETE → 403 stepup_bio_required → Bio-step-up (automatisch via authenticator) → opnieuw
  await expect(recRow.locator('.key-status')).toContainText('in de kluis');

  // ── vergrendelen en ontgrendelen met de Bio ──
  await page.click('#lock-vault');
  await expect(page.locator('#unlock-section')).toBeVisible();
  expect(await page.evaluate(() => (window as any).HorseSafeVaultUI.state.secret)).toBeNull();
  await expect(page.locator('#hwkey-unlock-btn')).toBeVisible({ timeout: 10_000 });
  const unlock1 = page.waitForResponse((r) => r.url().endsWith('/unlock') && r.request().method() === 'POST');
  await page.click('#hwkey-unlock-btn');
  const u1 = await unlock1;
  expect(u1.status(), await u1.text()).toBe(200);
  const oldSealed = (await u1.json()) as { id: string; sealed: string };
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('1');

  // ── wachtwoord wijzigen via /rekey ──
  await page.click('#keys-open');
  await page.fill('#rekey-pw', NEW_VAULT_PW);
  await page.fill('#rekey-pw2', NEW_VAULT_PW);
  const rekeyOk = page.waitForResponse((r) => r.url().endsWith('/rekey') && r.ok(), { timeout: 60_000 });
  await page.click('#rekey-submit');
  await rekeyOk;
  await expect(page.locator('#rekey-status')).toContainText('Gewijzigd', { timeout: 30_000 });

  // oud wachtwoord werkt niet meer, nieuw wel
  await page.click('#lock-vault');
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#unlock-error')).toContainText(/Verkeerd wachtwoord/, { timeout: 30_000 });
  await page.fill('#vault-pw', NEW_VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('1');

  // Bio opent de NIEUWE kopie
  await page.click('#lock-vault');
  await page.click('#hwkey-unlock-btn');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('1');

  // De OUDE kopie (van vóór de rekey) opent de kluis niet meer: we serveren hem terug op /unlock
  await page.click('#lock-vault');
  await page.route('**/unlock', async (route) => {
    const res = await route.fetch(); // echte assertion naar de server (challenge wordt verbruikt)
    expect(res.status()).toBe(200);
    await route.fulfill({ response: res, json: oldSealed });
  });
  await page.click('#hwkey-unlock-btn');
  await expect(page.locator('#unlock-error')).toContainText('Kopie verouderd', { timeout: 30_000 });
  await expect(page.locator('#vault-section')).toBeHidden();
  await page.unroute('**/unlock');
});

test('Koblitz: client faalt dicht bij gesynchroniseerde passkey (BE=1) en verkeerde host', async ({ page }) => {
  test.setTimeout(120_000);
  const web = `http://localhost:${webPort}`;
  page.on('dialog', (d) => d.accept());
  await page.addInitScript((port) => { localStorage.setItem('horsesafe.devApiPort', String(port)); }, apiPort);

  // Verkeerde host (127.0.0.1 i.p.v. de rpId): fail-closed met link naar icthorsecloud.nl
  await page.goto(`http://127.0.0.1:${webPort}/vault.html`);
  expect(await page.evaluate(() => (window as any).HorseSafeHwKeys.checkSupport()))
    .toEqual({ ok: false, reason: 'wrong_host', link: 'https://icthorsecloud.nl/HorseSafe/' });

  const email = `hwkeys-be+${Date.now()}@example.com`;
  await page.goto(`${web}/index.html`);
  await page.click('#show-register');
  await page.fill('#reg-email', email);
  await page.fill('#reg-pw', ACCOUNT_PW);
  await page.check('#reg-ack');
  await page.click('#register-submit');
  await page.waitForURL(/login\.html/, { timeout: 10_000 });
  await page.fill('#login-email', email);
  await page.fill('#login-pw', ACCOUNT_PW);
  await page.click('#login-submit');
  await page.waitForURL(/vault\.html/, { timeout: 10_000 });
  expect(await page.evaluate(() => (window as any).HorseSafeHwKeys.checkSupport())).toEqual({ ok: true, reason: null });
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });

  // Virtuele authenticator die zich als gesynchroniseerde passkey meldt (BE=1, BS=1)
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: false,
      hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true,
      defaultBackupEligibility: true, defaultBackupState: true,
    },
  });
  let posted = false;
  page.on('request', (r) => { if (/\/vault\/[^/]+\/keys$/.test(r.url()) && r.method() === 'POST') posted = true; });
  await page.click('#keys-open');
  await page.click('#key-add-bio');
  await expect(page.locator('#keys-error')).toContainText('gesynchroniseerde passkey', { timeout: 15_000 });
  expect(posted).toBe(false);
});
