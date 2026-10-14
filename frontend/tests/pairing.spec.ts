import { test, expect, type Page, type Route } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { createHmac, createHash, hkdfSync, generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startStack, freshTotp, REPO, PYTHON, type Stack } from './e2e-stack';

/**
 * v0.3.4-Miller e2e — telefoon koppelen (S17, docs/HARDWARE_KEYS.md §13.3).
 *
 * Eigen backend (uvicorn, vrije poort, tijdelijke DB) + statische frontend via e2e-stack.ts; NOOIT :3997
 * (productie op HC55; elk verzoek daarheen breekt af en laat de test falen).
 *
 * Test 1 "nep-API": login, TOTP, kluis en step-up gaan naar de echte (geïsoleerde) backend; alleen de
 *   /devices-endpoints worden in de test nagebootst. De test speelt zelf de app (HKDF/HMAC in Node) en
 *   controleert: s gaat nooit naar de server, step-up bij 403, QR + aftelling, mac_web fout → DELETE +
 *   "Koppeling niet vertrouwd", "Klopt niet" → DELETE, "Klopt" → Seal_v2 (kid = key_id) + vastleggen in de
 *   kluis + confirm, telefoonrij met toestel/model, toestel verwijderen via DELETE /devices/{id}, Annuleren.
 *   Draait ook zolang de backend §13 nog niet heeft.
 *
 * Test 2 "neptoestel": volledig tegen de backend met HORSESAFE_TEST_DEVICE_ATTESTATION=1 en de Python-helper
 *   backend/tests/fake_device.py die als app claimt en device-requests tekent. Verwachte CLI (afspraak met de
 *   backend-kant; pas HS_FAKE_DEVICE_MODULE aan als de module anders heet):
 *     python -m backend.tests.fake_device claim  --api <base> --qr <hs1p:…> --label <l> --model <m> --state <file>
 *       → stdout (laatste regel) JSON {"device_id": "...", "sas": "123456", ...}
 *     python -m backend.tests.fake_device status --api <base> --state <file>
 *       → stdout (laatste regel) JSON {"device_id": "...", "state": "pending|active|revoked", "keys": [...]}
 *   Wordt overgeslagen zolang fake_device.py of de /devices-endpoints ontbreken.
 *
 * Omgeving: HS_PYTHON (python met backend-deps), HS_E2E_TMPDIR, HS_E2E_DEBUG.
 */

const ACCOUNT_PW = 'PairAccount1234!';
const VAULT_PW = 'VaultPw99!xyz';
const FAKE_MODULE = process.env.HS_FAKE_DEVICE_MODULE || 'backend.tests.fake_device';
const FAKE_PATH = join(REPO, ...FAKE_MODULE.split('.')) + '.py';

let stack: Stack | null = null;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  stack = await startStack('hs-pair-e2e-', (origin) => ({
    HORSESAFE_WEBAUTHN_RP_ID: 'localhost',
    HORSESAFE_WEBAUTHN_ORIGIN: origin,
    HORSESAFE_TEST_DEVICE_ATTESTATION: '1',
  }));
});

test.afterAll(async () => {
  stack?.stop();
});

// ───────────── app-kant in Node (§13.1) ─────────────
const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString('base64url');
const hkdf = (s: Buffer, info: string) => Buffer.from(hkdfSync('sha256', s, Buffer.alloc(32), Buffer.from(info), 32));

function parseQr(qr: string): { pairingId: string; s: Buffer } {
  const m = /^hs1p:([0-9a-f-]{36})\.([A-Za-z0-9_-]{22})$/.exec(qr);
  expect(m, `QR-vorm: ${qr}`).not.toBeNull();
  const s = Buffer.from(m![2], 'base64url');
  expect(s.length).toBe(16);
  return { pairingId: m![1], s };
}

interface Fields { pairing_id: string; pk_c: string; k_dev_pub: string; k_biosig_pub: string; label: string; model: string; app_version: string }

function transcript(f: Fields): Buffer {
  return Buffer.from(['HSv2 pair', f.pairing_id, f.pk_c, f.k_dev_pub, f.k_biosig_pub, f.label, f.model, f.app_version].join('\0'), 'utf8');
}
function sas(t: Buffer): string {
  const d = createHash('sha256').update(Buffer.concat([Buffer.from('HSv2 pair sas\0'), t])).digest();
  return String(d.readUInt32BE(0) % 1_000_000).padStart(6, '0');
}

/** De "app": claim met echte mac_web (of bewust met k_srv = wat een kwaadwillende server zou kunnen). */
function makeClaim(qr: string, label: string, { evil = false } = {}) {
  const { pairingId, s } = parseQr(qr);
  const kSrv = hkdf(s, 'HSv2 pair srv');
  const kWeb = hkdf(s, 'HSv2 pair web');
  const { publicKey } = generateKeyPairSync('x25519');
  const pk = (publicKey.export({ format: 'jwk' }) as { x: string }).x;
  const fields: Fields = {
    pairing_id: pairingId,
    pk_c: pk,
    k_dev_pub: b64u(Buffer.alloc(91, 1)),
    k_biosig_pub: b64u(Buffer.alloc(91, 2)),
    label,
    model: 'SM-F956B',
    app_version: '0.3.4-Miller',
  };
  const t = transcript(fields);
  const macWeb = createHmac('sha256', evil ? kSrv : kWeb).update(t).digest();
  const { pairing_id: _p, ...rest } = fields;
  return {
    kSrv: b64u(kSrv),
    sas: sas(t),
    claim: {
      device_id: randomUUID(),
      key_id: randomUUID(),
      ...rest,
      mac_web: b64u(macWeb),
      security_level: 'StrongBox',
      strongbox: true,
    },
  };
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
  // Testhaak zonder productiecode: vang de QR-string op uit de sessie die pairing.js teruggeeft.
  await page.addInitScript(() => {
    let real: any;
    Object.defineProperty(window, 'HorseSafePairing', {
      configurable: true,
      get() { return real; },
      set(v) {
        const start = v.start;
        v.start = async (...a: any[]) => {
          const s = await start(...a);
          (window as any).__hsPairQr = s.qr;
          return s;
        };
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

/** Account + TOTP + kluis met wachtwoord; eindigt in het sleutelpaneel. Geeft het TOTP-secret. */
async function accountWithVault(page: Page, web: string, usedCodes: Set<string>): Promise<string> {
  const email = `pair+${Date.now()}@example.com`;
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

  await page.goto(`${web}/settings.html`);
  await expect(page.locator('#totp-status')).toHaveText('Niet ingeschakeld', { timeout: 10_000 });
  const setupP = page.waitForResponse((r) => r.url().includes('/auth/totp/setup') && r.status() === 200);
  await page.click('#totp-enable-btn');
  const totpSecret = (await (await setupP).json()).secret as string;
  await page.fill('#setup-code', await freshTotp(totpSecret, usedCodes));
  await page.click('#totp-verify-form button[type="submit"]');
  await expect(page.locator('#setup-success')).toBeVisible({ timeout: 10_000 });

  await page.goto(`${web}/vault.html`);
  await page.fill('#vault-pw', VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await page.click('#keys-open');
  await expect(page.locator('#phone-pair')).toBeEnabled();
  return totpSecret;
}

async function waitForQr(page: Page): Promise<string> {
  await expect(page.locator('#pair-step-qr')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('#pair-qr svg path')).toHaveCount(1);
  const qr = await page.evaluate(() => (window as any).__hsPairQr as string);
  parseQr(qr);
  return qr;
}

// ───────────── test 1: nep-API voor /devices ─────────────
test('Miller deel 2: koppelflow tegen nagebootste /devices-API (web-kant volledig)', async ({ page }) => {
  test.setTimeout(Number(process.env.HS_E2E_TIMEOUT || 180_000));
  const { apiPort, webPort } = stack!;
  const web = `http://localhost:${webPort}`;
  const usedCodes = new Set<string>();
  const prodHits = await preparePage(page, apiPort);

  // Nagebootste server-toestand
  type Call = { method: string; path: string; body: any };
  const calls: Call[] = [];
  let postCount = 0;
  const pairings = new Map<string, { kSrv: string; status: string; claim: any }>();
  let phoneKey: any = null;
  const cors = {
    'Access-Control-Allow-Origin': web,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  const reply = (route: Route, status: number, json?: unknown) => route.fulfill({
    status, headers: { ...cors, ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: json !== undefined ? JSON.stringify(json) : undefined,
  });

  await page.route(new RegExp(`^http://localhost:${apiPort}/devices(/.*)?$`), async (route) => {
    const req = route.request();
    const method = req.method();
    if (method === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
    const path = new URL(req.url()).pathname;
    const body = req.postData() ? req.postDataJSON() : undefined;
    calls.push({ method, path, body });
    let m: RegExpExecArray | null;
    if (method === 'POST' && path === '/devices/pairings') {
      postCount += 1;
      // eerste poging: step-up nodig (§13.4 SU)
      if (postCount === 1) return reply(route, 403, { detail: { error: 'stepup_required' } });
      const id = randomUUID();
      // vorige open koppeling → cancelled (één open koppeling per gebruiker)
      for (const p of pairings.values()) if (p.status === 'pending' || p.status === 'claimed') p.status = 'cancelled';
      pairings.set(id, { kSrv: body.k_srv, status: 'pending', claim: null });
      return reply(route, 201, { pairing_id: id, expires_at: Math.floor(Date.now() / 1000) + 300 });
    }
    if ((m = /^\/devices\/pairings\/([^/]+)$/.exec(path))) {
      const p = pairings.get(m[1]);
      if (!p) return reply(route, 404, { detail: { error: 'not_found' } });
      // zoals de server (§13.3): een geannuleerde koppeling bestaat voor het web niet meer → 404
      if (method === 'GET' && p.status === 'cancelled') return reply(route, 404, { detail: { error: 'not_found' } });
      if (method === 'GET') return reply(route, 200, { status: p.status, expires_at: 0, ...(p.status === 'claimed' ? { claim: p.claim } : {}) });
      if (method === 'DELETE') { p.status = 'cancelled'; return reply(route, 204); }
    }
    if (method === 'POST' && (m = /^\/devices\/pairings\/([^/]+)\/confirm$/.exec(path))) {
      const p = pairings.get(m[1]);
      if (!p || p.status !== 'claimed') return reply(route, 404, { detail: { error: 'not_found' } });
      p.status = 'confirmed';
      const now = Math.floor(Date.now() / 1000);
      phoneKey = {
        id: p.claim.key_id, kind: 'phone', label: p.claim.label, status: 'active', public_key: p.claim.pk_c,
        credential_id: null, prf_salt: null, aaguid: null, authenticator: null, created_at: now, updated_at: now,
        last_used_at: null, recovery: null, device: { id: p.claim.device_id, label: p.claim.label, model: p.claim.model },
      };
      return reply(route, 201, phoneKey);
    }
    if (method === 'DELETE' && (m = /^\/devices\/([^/]+)$/.exec(path))) {
      if (phoneKey && phoneKey.device.id === m[1]) phoneKey = null;
      return reply(route, 204);
    }
    return reply(route, 404, { detail: { error: 'not_found' } });
  });
  // De echte sleutellijst aanvullen met de (nagebootste) telefoonsleutel (§13.4: phone-sleutels met device)
  await page.route(new RegExp(`^http://localhost:${apiPort}/vault/[^/]+/keys$`), async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const res = await route.fetch();
    const data = await res.json();
    if (phoneKey) data.keys.push(phoneKey);
    await route.fulfill({ response: res, json: data });
  });

  const totpSecret = await accountWithVault(page, web, usedCodes);
  const confirmPosts = () => calls.filter((c) => c.method === 'POST' && c.path.endsWith('/confirm'));
  const deletesOf = (id: string) => calls.filter((c) => c.method === 'DELETE' && c.path === `/devices/pairings/${id}`);

  // ── 1. Start: 403 stepup_required → step-up (TOTP, nog geen Bio) → QR + aftelling ──
  await page.click('#phone-pair');
  await expect(page.locator('#stepup-totp-form')).toBeVisible({ timeout: 15_000 });
  await page.fill('#stepup-code', await freshTotp(totpSecret, usedCodes));
  await page.click('#stepup-totp-form button[type="submit"]');
  let qr = await waitForQr(page);
  expect(postCount).toBe(2);
  await expect(page.locator('#pair-countdown')).toHaveText(/^(5:00|4:5\d)$/);
  await expect(page.locator('#pair-status')).toContainText('Wachten op je telefoon');
  await expect(page.locator('#phone-pair')).toBeDisabled();
  // Alleen k_srv naar de server; s staat nergens in een request, k_srv = HKDF(s, "HSv2 pair srv")
  let { pairingId, s } = parseQr(qr);
  const startBody = calls.filter((c) => c.method === 'POST' && c.path === '/devices/pairings').at(-1)!.body;
  expect(Object.keys(startBody).sort()).toEqual(['k_srv', 'vault_id']);
  expect(startBody.vault_id).toBe(await page.evaluate(() => (window as any).HorseSafeVaultUI.state.vaultId));
  expect(startBody.k_srv).toBe(b64u(hkdf(s, 'HSv2 pair srv')));
  expect(JSON.stringify(calls)).not.toContain(b64u(s));

  // ── 2. Server levert een claim met mac_web = HMAC(k_srv) (kan de server zelf maken) → niet vertrouwd ──
  const evil = makeClaim(qr, 'Aanvaller', { evil: true });
  Object.assign(pairings.get(pairingId)!, { status: 'claimed', claim: evil.claim });
  await expect(page.locator('#pair-error')).toContainText('Koppeling niet vertrouwd — mogelijk gemanipuleerd', { timeout: 10_000 });
  expect(deletesOf(pairingId)).toHaveLength(1);
  expect(confirmPosts()).toHaveLength(0);
  await expect(page.locator('#pair-step-sas')).toBeHidden();
  await expect(page.locator('#pair-qr svg')).toHaveCount(0);
  await expect(page.locator('#phone-pair')).toBeEnabled();

  // ── 3. Echte claim, maar de gebruiker kiest "Klopt niet" → DELETE, niets verzegeld ──
  await page.click('#phone-pair'); // step-up nog geldig: meteen QR
  qr = await waitForQr(page);
  ({ pairingId } = parseQr(qr));
  const wrong = makeClaim(qr, 'Telefoon buurman');
  Object.assign(pairings.get(pairingId)!, { status: 'claimed', claim: wrong.claim });
  await expect(page.locator('#pair-step-sas')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('#pair-sas')).toHaveText(`${wrong.sas.slice(0, 3)} ${wrong.sas.slice(3)}`);
  await expect(page.locator('#pair-device-label')).toHaveText('Telefoon buurman');
  await expect(page.locator('#pair-qr svg')).toHaveCount(0); // QR (met s) weg zodra er een claim is
  await page.click('#pair-sas-bad');
  await expect(page.locator('#pair-error')).toContainText('code niet klopt');
  expect(deletesOf(pairingId)).toHaveLength(1);
  expect(confirmPosts()).toHaveLength(0);

  // ── 4. Annuleren tijdens de QR → DELETE ──
  await page.click('#phone-pair');
  qr = await waitForQr(page);
  ({ pairingId } = parseQr(qr));
  await page.click('#pair-cancel');
  await expect(page.locator('#pair-status')).toContainText('geannuleerd');
  await expect.poll(() => deletesOf(pairingId).length).toBe(1);
  await expect(page.locator('#pair-qr svg')).toHaveCount(0);

  // ── 5. Echte claim, "Klopt" → Seal_v2 naar pk_c (kid = key_id), vastgelegd in de kluis, confirm ──
  await page.click('#phone-pair');
  qr = await waitForQr(page);
  ({ pairingId } = parseQr(qr));
  const good = makeClaim(qr, 'Galaxy Z Fold6');
  Object.assign(pairings.get(pairingId)!, { status: 'claimed', claim: good.claim });
  await expect(page.locator('#pair-sas')).toHaveText(`${good.sas.slice(0, 3)} ${good.sas.slice(3)}`, { timeout: 10_000 });
  await expect(page.locator('#pair-device-model')).toHaveText('SM-F956B');
  await expect(page.locator('#pair-sas-ok')).toBeFocused();
  // Smal scherm (360 px): SAS en knoppen passen, paneel loopt niet buiten beeld, knoppen ≥ 44 px hoog
  const wide = page.viewportSize()!;
  await page.setViewportSize({ width: 360, height: 740 });
  for (const sel of ['#pair-section', '#pair-sas', '#pair-sas-ok', '#pair-sas-bad']) {
    const b = (await page.locator(sel).boundingBox())!;
    expect(b.x, sel).toBeGreaterThanOrEqual(0);
    expect(b.x + b.width, sel).toBeLessThanOrEqual(360);
  }
  expect((await page.locator('#pair-sas-ok').boundingBox())!.height).toBeGreaterThanOrEqual(44);
  await page.setViewportSize(wide);
  await page.click('#pair-sas-ok');
  await expect(page.locator('#pair-status')).toContainText('✓ Telefoon "Galaxy Z Fold6" gekoppeld', { timeout: 30_000 });
  expect(confirmPosts()).toHaveLength(1);
  const confirmBody = confirmPosts()[0].body;
  expect(Object.keys(confirmBody)).toEqual(['sealed']);
  const sealed = JSON.parse(confirmBody.sealed);
  expect(Object.keys(sealed)).toEqual(['v', 'kid', 'epk', 'iv', 'ct']);
  expect(sealed).toMatchObject({ v: 2, kid: good.claim.key_id });
  expect(confirmBody.sealed).not.toContain(VAULT_PW);
  // R15: ontvanger vastgelegd in de versleutelde kluis (anders weigeren reseal/rekey dit toestel later)
  const pins = await page.evaluate(() => (window as any).HorseSafeVaultUI.pins());
  expect(pins[good.claim.key_id]).toBe(good.claim.pk_c);
  // Lijst ververst: telefoonrij met toestellabel en model
  const row = page.locator(`#keys-body tr[data-key="${good.claim.key_id}"]`);
  await expect(row).toContainText('Galaxy Z Fold6');
  await expect(row).toContainText('Telefoon');
  await expect(row).toContainText('SM-F956B');
  await expect(row.locator('.key-status')).not.toContainText('⚠');

  // ── 5b. Server hergebruikt een bestaand key_id (valt niet onder mac_web) → geweigerd vóór seal/pin ──
  await page.click('#phone-pair');
  qr = await waitForQr(page);
  ({ pairingId } = parseQr(qr));
  const reuse = makeClaim(qr, 'Tweede telefoon');
  reuse.claim.key_id = good.claim.key_id; // al in de sleutellijst én vastgelegd in de kluis
  Object.assign(pairings.get(pairingId)!, { status: 'claimed', claim: reuse.claim });
  await expect(page.locator('#pair-step-sas')).toBeVisible({ timeout: 10_000 });
  await page.click('#pair-sas-ok');
  await expect(page.locator('#pair-error')).toContainText('sleutelnummer op dat al bij je kluis hoort', { timeout: 10_000 });
  expect(confirmPosts()).toHaveLength(1); // alleen die van stap 5
  expect(deletesOf(pairingId)).toHaveLength(1);
  const pinsAfter = await page.evaluate(() => (window as any).HorseSafeVaultUI.pins());
  expect(pinsAfter[good.claim.key_id]).toBe(good.claim.pk_c); // pin niet overschreven

  // ── 6. Toestel verwijderen → DELETE /devices/{id} (bevestiging wordt in de test geaccepteerd) ──
  await row.locator('button[data-device]').click();
  await expect(page.locator('#keys-status')).toContainText('verwijderd');
  expect(calls.some((c) => c.method === 'DELETE' && c.path === `/devices/${good.claim.device_id}`)).toBe(true);
  await expect(row).toHaveCount(0);

  // ── 7. Kluis vergrendelen tijdens een koppeling → DELETE en paneel weg ──
  await page.click('#phone-pair');
  qr = await waitForQr(page);
  ({ pairingId } = parseQr(qr));
  await page.click('#lock-vault');
  await expect.poll(() => deletesOf(pairingId).length).toBe(1);
  await expect(page.locator('#pair-section')).toBeHidden();

  await page.unrouteAll({ behavior: 'ignoreErrors' });
  expect(prodHits, 'e2e mag nooit de productie-backend op :3997 raken').toEqual([]);
});

// ───────────── test 2: echte backend + neptoestel (fake_device.py) ─────────────
function fake(args: string[]): any {
  const r = spawnSync(PYTHON, ['-m', FAKE_MODULE, ...args], { cwd: REPO, encoding: 'utf8', timeout: 60_000 });
  if (r.status !== 0) throw new Error(`fake_device ${args[0]} faalde (${r.status}):\n${r.stdout}\n${r.stderr}`);
  const last = r.stdout.trim().split('\n').at(-1) || '';
  return JSON.parse(last);
}

test('Miller deel 2: koppelflow met neptoestel tegen de echte backend', async ({ page }) => {
  test.skip(!existsSync(FAKE_PATH), `${FAKE_PATH} ontbreekt nog (backend-kant §13 niet klaar)`);
  test.setTimeout(Number(process.env.HS_E2E_TIMEOUT || 180_000));
  const { apiPort, webPort } = stack!;
  const health = await (await fetch(`http://127.0.0.1:${apiPort}/health`)).json();
  test.skip(health.test_device_attestation !== true, 'backend draait zonder test_device_attestation');
  const api = `http://127.0.0.1:${apiPort}`;
  const web = `http://localhost:${webPort}`;
  const usedCodes = new Set<string>();
  const prodHits = await preparePage(page, apiPort);
  const tmp = mkdtempSync(join(process.env.HS_E2E_TMPDIR || tmpdir(), 'hs-fake-device-'));
  const state = join(tmp, 'device.json');
  try {
    const totpSecret = await accountWithVault(page, web, usedCodes);
    await page.click('#phone-pair');
    await expect(page.locator('#stepup-totp-form')).toBeVisible({ timeout: 15_000 });
    await page.fill('#stepup-code', await freshTotp(totpSecret, usedCodes));
    await page.click('#stepup-totp-form button[type="submit"]');
    const qr = await waitForQr(page);

    // De app scant de QR en claimt (testvlag: software-attestation)
    const claimed = fake(['claim', '--api', api, '--qr', qr, '--label', 'Neptoestel', '--model', 'Pixel Test', '--state', state]);
    expect(claimed.sas).toMatch(/^\d{6}$/);
    // Web toont dezelfde SAS als de app
    await expect(page.locator('#pair-sas')).toHaveText(`${claimed.sas.slice(0, 3)} ${claimed.sas.slice(3)}`, { timeout: 15_000 });
    await expect(page.locator('#pair-device-label')).toHaveText('Neptoestel');
    expect(fake(['status', '--api', api, '--state', state]).state).toBe('pending');

    const confirmP = page.waitForResponse((r) => r.url().endsWith('/confirm') && r.request().method() === 'POST');
    await page.click('#pair-sas-ok');
    const conf = await confirmP;
    expect(conf.status(), await conf.text()).toBe(201);
    const key = await conf.json();
    expect(key.kind).toBe('phone');
    expect(key.device).toMatchObject({ id: claimed.device_id, label: 'Neptoestel', model: 'Pixel Test' });
    await expect(page.locator('#pair-status')).toContainText('gekoppeld');
    const row = page.locator(`#keys-body tr[data-key="${key.id}"]`);
    await expect(row).toContainText('Neptoestel');
    await expect(row).toContainText('Pixel Test');

    // App ziet "active" met de sleutel van deze kluis
    const st = fake(['status', '--api', api, '--state', state]);
    expect(st.state).toBe('active');
    expect(st.keys.map((k: any) => k.key_id)).toContain(key.id);

    // Toestel verwijderen → app ziet "revoked" zonder sleutels
    await row.locator('button[data-device]').click();
    await expect(page.locator('#keys-status')).toContainText('verwijderd');
    await expect(row).toHaveCount(0);
    const st2 = fake(['status', '--api', api, '--state', state]);
    expect(st2.state).toBe('revoked');
    expect(st2.keys).toEqual([]);
    expect(prodHits).toEqual([]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
