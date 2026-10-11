import { test, expect, type Page, type CDPSession } from '@playwright/test';
import { startStack, freshTotp, type Stack } from './e2e-stack';

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

const EMAIL = `hwkeys+${Date.now()}@example.com`;
const ACCOUNT_PW = 'HwKeysAccount1234!';
const VAULT_PW = 'VaultPw99!xyz';
const NEW_VAULT_PW = 'NieuwKluisWw-2026!';

let stack: Stack | null = null;
let apiPort = 0;
let webPort = 0;

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
  stack = await startStack('hs-hwkeys-e2e-', (origin) => ({
    HORSESAFE_WEBAUTHN_RP_ID: 'localhost',
    HORSESAFE_WEBAUTHN_ORIGIN: origin,
    HORSESAFE_TEST_ATTESTATION: '1',
  }));
  ({ apiPort, webPort } = stack);
});

test.afterAll(async () => {
  stack?.stop();
});

test('Koblitz: koppelen, step-up, blokkeren, ontgrendelen, rekey en verouderde kopie', async ({ page }) => {
  test.setTimeout(Number(process.env.HS_E2E_TIMEOUT || 240_000));
  const web = `http://localhost:${webPort}`;
  const usedCodes = new Set<string>();
  page.on('dialog', (d) => d.accept());
  await page.addInitScript((port) => { localStorage.setItem('horsesafe.devApiPort', String(port)); }, apiPort);
  await noneAttestationShim(page);
  page.on('console', (m) => { if (process.env.HS_E2E_DEBUG) console.log('[page]', m.type(), m.text()); });
  page.on('pageerror', (e) => { if (process.env.HS_E2E_DEBUG) console.log('[pageerror]', e.message); });
  page.on('response', (r) => { if (process.env.HS_E2E_DEBUG && r.url().includes(String(apiPort))) console.log('[api]', r.request().method(), r.url(), r.status()); });

  // ── account + TOTP ──
  await page.goto(`${web}/index.html`);
  // Twee fysieke sleutels: eerst de noodsleutel (reserve-YubiKey), daarna de Bio
  const recoveryToken = await addAuthenticator(page);
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
  // Noodsleutel eruit (gaat de fysieke kluis in), Bio erin. Op één authenticator zou excludeCredentials
  // de tweede registratie terecht blokkeren.
  await recoveryToken.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: recoveryToken.id });
  await addAuthenticator(page);
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

  // ── keyfile van 32 bytes toevoegen via /rekey (reviewronde 1, bevinding 4 + 5) ──
  // Alleen een keyfile kiezen: het wachtwoord blijft. Daarna een gewone save; de kluis moet daarna
  // nog steeds opengaan met wachtwoord + dezelfde keyfile (en met de Bio).
  const KEYFILE = { name: 'kluis.key', mimeType: 'application/octet-stream', buffer: Buffer.alloc(32, 7) };
  await page.fill('#vault-pw', NEW_VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await page.click('#keys-open');
  await page.setInputFiles('#rekey-keyfile', KEYFILE);
  const rekey2 = page.waitForResponse((r) => r.url().endsWith('/rekey') && r.ok(), { timeout: 60_000 });
  await page.click('#rekey-submit');
  await rekey2;
  await expect(page.locator('#rekey-status')).toContainText('Gewijzigd', { timeout: 30_000 });
  await page.click('#add-entry');
  await page.fill('#e-title', 'Na keyfile');
  await page.click('#edit-form button[type="submit"]');
  await expect(page.locator('#entry-count')).toHaveText('2', { timeout: 30_000 });

  await page.click('#lock-vault');
  await page.fill('#vault-pw', NEW_VAULT_PW);
  await page.click('#unlock-submit');
  await expect(page.locator('#unlock-error')).toContainText(/Verkeerd wachtwoord/, { timeout: 30_000 });
  await page.fill('#vault-pw', NEW_VAULT_PW);
  await page.setInputFiles('#vault-keyfile', KEYFILE);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('2');
  await page.click('#lock-vault');
  await page.click('#hwkey-unlock-btn');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('2');

  // ── reviewronde 2: publieke sleutels vastgelegd in de KDBX (overleven opslaan + server + openen) ──
  const pins = await page.evaluate(() => (window as any).HorseSafeVaultUI.pins());
  expect(Object.keys(pins).sort()).toEqual([bioRes.request().postDataJSON().key_id, recKey.id].sort());
  expect(pins[recKey.id]).toBe(recBody.public_key);

  // Server (of DB-schrijver) verwisselt de public_key van de Bio → reseal verzegelt niets, geen PUT
  const bioId = bioRes.request().postDataJSON().key_id as string;
  const evilPk = Buffer.alloc(32, 9).toString('base64url');
  await page.route('**/keys', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const res = await route.fetch();
    const data = await res.json();
    for (const k of data.keys) if (k.id === bioId) k.public_key = evilPk;
    await route.fulfill({ response: res, json: data });
  });
  let resealPut = false;
  page.on('request', (r) => { if (r.url().endsWith('/keys/sealed') && r.method() === 'PUT') resealPut = true; });
  await page.click('#keys-open');
  await expect(page.locator(`#keys-body tr[data-key="${bioId}"] .key-status`)).toContainText('publieke sleutel gewijzigd', { timeout: 10_000 });
  await page.click('#keys-reseal');
  await expect(page.locator('#keys-error')).toContainText('wijkt af', { timeout: 10_000 });
  expect(resealPut).toBe(false);
  await page.unroute('**/keys');

  // ── reviewronde 2: rekey gecommit, maar het antwoord gaat verloren (504) → tab neemt nieuw materiaal over ──
  const THIRD_PW = 'DerdeKluisWw-2026!';
  let rekeyCommitted = false;
  await page.route('**/rekey', async (route) => {
    const res = await route.fetch(); // de server voert de rekey echt door
    if (res.status() !== 200) return route.fulfill({ response: res }); // bv. 403 stepup_required
    rekeyCommitted = true;
    await route.fulfill({ status: 504, body: '<html>504 Gateway Time-out</html>', contentType: 'text/html' });
  });
  await page.click('#keys-open');
  await page.fill('#rekey-pw', THIRD_PW);
  await page.fill('#rekey-pw2', THIRD_PW);
  await page.click('#rekey-submit');
  await expect(page.locator('#rekey-status')).toContainText('bevestigd na een vertraagd antwoord', { timeout: 60_000 });
  await page.unroute('**/rekey');
  expect(rekeyCommitted).toBe(true);
  // De tab werkt door met de nieuwe etag: een gewone save lukt (geen 412)
  await page.click('#add-entry');
  await page.fill('#e-title', 'Na 504');
  await page.click('#edit-form button[type="submit"]');
  await expect(page.locator('#entry-count')).toHaveText('3', { timeout: 30_000 });
  await page.click('#lock-vault');
  await page.fill('#vault-pw', THIRD_PW);
  await page.setInputFiles('#vault-keyfile', KEYFILE);
  await page.click('#unlock-submit');
  await expect(page.locator('#vault-section')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#entry-count')).toHaveText('3');
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
