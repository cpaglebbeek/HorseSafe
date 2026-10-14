// v0.2.0-Koblitz — fail-closed clientcontroles en API-afhandeling van js/hwkeys.js (§12.13), met nep-WebAuthn
// en nep-fetch. Node ≥ 20. Draai: node --test tests/unit/
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createHash } from 'node:crypto';

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

// ───────────── nep-browseromgeving ─────────────
const env = { routes: {}, calls: [], create: null, get: null };
Object.defineProperty(globalThis, 'navigator', {
  value: {
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36',
    maxTouchPoints: 0,
    credentials: {
      create: (o) => env.create(o.publicKey),
      get: (o) => env.get(o.publicKey),
    },
  },
  configurable: true,
  writable: true,
});
globalThis.location = { hostname: 'localhost' };
globalThis.PublicKeyCredential = function PublicKeyCredential() {};
globalThis.HorseSafeAPI = { base: 'http://api' };
globalThis.fetch = async (url, opts) => {
  const path = url.replace('http://api', '');
  const key = `${opts.method} ${path}`;
  env.calls.push({ key, body: opts.body });
  const h = env.routes[key];
  if (!h) return new Response(JSON.stringify({ detail: { error: 'not_found' } }), { status: 404 });
  const [status, body] = await h(typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body);
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
};

vm.runInThisContext(read('../../vendor/kdbxweb/kdbxweb.min.js'));
vm.runInThisContext(read('../../js/hwkeys.js'));
const HK = globalThis.HorseSafeHwKeys;
const H = HK._crypto;
const kdbxweb = globalThis.kdbxweb;

const VAULT = '3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b';
const KID = '9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a';
const CRED = new Uint8Array(32).fill(9);
const CRED_B64 = H.b64uEncode(CRED);
const PRF = new Uint8Array(32).fill(5);
const SALT = H.b64uEncode(new Uint8Array(32).fill(3));
const b = (n, v = 0) => new Uint8Array(n).fill(v);

function authData(flags) {
  const a = new Uint8Array(37);
  a[32] = flags;
  return a.buffer;
}

function makeAssertion({ flags = 0x05, prf = PRF, rawId = CRED } = {}) {
  return {
    rawId: rawId.buffer.slice(0),
    response: {
      clientDataJSON: b(10, 1).buffer, authenticatorData: authData(flags), signature: b(8, 2).buffer, userHandle: null,
    },
    getClientExtensionResults: () => (prf ? { prf: { results: { first: prf.buffer.slice(0) } } } : {}),
  };
}

function makeCredential({ flags = 0x45, prfEnabled = true, withAuthData = true } = {}) {
  const response = { clientDataJSON: b(10, 1).buffer, attestationObject: b(20, 4).buffer, getTransports: () => ['usb'] };
  if (withAuthData) response.getAuthenticatorData = () => authData(flags);
  return { rawId: CRED.buffer.slice(0), response, getClientExtensionResults: () => ({ prf: { enabled: prfEnabled } }) };
}

const registerOptions = {
  purpose: 'register', key_id: KID, prf_salt: SALT,
  rp: { id: 'localhost', name: 'HorseSafe' },
  user: { id: H.b64uEncode(new TextEncoder().encode('user-1')), name: 'a@b.nl', display_name: 'a@b.nl' },
  create: { challenge_id: 'c1', challenge: H.b64uEncode(b(32, 7)) },
  assert: { challenge_id: 'c2', challenge: H.b64uEncode(b(32, 8)) },
  pub_key_cred_params: [-8, -7], exclude_credentials: [], timeout_ms: 1000,
};

const noPin = async () => {};

async function secret() {
  const c = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('wachtwoord123'), null);
  return HK.secretFromCredentials(c);
}

beforeEach(() => {
  env.routes = {};
  env.calls = [];
  env.create = async () => makeCredential();
  env.get = async () => makeAssertion();
  globalThis.location = { hostname: 'localhost' };
});

// ───────────── checkSupport ─────────────
test('checkSupport: localhost/icthorsecloud.nl ok; andere host → wrong_host met link', async () => {
  assert.deepEqual({ ...(await HK.checkSupport()) }, { ok: true, reason: null });
  globalThis.location = { hostname: 'icthorsecloud.nl' };
  assert.equal((await HK.checkSupport()).ok, true);
  globalThis.location = { hostname: 'horsecloud55.example.org' };
  const r = await HK.checkSupport();
  assert.equal(r.reason, 'wrong_host');
  assert.equal(r.link, 'https://icthorsecloud.nl/HorseSafe/');
});

test('checkSupport: Safari en iOS → safari', async () => {
  const ua = navigator.userAgent;
  navigator.userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
  assert.equal((await HK.checkSupport()).reason, 'safari');
  navigator.userAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/120 Mobile Safari/604.1';
  assert.equal((await HK.checkSupport()).reason, 'safari');
  navigator.userAgent = ua;
});

// ───────────── registratie ─────────────
test('enroll: server-challenges, create+get met PRF, Seal_v2 en POST met attestation_object', async () => {
  let posted;
  env.routes['POST /webauthn/options'] = async (body) => {
    assert.deepEqual(body, { purpose: 'register', vault_id: VAULT, kind: 'bio' });
    return [200, registerOptions];
  };
  env.create = async (pk) => {
    assert.equal(pk.attestation, 'direct');
    assert.deepEqual(pk.hints, ['security-key']);
    assert.equal(pk.authenticatorSelection.userVerification, 'required');
    assert.equal(pk.authenticatorSelection.authenticatorAttachment, 'cross-platform');
    assert.deepEqual(pk.pubKeyCredParams.map((p) => p.alg), [-8, -7]);
    assert.deepEqual(pk.extensions, { prf: {} });
    assert.equal(H.b64uEncode(pk.challenge), registerOptions.create.challenge);
    return makeCredential();
  };
  env.get = async (pk) => {
    assert.equal(H.b64uEncode(pk.challenge), registerOptions.assert.challenge);
    assert.equal(pk.rpId, 'localhost');
    assert.equal(H.b64uEncode(pk.extensions.prf.evalByCredential[CRED_B64].first), SALT);
    return makeAssertion();
  };
  const order = [];
  env.routes[`POST /vault/${VAULT}/keys`] = async (body) => { order.push('post'); posted = body; return [201, { id: KID, kind: 'bio' }]; };
  const s = await secret();
  let pinned;
  const pin = async (kid, pk) => { order.push('pin'); pinned = { kid, pk }; };
  const key = await HK.enroll({ vaultId: VAULT, kind: 'bio', label: 'Bio', secret: s, pin });
  assert.equal(key.id, KID);
  assert.deepEqual(order, ['pin', 'post'], 'eerst vastleggen in de kluis, dan koppelen');
  assert.deepEqual(pinned, { kid: KID, pk: posted.public_key });
  assert.equal(posted.key_id, KID);
  assert.equal(posted.create.challenge_id, 'c1');
  assert.equal(posted.create.attestation_object, H.b64uEncode(b(20, 4)));
  assert.equal(posted.create.client_data_json, H.b64uEncode(b(10, 1)));
  assert.deepEqual(posted.create.transports, ['usb']);
  assert.equal(posted.assert.challenge_id, 'c2');
  assert.equal(posted.assert.credential_id, CRED_B64);
  assert.equal(posted.assert.user_handle, null);
  assert.equal('prf_salt' in posted, false, 'client stuurt prf_salt niet mee');
  const kp = await H.keypairFromPrf(PRF);
  assert.equal(posted.public_key, kp.publicKey);
  const opened = await H.unseal(posted.sealed, kp, { vaultId: VAULT, keyId: KID });
  assert.deepEqual(Array.from(opened.ph), Array.from(s.ph.getBinary()));
  assert.equal(opened.kh, null);
  assert.ok(!JSON.stringify(posted).includes('wachtwoord123'));
});

const enrollFails = [
  ['geen getAuthenticatorData → browser_unsupported', { create: () => makeCredential({ withAuthData: false }) }, 'browser_unsupported'],
  ['prf.enabled false → no_prf', { create: () => makeCredential({ prfEnabled: false }) }, 'no_prf'],
  ['UV uit bij create → no_uv', { create: () => makeCredential({ flags: 0x41 }) }, 'no_uv'],
  ['BE aan bij create → synced', { create: () => makeCredential({ flags: 0x4d }) }, 'synced'],
  ['geen PRF-resultaat bij get → no_prf', { get: () => makeAssertion({ prf: null }) }, 'no_prf'],
  ['BS aan bij get → synced', { get: () => makeAssertion({ flags: 0x15 }) }, 'synced'],
  ['annuleren → cancelled', { create: () => { throw Object.assign(new Error('x'), { name: 'NotAllowedError' }); } }, 'cancelled'],
  ['al gekoppeld → credential_exists', { create: () => { throw Object.assign(new Error('x'), { name: 'InvalidStateError' }); } }, 'credential_exists'],
];
for (const [name, mocks, code] of enrollFails) {
  test(`enroll faalt dicht: ${name}, zonder POST`, async () => {
    env.routes['POST /webauthn/options'] = async () => [200, registerOptions];
    if (mocks.create) env.create = async () => mocks.create();
    if (mocks.get) env.get = async () => mocks.get();
    await assert.rejects(HK.enroll({ vaultId: VAULT, kind: 'bio', label: 'x', secret: await secret(), pin: noPin }), (e) => e.code === code);
    assert.ok(!env.calls.some((c) => c.key === `POST /vault/${VAULT}/keys`));
  });
}

test('enroll: serveropties met andere rpId → wrong_host (rpId vast)', async () => {
  env.routes['POST /webauthn/options'] = async () => [200, { ...registerOptions, rp: { id: 'evil.example', name: 'x' } }];
  await assert.rejects(HK.enroll({ vaultId: VAULT, kind: 'bio', label: 'x', secret: await secret(), pin: noPin }), (e) => e.code === 'wrong_host');
});

test('enroll: 403 stepup_required wordt een HwKeyError met code (voor de step-up-dialoog)', async () => {
  env.routes['POST /webauthn/options'] = async () => [403, { detail: { error: 'stepup_required' } }];
  await assert.rejects(HK.enroll({ vaultId: VAULT, kind: 'bio', label: 'x', secret: await secret(), pin: noPin }),
    (e) => e.code === 'stepup_required' && e.message === HK.MESSAGES.stepup_required);
});

// ───────────── ontgrendelen ─────────────
async function unlockSetup({ sealedFor = { vaultId: VAULT, keyId: KID }, pkOverride } = {}) {
  const kp = await H.keypairFromPrf(PRF);
  const s = await secret();
  const raw = { ph: s.ph.getBinary(), kh: null };
  const sealed = await H.seal(kp.publicKey, raw, sealedFor);
  env.routes['POST /webauthn/options'] = async (body) => {
    assert.deepEqual(body, { purpose: 'unlock', vault_id: VAULT });
    return [200, { purpose: 'unlock', challenge_id: 'u1', challenge: H.b64uEncode(b(32, 1)), rp_id: 'localhost',
      allow_credentials: [{ key_id: KID, kind: 'bio', credential_id: CRED_B64, prf_salt: SALT }] }];
  };
  env.routes[`GET /vault/${VAULT}/keys`] = async () => [200, { keys: [{ id: KID, kind: 'bio', status: 'active', public_key: pkOverride || kp.publicKey }], notify_available: true, stepup_until: null }];
  env.routes[`POST /vault/${VAULT}/keys/${KID}/unlock`] = async (body) => {
    assert.equal(body.challenge_id, 'u1');
    assert.equal(body.credential_id, CRED_B64);
    return [200, { id: KID, sealed }];
  };
  return s;
}

test('unlock: assertion naar server, sealed openen met AAD, credentialsFromHashes = zelfde samengestelde sleutel', async () => {
  const s = await unlockSetup();
  const r = await HK.unlock({ vaultId: VAULT });
  assert.equal(r.key.id, KID);
  const orig = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('wachtwoord123'), null);
  const a = new Uint8Array(await HK.credentialsFromHashes(r.secret).getHash());
  const c = new Uint8Array(await orig.getHash());
  assert.deepEqual(Array.from(a), Array.from(c));
  assert.equal(r.secret.kh, null);
  HK.wipeSecret(s);
});

test('unlock: pk uit PRF ≠ public_key van de sleutel → unseal_failed, geen unlock-POST', async () => {
  await unlockSetup({ pkOverride: H.b64uEncode(b(32, 1)) });
  await assert.rejects(HK.unlock({ vaultId: VAULT }), (e) => e.code === 'unseal_failed');
  assert.ok(!env.calls.some((c) => c.key.endsWith('/unlock')));
});

test('unlock: kopie gebonden aan een andere vault → unseal_failed', async () => {
  await unlockSetup({ sealedFor: { vaultId: '00000000-0000-4000-8000-000000000000', keyId: KID } });
  await assert.rejects(HK.unlock({ vaultId: VAULT }), (e) => e.code === 'unseal_failed');
});

test('unlock: UV ontbreekt → no_uv vóór de server', async () => {
  await unlockSetup();
  env.get = async () => makeAssertion({ flags: 0x01 });
  await assert.rejects(HK.unlock({ vaultId: VAULT }), (e) => e.code === 'no_uv');
  assert.ok(!env.calls.some((c) => c.key.endsWith('/unlock')));
});

test('unlock: 423 recovery_waiting draagt state en release_at mee', async () => {
  await unlockSetup();
  const at = Math.floor(Date.now() / 1000) + 3600;
  env.routes[`POST /vault/${VAULT}/keys/${KID}/unlock`] = async () => [423, { detail: { error: 'recovery_waiting', state: 'waiting', release_at: at, release_until: at + 86400 } }];
  await assert.rejects(HK.unlock({ vaultId: VAULT }), (e) => e.code === 'recovery_waiting' && e.state === 'waiting' && e.release_at === at);
});

test('unlock: geen bruikbare sleutels (409) → no_usable_keys', async () => {
  env.routes['POST /webauthn/options'] = async () => [409, { detail: { error: 'no_usable_keys' } }];
  env.routes[`GET /vault/${VAULT}/keys`] = async () => [200, { keys: [], notify_available: true, stepup_until: null }];
  await assert.rejects(HK.unlock({ vaultId: VAULT }), (e) => e.code === 'no_usable_keys');
});

// ───────────── overige endpoints ─────────────
test('422 → invalid_request; onbekende fout → api_<status>', async () => {
  env.routes[`GET /vault/${VAULT}/keys`] = async () => [422, { detail: [{ loc: ['x'] }] }];
  await assert.rejects(HK.listKeys(VAULT), (e) => e.code === 'invalid_request');
  env.routes[`GET /vault/${VAULT}/keys`] = async () => [500, {}];
  await assert.rejects(HK.listKeys(VAULT), (e) => e.code === 'api_500');
});

test('resealAll: één Seal_v2 per sleutel, gebonden aan elk key_id', async () => {
  const kps = [await H.keypairFromPrf(b(32, 1)), await H.keypairFromPrf(b(32, 2))];
  const keys = [{ id: 'k-1', public_key: kps[0].publicKey }, { id: 'k-2', public_key: kps[1].publicKey }];
  const pins = { 'k-1': kps[0].publicKey, 'k-2': kps[1].publicKey };
  let items;
  env.routes[`PUT /vault/${VAULT}/keys/sealed`] = async (body) => { items = body.items; return [200, { updated: 2 }]; };
  assert.equal(await HK.resealAll({ vaultId: VAULT, keys, secret: await secret(), pins }), 2);
  assert.deepEqual(items.map((i) => i.id), ['k-1', 'k-2']);
  await H.unseal(items[1].sealed, kps[1], { vaultId: VAULT, keyId: 'k-2' });
  await assert.rejects(H.unseal(items[1].sealed, kps[1], { vaultId: VAULT, keyId: 'k-1' }), (e) => e.code === 'unseal_failed');
});

test('block/unblock/release/cancel: juiste methode en pad; serverfoutcode doorgegeven', async () => {
  const base = `/vault/${VAULT}/keys/${KID}`;
  env.routes[`POST ${base}/block`] = async () => [200, { id: KID }];
  env.routes[`DELETE ${base}/block`] = async () => [403, { detail: { error: 'stepup_bio_required' } }];
  env.routes[`POST ${base}/release`] = async () => [503, { detail: { error: 'notify_unavailable' } }];
  env.routes[`DELETE ${base}/release`] = async () => [409, { detail: { error: 'nothing_to_cancel' } }];
  env.routes[`DELETE ${base}`] = async () => [204, null];
  assert.equal((await HK.block(VAULT, KID)).id, KID);
  await assert.rejects(HK.unblock(VAULT, KID), (e) => e.code === 'stepup_bio_required');
  await assert.rejects(HK.requestRelease(VAULT, KID), (e) => e.code === 'notify_unavailable');
  await assert.rejects(HK.cancelRelease(VAULT, KID), (e) => e.code === 'nothing_to_cancel');
  assert.equal(await HK.deleteKey(VAULT, KID), true);
});

test('stepUp bio: purpose stepup zonder vault_id en zonder PRF; 409 no_bio_keys gaat door', async () => {
  env.routes['POST /webauthn/options'] = async (body) => {
    assert.deepEqual(body, { purpose: 'stepup' });
    return [200, { purpose: 'stepup', challenge_id: 's1', challenge: H.b64uEncode(b(32, 1)), rp_id: 'localhost', allow_credentials: [{ key_id: KID, kind: 'bio', credential_id: CRED_B64 }] }];
  };
  let sent;
  env.get = async (pk) => { assert.equal(pk.extensions, undefined); return makeAssertion({ prf: null }); };
  env.routes['POST /auth/stepup'] = async (body) => { sent = body; return [200, { ok: true, method: 'bio', stepup_until: 1 }]; };
  assert.equal((await HK.stepUp({ method: 'bio' })).method, 'bio');
  assert.equal(sent.method, 'bio');
  assert.equal(sent.challenge_id, 's1');
  env.routes['POST /webauthn/options'] = async () => [409, { detail: { error: 'no_bio_keys' } }];
  await assert.rejects(HK.stepUp({ method: 'bio' }), (e) => e.code === 'no_bio_keys');
  env.routes['POST /auth/stepup'] = async (body) => { sent = body; return [401, { detail: { error: 'invalid_code' } }]; };
  await assert.rejects(HK.stepUp({ method: 'totp', code: ' 123456 ' }), (e) => e.code === 'invalid_code');
  assert.deepEqual(sent, { method: 'totp', code: '123456' });
});

// ───────────── vastgelegde ontvangers (reviewronde 2) ─────────────
test('enroll: pin mislukt → pin_save_failed en geen POST; zonder pin-callback geen koppeling', async () => {
  env.routes['POST /webauthn/options'] = async () => [200, registerOptions];
  env.routes[`POST /vault/${VAULT}/keys`] = async () => [201, { id: KID }];
  await assert.rejects(HK.enroll({ vaultId: VAULT, kind: 'bio', label: 'x', secret: await secret(), pin: async () => { throw new Error('412'); } }),
    (e) => e.code === 'pin_save_failed');
  await assert.rejects(HK.enroll({ vaultId: VAULT, kind: 'bio', label: 'x', secret: await secret() }), (e) => e.code === 'pin_save_failed');
  assert.ok(!env.calls.some((c) => c.key === `POST /vault/${VAULT}/keys`));
});

test('resealAll/rekey: verwisselde public_key of niet-vastgelegde sleutel → niets verzegeld, geen PUT', async () => {
  const mine = await H.keypairFromPrf(b(32, 1));
  const evil = await H.keypairFromPrf(b(32, 66));
  const pins = { 'k-1': mine.publicKey };
  env.routes[`PUT /vault/${VAULT}/keys/sealed`] = async () => [200, { updated: 1 }];
  env.routes[`PUT /vault/${VAULT}/rekey`] = async () => [200, { vault: { etag: 'x' }, resealed: 1 }];
  const swapped = [{ id: 'k-1', label: 'Mijn Bio', public_key: evil.publicKey }];
  await assert.rejects(HK.resealAll({ vaultId: VAULT, keys: swapped, secret: await secret(), pins }),
    (e) => e.code === 'key_pin_mismatch' && e.key_id === 'k-1' && HK.messageFor(e).includes('"Mijn Bio"'));
  const extra = [{ id: 'k-1', public_key: mine.publicKey }, { id: 'k-2', label: 'Onbekend', public_key: evil.publicKey }];
  await assert.rejects(HK.resealAll({ vaultId: VAULT, keys: extra, secret: await secret(), pins }), (e) => e.code === 'key_not_pinned');
  await assert.rejects(HK.resealAll({ vaultId: VAULT, keys: swapped, secret: await secret() }), (e) => e.code === 'key_not_pinned');
  await assert.rejects(HK.rekey({ vaultId: VAULT, etag: 'e0', blob: new Uint8Array(4), keys: swapped, secret: await secret(), pins }),
    (e) => e.code === 'key_pin_mismatch');
  assert.equal(env.calls.filter((c) => c.key.startsWith('PUT ')).length, 0);
});

test('pins: vastleggen in de KDBX-meta (CustomData); andere vault telt niet', async () => {
  // Opslaan + openen van de KDBX vraagt DOMParser (browser); die rondgang dekt de Playwright-e2e
  // (rekey na opnieuw openen faalt anders met key_not_pinned).
  const creds = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('wachtwoord123'), null);
  const db = kdbxweb.Kdbx.create(creds, 'pins');
  const kp = await H.keypairFromPrf(b(32, 1));
  assert.deepEqual(HK.readPins(db, VAULT), {});
  HK.pinKey(db, VAULT, KID, kp.publicKey);
  HK.pinKey(db, VAULT, 'k-2', (await H.keypairFromPrf(b(32, 2))).publicKey);
  assert.throws(() => HK.pinKey(db, VAULT, 'k-3', 'te-kort'), (e) => e.code === 'invalid_public_key');
  const item = db.meta.customData.get('HorseSafe.KeyPins.v1');
  assert.equal(typeof item.value, 'string');
  assert.ok(item.lastModified instanceof Date);
  assert.ok(!item.value.includes('wachtwoord123'));
  const pins = HK.readPins(db, VAULT);
  assert.equal(pins[KID], kp.publicKey);
  assert.equal(Object.keys(pins).length, 2);
  assert.deepEqual(HK.readPins(db, '00000000-0000-4000-8000-000000000000'), {});
  db.meta.customData.set('HorseSafe.KeyPins.v1', { value: '{kapot' });
  assert.deepEqual(HK.readPins(db, VAULT), {});
  assert.equal(HK.pinStatus({ id: KID, public_key: kp.publicKey }, pins), 'ok');
  assert.equal(HK.pinStatus({ id: KID, public_key: 'anders' }, pins), 'mismatch');
  assert.equal(HK.pinStatus({ id: 'k-9', public_key: kp.publicKey }, pins), 'missing');
});

test('pinKey overschrijft nooit een bestaande pin met een andere publieke sleutel (key_id komt van de server)', async () => {
  const creds = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('wachtwoord123'), null);
  const db = kdbxweb.Kdbx.create(creds, 'pins');
  const yubi = (await H.keypairFromPrf(b(32, 1))).publicKey;
  const phone = (await H.keypairFromPrf(b(32, 2))).publicKey;
  HK.pinKey(db, VAULT, KID, yubi);
  assert.throws(() => HK.pinKey(db, VAULT, KID, phone), (e) => e.code === 'key_pin_conflict' && e.key_id === KID);
  assert.equal(HK.readPins(db, VAULT)[KID], yubi, 'oude pin onaangetast');
  HK.pinKey(db, VAULT, KID, yubi); // dezelfde sleutel opnieuw: mag (idempotent)
  HK.pinKey(db, VAULT, 'k-2', phone); // nieuw key_id: mag
  assert.deepEqual(HK.readPins(db, VAULT), { [KID]: yubi, 'k-2': phone });
  assert.match(HK.messageFor({ code: 'key_pin_conflict' }), /al met een andere sleutel/);
  assert.throws(() => HK.pinKey(db, VAULT, '', phone), (e) => e.code === 'invalid_request');
});

// ───────────── rekey: onbekende uitkomst (reviewronde 2) ─────────────
async function rekeySetup() {
  const kp = await H.keypairFromPrf(b(32, 1));
  return { keys: [{ id: 'k-1', public_key: kp.publicKey }], pins: { 'k-1': kp.publicKey }, blob: new TextEncoder().encode('nieuwe-kdbx') };
}

test('rekey: expliciete weigering (servercode of 4xx) blijft die fout; 5xx/netwerk → rekey_unknown', async () => {
  const { keys, pins, blob } = await rekeySetup();
  const s = await secret();
  for (const [status, body, want] of [
    [412, { detail: { error: 'etag_mismatch' } }, 'etag_mismatch'],
    [500, { detail: { error: 'write_failed' } }, 'write_failed'],
    [413, null, 'api_413'],
    [504, null, 'rekey_unknown'],
    [502, { detail: 'Bad Gateway' }, 'rekey_unknown'],
  ]) {
    env.routes[`PUT /vault/${VAULT}/rekey`] = async () => [status, body];
    await assert.rejects(HK.rekey({ vaultId: VAULT, etag: 'e0', blob, keys, secret: s, pins }), (e) => e.code === want, `${status}`);
  }
  env.routes[`PUT /vault/${VAULT}/rekey`] = async () => { throw new TypeError('Failed to fetch'); };
  await assert.rejects(HK.rekey({ vaultId: VAULT, etag: 'e0', blob, keys, secret: s, pins }),
    (e) => e.code === 'rekey_unknown' && e.cause instanceof TypeError);
});

test('rekeyLanded: etag van de server = SHA-256 van de verstuurde blob → landed; anders not_landed; geen antwoord → unknown', async () => {
  const { blob } = await rekeySetup();
  const want = await HK.blobEtag(blob);
  assert.equal(want, createHash('sha256').update(blob).digest('hex'));
  env.routes['GET /vault'] = async () => [200, [{ id: VAULT, etag: want }]];
  assert.deepEqual(await HK.rekeyLanded({ vaultId: VAULT, blob }), { state: 'landed', etag: want });
  env.routes['GET /vault'] = async () => [200, [{ id: VAULT, etag: 'oud' }]];
  assert.deepEqual(await HK.rekeyLanded({ vaultId: VAULT, blob }), { state: 'not_landed', etag: 'oud' });
  env.routes['GET /vault'] = async () => [504, null];
  assert.deepEqual(await HK.rekeyLanded({ vaultId: VAULT, blob }), { state: 'unknown' });
  env.routes['GET /vault'] = async () => [200, []];
  assert.deepEqual(await HK.rekeyLanded({ vaultId: VAULT, blob }), { state: 'unknown' });
});
