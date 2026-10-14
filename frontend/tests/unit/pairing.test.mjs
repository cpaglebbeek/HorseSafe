// v0.3.4-Miller — vectortests voor js/pairing.js (telefoon koppelen, docs/HARDWARE_KEYS.md §13.1).
// Node ≥ 20, geen browser nodig. Draai: node --test tests/unit/
// Testvectoren: specs/testvectors/pair_v1.json (gegenereerd door specs/testvectors/gen_pair_v1.py). Een ander
// pad kan via HS_PAIR_VECTORS; ontbreekt het bestand, dan falen de vectortests (nooit overslaan: JS == Python).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');
vm.runInThisContext(read('../../js/hwkeys.js'));
vm.runInThisContext(read('../../js/pairing.js'));
const HK = globalThis.HorseSafeHwKeys;
const P = globalThis.HorseSafePairing;
const C = P._crypto;
const { b64uEncode, b64uDecode } = HK._crypto;
const hex = (b) => Buffer.from(b).toString('hex');

const vectorPath = process.env.HS_PAIR_VECTORS
  || new URL('../../../specs/testvectors/pair_v1.json', import.meta.url).pathname;
const data = existsSync(vectorPath) ? JSON.parse(readFileSync(vectorPath, 'utf8')) : null;
test('testvectoren pair_v1 aanwezig', () => {
  assert.ok(data, `testvectoren ontbreken (${vectorPath})`);
  assert.equal(data.format, 'HorseSafe pair_v1 testvectors');
  assert.ok(data.vectors.length >= 2);
});
const vectors = data ? data.vectors : [];

for (const v of vectors) {
  test(`vector ${v.name}: k_srv en k_web (HKDF)`, async () => {
    const { kSrv, kWeb } = await C.deriveKeys(b64uDecode(v.s));
    assert.equal(b64uEncode(kSrv), v.k_srv);
    assert.equal(b64uEncode(kWeb), v.k_web);
  });

  test(`vector ${v.name}: QR-string`, () => {
    assert.equal(P.qrString(v.fields.pairing_id, b64uDecode(v.s)), v.qr);
  });

  test(`vector ${v.name}: att_challenge`, async () => {
    const { kSrv } = await C.deriveKeys(b64uDecode(v.s));
    assert.equal(hex(await C.attChallenge(v.fields.pairing_id, kSrv)), v.att_challenge_hex);
  });

  test(`vector ${v.name}: transcript`, () => {
    assert.equal(hex(C.transcript(v.fields)), v.transcript_hex);
  });

  test(`vector ${v.name}: mac_srv, mac_web en sas`, async () => {
    const { kSrv, kWeb } = await C.deriveKeys(b64uDecode(v.s));
    const t = C.transcript(v.fields);
    assert.equal(b64uEncode(await C.mac(kSrv, t)), v.mac_srv);
    assert.equal(b64uEncode(await C.mac(kWeb, t)), v.mac_web);
    assert.equal(await C.sas(t), v.sas);
    assert.match(v.sas, /^\d{6}$/);
  });

  test(`vector ${v.name}: verifyClaim accepteert de echte claim en geeft de SAS`, async () => {
    const { kWeb } = await C.deriveKeys(b64uDecode(v.s));
    const claim = claimFrom(v);
    const r = await P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, claim);
    assert.equal(r.sas, v.sas);
  });

  test(`vector ${v.name}: mac_srv als mac_web (server kent alleen k_srv) → pairing_untrusted`, async () => {
    const { kWeb } = await C.deriveKeys(b64uDecode(v.s));
    const claim = { ...claimFrom(v), mac_web: v.mac_srv };
    await assert.rejects(P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, claim), (e) => e.code === 'pairing_untrusted');
  });
}

function claimFrom(v) {
  const f = v.fields;
  return {
    device_id: 'b1c2d3e4-0000-4000-8000-000000000001',
    key_id: '7d6c5b4a-3928-4170-8e6f-5d4c3b2a1908',
    pk_c: f.pk_c,
    k_dev_pub: f.k_dev_pub,
    k_biosig_pub: f.k_biosig_pub,
    label: f.label,
    model: f.model,
    app_version: f.app_version,
    mac_web: v.mac_web,
    security_level: 'StrongBox',
    strongbox: true,
  };
}

// ───────────── negatieve gevallen ─────────────
test('negatief "ander label": mac_srv, mac_web en sas wijken af; verifyClaim weigert', async () => {
  const neg = data.negative.find((n) => n.name === 'ander label');
  const base = vectors.find((v) => v.name === neg.based_on);
  const fields = { ...base.fields, ...neg.change };
  const { kSrv, kWeb } = await C.deriveKeys(b64uDecode(base.s));
  const t = C.transcript(fields);
  assert.notEqual(b64uEncode(await C.mac(kSrv, t)), base.mac_srv);
  assert.notEqual(b64uEncode(await C.mac(kWeb, t)), base.mac_web);
  assert.notEqual(await C.sas(t), base.sas);
  const claim = { ...claimFrom(base), label: neg.change.label }; // server/aanvaller wijzigt het label, oude mac_web
  await assert.rejects(P.verifyClaim({ pairingId: base.fields.pairing_id, kWeb }, claim), (e) => e.code === 'pairing_untrusted');
});

test('verwisselde pk_c (kwaadwillende server) → pairing_untrusted', async () => {
  const v = vectors[0];
  const { kWeb } = await C.deriveKeys(b64uDecode(v.s));
  const claim = { ...claimFrom(v), pk_c: b64uEncode(new Uint8Array(32).fill(9)) };
  await assert.rejects(P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, claim), (e) => e.code === 'pairing_untrusted');
});

test('transcript gebruikt het eigen pairing_id, niet dat van een andere koppeling', async () => {
  const v = vectors[0];
  const { kWeb } = await C.deriveKeys(b64uDecode(v.s));
  const other = vectors[1].fields.pairing_id;
  await assert.rejects(P.verifyClaim({ pairingId: other, kWeb }, claimFrom(v)), (e) => e.code === 'pairing_untrusted');
  // een claim die zelf een ander pairing_id noemt, wordt ook geweigerd
  await assert.rejects(P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, { ...claimFrom(v), pairing_id: other }),
    (e) => e.code === 'pairing_untrusted');
});

test('vormcontrole claim: \\0/stuurtekens, verkeerde lengtes en ontbrekende velden → pairing_untrusted', async () => {
  const v = vectors[0];
  const { kWeb } = await C.deriveKeys(b64uDecode(v.s));
  const bad = [
    { label: 'a\0b' },
    { label: 'regel\nnieuw' },
    { label: 'Fold\u202eexe.gpj' }, // Cf: leesrichting omdraaien
    { label: 'Fo\u200bld' }, // Cf: zero-width space
    { model: 'SM\u2028F956B' }, // regelscheider
    { model: 'SM\u2029F956B' }, // alineascheider
    { app_version: '0.3.4\ufeff' }, // Cf: BOM
    { label: 'Fold\ud800' }, // los surrogaat
    { label: '' },
    { label: 'x'.repeat(65) },
    { model: 'x'.repeat(65) },
    { app_version: 'x'.repeat(33) },
    { pk_c: v.fields.pk_c.slice(0, 42) },
    { pk_c: v.fields.pk_c.replace(/.$/, '=') },
    { k_dev_pub: 'A'.repeat(201) },
    { k_biosig_pub: 'ab+c' },
    { key_id: 'GEEN-UUID' },
    { mac_web: v.mac_web.slice(0, 42) },
    { mac_web: undefined },
    { device_id: '' },
  ];
  for (const change of bad) {
    await assert.rejects(P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, { ...claimFrom(v), ...change }),
      (e) => e.code === 'pairing_untrusted', JSON.stringify(change));
  }
  await assert.rejects(P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, null), (e) => e.code === 'pairing_untrusted');
  assert.throws(() => C.transcript({ ...v.fields, model: 'a\0' }), (e) => e.code === 'pairing_untrusted');
});

test('opmaaktekens/surrogaten in label/model met GELDIGE mac_web → toch pairing_untrusted (vóór tonen)', async () => {
  const v = vectors[0];
  const { kWeb } = await C.deriveKeys(b64uDecode(v.s));
  const bad = [
    { label: 'Fold\u202eexe.gpj' },
    { label: 'Fo\u200bld' },
    { label: 'Fold\u2066' },
    { model: 'SM\u2028F956B' },
    { model: 'SM\u2029F956B' },
    { label: 'Fold\ud800' },
    { app_version: '0.3.4\ufeff' },
  ];
  for (const change of bad) {
    const fields = { ...v.fields, ...change };
    const macWeb = b64uEncode(await C.mac(kWeb, C.transcript(fields)));
    const claim = { ...claimFrom(v), ...change, mac_web: macWeb };
    await assert.rejects(P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, claim),
      (e) => e.code === 'pairing_untrusted', JSON.stringify(change));
  }
  // gewone niet-ASCII-tekst (accenten, emoji zonder ZWJ) blijft toegestaan
  const ok = { label: 'Téléphone 📱', model: 'Fairphone 5' };
  const fields = { ...v.fields, ...ok };
  const claim = { ...claimFrom(v), ...ok, mac_web: b64uEncode(await C.mac(kWeb, C.transcript(fields))) };
  assert.equal((await P.verifyClaim({ pairingId: v.fields.pairing_id, kWeb }, claim)).sas, await C.sas(C.transcript(fields)));
});

test('s is 16 willekeurige bytes; QR heeft vorm hs1p:<uuid>.<22 tekens b64u>', () => {
  const a = C.newSecret();
  const b = C.newSecret();
  assert.equal(a.length, 16);
  assert.notDeepEqual(Array.from(a), Array.from(b));
  const qr = P.qrString('5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d', a);
  assert.match(qr, /^hs1p:[0-9a-f-]{36}\.[A-Za-z0-9_-]{22}$/);
  assert.throws(() => P.qrString('geen-uuid', a), (e) => e.code === 'invalid_request');
});

// ───────────── flow met nep-fetch (start → claim → confirm, wissen) ─────────────
function fakeServer(handler) {
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ method: opts.method, url, body });
    const r = await handler(opts.method, url, body);
    const status = r.status || 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: new Map(),
      json: async () => r.json ?? null,
    };
  };
  return calls;
}

function fakeSecret() {
  const ph = new Uint8Array(32).fill(5);
  return { ph: { getBinary: () => new Uint8Array(ph) }, kh: null };
}

test('flow: start stuurt alleen k_srv; claim → mac_web ok → SAS; confirm verzegelt naar pk_c met kid = key_id; k_web gewist', async () => {
  const PID = '5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d';
  const VAULT = '3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b';
  let kSrvSeen = null;
  let claim = null;
  const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pk = b64uEncode(new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey)));
  const calls = fakeServer(async (method, url, body) => {
    if (method === 'POST' && url.endsWith('/devices/pairings')) {
      kSrvSeen = body.k_srv;
      return { status: 201, json: { pairing_id: PID, expires_at: Math.floor(Date.now() / 1000) + 300 } };
    }
    if (method === 'GET' && url.endsWith(`/devices/pairings/${PID}`)) {
      return { json: claim ? { status: 'claimed', expires_at: 0, claim } : { status: 'pending', expires_at: 0 } };
    }
    if (method === 'POST' && url.endsWith('/confirm')) return { status: 201, json: { id: claim.key_id, kind: 'phone' } };
    if (method === 'GET' && url.endsWith(`/vault/${VAULT}/keys`)) return { json: { keys: [{ id: 'yubi-1', kind: 'bio' }] } };
    return { status: 404, json: { detail: { error: 'not_found' } } };
  });
  const session = await P.start({ vaultId: VAULT });
  assert.equal(calls[0].body.vault_id, VAULT);
  assert.deepEqual(Object.keys(calls[0].body).sort(), ['k_srv', 'vault_id']);
  assert.equal(kSrvSeen.length, 43);
  assert.ok(session.qr.startsWith(`hs1p:${PID}.`));
  const s = b64uDecode(session.qr.split('.')[1]);
  assert.ok(!JSON.stringify(calls).includes(session.qr.split('.')[1]), 's mag nooit naar de server');
  const { kSrv, kWeb } = await C.deriveKeys(s);
  assert.equal(b64uEncode(kSrv), kSrvSeen);

  // "app" claimt na de eerste poll
  const fields = { pairing_id: PID, pk_c: pk, k_dev_pub: 'AAAA', k_biosig_pub: 'BBBB', label: 'Testtoestel', model: 'Pixel', app_version: '0.3.4-Miller' };
  const t = C.transcript(fields);
  const ticks = [];
  const macWeb = b64uEncode(await C.mac(kWeb, t));
  setTimeout(() => {
    claim = { device_id: 'd1', key_id: '7d6c5b4a-3928-4170-8e6f-5d4c3b2a1908', ...fields, mac_web: macWeb };
  }, 30);
  const r = await P.waitForClaim(session, { pollMs: 20, onTick: (n) => ticks.push(n) });
  assert.equal(r.sas, await C.sas(t));
  assert.ok(ticks[0] <= 300 && ticks[0] >= 299);

  const pinned = [];
  const key = await P.confirm(session, {
    secret: fakeSecret(), pin: async (kid, p) => pinned.push([kid, p]), pins: () => ({ 'yubi-1': 'pk-yubi' }),
  });
  assert.equal(key.kind, 'phone');
  assert.deepEqual(pinned, [[claim.key_id, pk]]);
  const conf = calls.find((c) => c.url.endsWith('/confirm'));
  assert.deepEqual(Object.keys(conf.body), ['sealed']);
  const sealed = JSON.parse(conf.body.sealed);
  assert.deepEqual(Object.keys(sealed), ['v', 'kid', 'epk', 'iv', 'ct']);
  assert.equal(sealed.kid, claim.key_id);
  assert.ok(C.checkSealedShape(conf.body.sealed, claim.key_id));

  const kw = session.kWeb;
  P.wipe(session);
  assert.ok(kw.every((b) => b === 0), 'k_web gewist');
  assert.equal(session.kWeb, null);
  assert.equal(session.qr, null);
});

test('confirm: key_id van de server al in de sleutellijst of al vastgelegd → pairing_key_exists, niets verzegeld of vastgelegd', async () => {
  const PID = '5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d';
  const VAULT = '3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b';
  const KID = '7d6c5b4a-3928-4170-8e6f-5d4c3b2a1908';
  const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pk = b64uEncode(new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey)));
  let listed = [];
  let listStatus = 200;
  const calls = fakeServer(async (method, url) => {
    if (method === 'POST' && url.endsWith('/devices/pairings')) return { status: 201, json: { pairing_id: PID, expires_at: Math.floor(Date.now() / 1000) + 300 } };
    if (method === 'GET' && url.endsWith(`/vault/${VAULT}/keys`)) return { status: listStatus, json: listStatus === 200 ? { keys: listed } : null };
    if (method === 'POST' && url.endsWith('/confirm')) return { status: 201, json: { id: KID, kind: 'phone' } };
    return { status: 404, json: { detail: { error: 'not_found' } } };
  });
  async function claimedSession() {
    const session = await P.start({ vaultId: VAULT });
    const { kWeb } = await C.deriveKeys(b64uDecode(session.qr.split('.')[1]));
    const fields = { pairing_id: PID, pk_c: pk, k_dev_pub: 'AAAA', k_biosig_pub: 'BBBB', label: 'Telefoon', model: 'Pixel', app_version: '0.3.4-Miller' };
    session.claim = { device_id: 'd1', key_id: KID, ...fields, mac_web: b64uEncode(await C.mac(kWeb, C.transcript(fields))) };
    session.sas = '123456';
    return session;
  }
  const pinned = [];
  const pin = async (kid, p) => pinned.push([kid, p]);
  const sealSpy = HK._crypto.seal;
  let sealed = 0;
  HK._crypto.seal = async (...a) => { sealed += 1; return sealSpy(...a); };
  try {
    // a. key_id staat al in de sleutellijst van de kluis (bv. het id van een YubiKey)
    listed = [{ id: KID, kind: 'bio' }];
    await assert.rejects(P.confirm(await claimedSession(), { secret: fakeSecret(), pin, pins: () => ({}) }),
      (e) => e.code === 'pairing_key_exists' && /Koppeling niet vertrouwd/.test(P.messageFor(e)));
    // b. key_id staat al vastgelegd in de KDBX (ook als de server hem uit de lijst weglaat)
    listed = [];
    await assert.rejects(P.confirm(await claimedSession(), { secret: fakeSecret(), pin, pins: () => ({ [KID]: 'pk-yubi' }) }),
      (e) => e.code === 'pairing_key_exists');
    // c. lijst niet op te halen → dicht
    listStatus = 500;
    await assert.rejects(P.confirm(await claimedSession(), { secret: fakeSecret(), pin, pins: () => ({}) }), (e) => e.code === 'api_500');
    // d. zonder pins-callback geen koppeling
    listStatus = 200;
    await assert.rejects(P.confirm(await claimedSession(), { secret: fakeSecret(), pin }), (e) => e.code === 'pin_save_failed');
    assert.equal(sealed, 0, 'niets verzegeld');
    assert.deepEqual(pinned, [], 'niets vastgelegd');
    assert.ok(!calls.some((c) => c.url.endsWith('/confirm')), 'geen confirm');
    // e. vrij key_id → wel
    const key = await P.confirm(await claimedSession(), { secret: fakeSecret(), pin, pins: () => ({ 'yubi-1': 'pk-yubi' }) });
    assert.equal(key.id, KID);
    assert.equal(sealed, 1);
    assert.deepEqual(pinned, [[KID, pk]]);
  } finally {
    HK._crypto.seal = sealSpy;
  }
});

test('flow: verkeerde mac_web → DELETE en pairing_untrusted (er wordt niets verzegeld)', async () => {
  const PID = 'c0ffee00-1234-4abc-9def-0123456789ab';
  const v = vectors[0];
  const calls = fakeServer(async (method, url) => {
    if (method === 'POST' && url.endsWith('/devices/pairings')) return { status: 201, json: { pairing_id: PID, expires_at: Math.floor(Date.now() / 1000) + 300 } };
    if (method === 'GET') return { json: { status: 'claimed', claim: { ...claimFrom(v), mac_web: v.mac_web } } };
    if (method === 'DELETE') return { status: 204 };
    return { status: 500 };
  });
  const session = await P.start({ vaultId: 'v' });
  await assert.rejects(P.waitForClaim(session, { pollMs: 5 }), (e) => e.code === 'pairing_untrusted');
  assert.ok(calls.some((c) => c.method === 'DELETE' && c.url.endsWith(`/devices/pairings/${PID}`)));
  assert.ok(!calls.some((c) => c.url.endsWith('/confirm')));
  await assert.rejects(P.confirm(session, { secret: fakeSecret() }), (e) => e.code === 'pairing_not_claimed');
  assert.match(P.messageFor({ code: 'pairing_untrusted' }), /^Koppeling niet vertrouwd — mogelijk gemanipuleerd/);
  P.wipe(session);
});

test('flow: verlopen → DELETE en pairing_expired; 404 → pairing_not_found; cancelled → pairing_cancelled', async () => {
  const PID = '5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d';
  let mode = 'pending';
  const calls = fakeServer(async (method, url) => {
    if (method === 'POST') return { status: 201, json: { pairing_id: PID, expires_at: Math.floor(Date.now() / 1000) + 300 } };
    if (method === 'DELETE') return { status: 204 };
    if (mode === '404') return { status: 404, json: { detail: { error: 'not_found' } } };
    return { json: { status: mode } };
  });
  const s1 = await P.start({ vaultId: 'v' });
  s1.startedAt = Date.now() - 301_000; // aftelling voorbij
  await assert.rejects(P.waitForClaim(s1, { pollMs: 5 }), (e) => e.code === 'pairing_expired');
  assert.ok(calls.some((c) => c.method === 'DELETE'));
  mode = '404';
  await assert.rejects(P.waitForClaim(await P.start({ vaultId: 'v' }), { pollMs: 5 }), (e) => e.code === 'pairing_not_found');
  mode = 'cancelled';
  await assert.rejects(P.waitForClaim(await P.start({ vaultId: 'v' }), { pollMs: 5 }), (e) => e.code === 'pairing_cancelled');
});

test('start: 403 stepup_required komt door als HwKeyError (stepup.js vangt hem af)', async () => {
  fakeServer(async () => ({ status: 403, json: { detail: { error: 'stepup_required' } } }));
  await assert.rejects(P.start({ vaultId: 'v' }), (e) => e instanceof HK.HwKeyError && e.code === 'stepup_required');
  fakeServer(async () => ({ status: 429, json: null }));
  await assert.rejects(P.start({ vaultId: 'v' }), (e) => e.code === 'api_429' && /Te veel koppelpogingen/.test(P.messageFor(e)));
});

test('checkSealedShape volgt validate_sealed (§12.5)', () => {
  const kid = '7d6c5b4a-3928-4170-8e6f-5d4c3b2a1908';
  const ok = { v: 2, kid, epk: 'A'.repeat(43), iv: 'B'.repeat(16), ct: 'C'.repeat(60) };
  assert.ok(C.checkSealedShape(JSON.stringify(ok), kid));
  assert.ok(!C.checkSealedShape(JSON.stringify({ ...ok, v: 1 }), kid));
  assert.ok(!C.checkSealedShape(JSON.stringify({ ...ok, kid: 'x' }), kid));
  assert.ok(!C.checkSealedShape(JSON.stringify({ ...ok, extra: 1 }), kid));
  assert.ok(!C.checkSealedShape(JSON.stringify({ ...ok, ct: 'C'.repeat(39) }), kid));
  assert.ok(!C.checkSealedShape(JSON.stringify({ ...ok, ct: 'C'.repeat(401) }), kid));
  assert.ok(!C.checkSealedShape(JSON.stringify({ ...ok, epk: 'A'.repeat(42) }), kid));
  assert.ok(!C.checkSealedShape('geen json', kid));
});
