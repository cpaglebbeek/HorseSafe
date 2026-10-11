// v0.2.0-Koblitz — cryptotests voor js/hwkeys.js (Seal_v2, §12.5). Node ≥ 20, geen browser nodig.
// Draai: node --test tests/unit/
// Testvectoren: specs/testvectors/seal_v2.json (gegenereerd door specs/testvectors/gen_seal_v2.py met de
// Python-referentie). Een ander pad kan via HS_SEAL_VECTORS; ontbreekt het bestand, dan falen de vectortests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');
// Zelfde realm als de test (runInThisContext): Node-WebCrypto en kdbxweb accepteren dan elkaars buffers.
vm.runInThisContext(read('../../vendor/kdbxweb/kdbxweb.min.js'));
vm.runInThisContext(read('../../js/hwkeys.js'));
const HK = globalThis.HorseSafeHwKeys;
const H = HK._crypto;
const kdbxweb = globalThis.kdbxweb;
const kbytes = (a) => Uint8Array.from(a);

const VAULT = '3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b';
const KID = '9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a';
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const u8 = (x) => new Uint8Array(x);
const same = (a, b) => assert.deepEqual(Array.from(a || []), Array.from(b || []));

const vectorPath = process.env.HS_SEAL_VECTORS
  || new URL('../../../specs/testvectors/seal_v2.json', import.meta.url).pathname;
const vectors = existsSync(vectorPath) ? JSON.parse(readFileSync(vectorPath, 'utf8')) : null;
// Nooit overslaan: de kruiscontrole JS == Python is acceptatie 2 (§10).
test('testvectoren aanwezig', () => assert.ok(vectors, `testvectoren ontbreken (${vectorPath})`));

// ───────────── sleutelafleiding ─────────────
test('zelfde PRF-uitvoer → zelfde sleutelpaar (deterministisch)', async () => {
  const p = rnd(32);
  const a = await H.keypairFromPrf(p);
  const b = await H.keypairFromPrf(p);
  assert.equal(a.publicKey, b.publicKey);
  assert.equal(a.publicKey.length, 43);
  assert.notEqual((await H.keypairFromPrf(rnd(32))).publicKey, a.publicKey);
});

test('PRF-uitvoer van verkeerde lengte wordt geweigerd', async () => {
  await assert.rejects(H.keypairFromPrf(rnd(16)), (e) => e.code === 'no_prf');
});

// ───────────── AAD en plaintext ─────────────
test('AAD = "HSv2" 0 purpose 0 vault_id 0 bind', () => {
  const aad = u8(H.buildAad('store', VAULT, KID));
  assert.equal(Buffer.from(aad).toString('utf8'), `HSv2\0store\0${VAULT}\0${KID}`);
  assert.throws(() => H.buildAad('anders', VAULT, KID), (e) => e.code === 'invalid_purpose');
});

test('plaintext is exact {"ph":…,"kh":…} zonder spaties; null voor ontbrekend deel', () => {
  const ph = new Uint8Array(32).fill(1);
  const kh = new Uint8Array(32).fill(2);
  const t = (a, b) => Buffer.from(u8(H.encodePlaintext(a, b))).toString('utf8');
  assert.equal(t(ph, kh), `{"ph":"${H.b64uEncode(ph)}","kh":"${H.b64uEncode(kh)}"}`);
  assert.equal(t(ph, null), `{"ph":"${H.b64uEncode(ph)}","kh":null}`);
  assert.equal(t(null, kh), `{"ph":null,"kh":"${H.b64uEncode(kh)}"}`);
  assert.throws(() => H.encodePlaintext(null, null), (e) => e.code === 'no_secret');
  assert.throws(() => H.encodePlaintext(new Uint8Array(31), null), (e) => e.code === 'invalid_secret');
});

// ───────────── verzegelen / openen ─────────────
async function fresh(raw = { ph: rnd(32), kh: rnd(32) }) {
  const p = rnd(32);
  const kp = await H.keypairFromPrf(p);
  const sealed = await H.seal(kp.publicKey, raw, { vaultId: VAULT, keyId: KID });
  return { p, kp, sealed, raw };
}

test('verzegelen naar publieke sleutel en openen met PRF (Seal_v2-vorm)', async () => {
  const { p, sealed, raw } = await fresh();
  const obj = JSON.parse(sealed);
  assert.deepEqual(Object.keys(obj), ['v', 'kid', 'epk', 'iv', 'ct']);
  assert.equal(obj.v, 2);
  assert.equal(obj.kid, KID);
  assert.equal(obj.epk.length, 43);
  assert.equal(obj.iv.length, 16);
  assert.ok(obj.ct.length >= 40 && obj.ct.length <= 400);
  assert.ok(sealed.length <= 1024);
  assert.ok(!sealed.includes(H.b64uEncode(raw.ph)), 'geen klare tekst in de kopie');
  const opened = await H.unseal(sealed, await H.keypairFromPrf(p), { vaultId: VAULT, keyId: KID });
  same(opened.ph, raw.ph);
  same(opened.kh, raw.kh);
});

test('alleen ph of alleen kh blijft intact', async () => {
  for (const raw of [{ ph: rnd(32), kh: null }, { ph: null, kh: rnd(32) }]) {
    const { kp, sealed } = await fresh(raw);
    const opened = await H.unseal(sealed, kp, { vaultId: VAULT, keyId: KID });
    assert.equal(opened.ph === null, raw.ph === null);
    assert.equal(opened.kh === null, raw.kh === null);
    same(opened.ph, raw.ph);
    same(opened.kh, raw.kh);
  }
});

test('elke verzegeling is uniek (verse efemere sleutel + iv)', async () => {
  const { kp, raw } = await fresh();
  const a = JSON.parse(await H.seal(kp.publicKey, raw, { vaultId: VAULT, keyId: KID }));
  const b = JSON.parse(await H.seal(kp.publicKey, raw, { vaultId: VAULT, keyId: KID }));
  assert.notEqual(a.epk, b.epk);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ct, b.ct);
});

test('verkeerde sleutel kan niet openen', async () => {
  const { sealed } = await fresh();
  await assert.rejects(H.unseal(sealed, await H.keypairFromPrf(rnd(32)), { vaultId: VAULT, keyId: KID }),
    (e) => e.code === 'unseal_failed');
});

test('AAD-binding: andere vault, andere key_id, andere purpose → unseal_failed', async () => {
  const { kp, sealed } = await fresh();
  const other = '00000000-0000-4000-8000-000000000000';
  await assert.rejects(H.unseal(sealed, kp, { vaultId: other, keyId: KID }), (e) => e.code === 'unseal_failed');
  await assert.rejects(H.unseal(sealed, kp, { vaultId: VAULT, keyId: other }), (e) => e.code === 'unseal_failed');
  // kid gelijk houden, maar bind anders: de AAD faalt, niet alleen de kid-controle
  await assert.rejects(H.unseal(sealed, kp, { vaultId: VAULT, keyId: KID, bind: other }), (e) => e.code === 'unseal_failed');
  await assert.rejects(H.unseal(sealed, kp, { vaultId: VAULT, keyId: KID, purpose: 'relay' }), (e) => e.code === 'unseal_failed');
});

test('kopie met omgezette kid wordt geweigerd (kid wordt nooit vertrouwd)', async () => {
  const { kp, sealed } = await fresh();
  const other = '11111111-1111-4111-8111-111111111111';
  const obj = JSON.parse(sealed);
  obj.kid = other;
  await assert.rejects(H.unseal(JSON.stringify(obj), kp, { vaultId: VAULT, keyId: other }), (e) => e.code === 'unseal_failed');
});

test('gemanipuleerde kopie of versie 1 wordt geweigerd', async () => {
  const { kp, sealed } = await fresh();
  const obj = JSON.parse(sealed);
  const ct = u8(H.b64uDecode(obj.ct)); ct[0] ^= 1;
  await assert.rejects(H.unseal(JSON.stringify({ ...obj, ct: H.b64uEncode(ct) }), kp, { vaultId: VAULT, keyId: KID }),
    (e) => e.code === 'unseal_failed');
  await assert.rejects(H.unseal(JSON.stringify({ ...obj, v: 1 }), kp, { vaultId: VAULT, keyId: KID }),
    (e) => e.code === 'unseal_failed');
  await assert.rejects(H.unseal('geen json', kp, { vaultId: VAULT, keyId: KID }), (e) => e.code === 'unseal_failed');
});

// ───────────── testvectoren (Python-referentie) ─────────────
test('PRF-vectoren: sk/pk gelijk aan de referentie', async () => {
  for (const v of vectors.prf_vectors) {
    const kp = await H.keypairFromPrf(u8(H.b64uDecode(v.prf)));
    assert.equal(kp.publicKey, v.pk);
  }
});

test('seal-vectoren: byte voor byte gelijk (sealWith) en te openen', async () => {
  for (const v of vectors.seal_vectors) {
    const dec = (x) => (x ? u8(H.b64uDecode(x)) : null);
    const r = await H.sealWith({
      recipientPk: v.recipient_pk, ph: dec(v.ph), kh: dec(v.kh), purpose: v.purpose, vaultId: v.vault_id,
      bind: v.bind, kid: v.kid, ephemeralSk: dec(v.ephemeral_sk), iv: dec(v.iv),
    });
    assert.equal(H.hex(u8(r.aad)), v.aad_hex, `${v.name}: aad`);
    assert.equal(Buffer.from(u8(r.pt)).toString('utf8'), v.pt_utf8, `${v.name}: pt`);
    assert.equal(H.hex(u8(r.k)), v.k_hex, `${v.name}: k`);
    assert.equal(r.sealed, v.sealed, `${v.name}: sealed`);
    assert.equal(JSON.parse(r.sealed).epk, v.ephemeral_pk);
    // Openen met de ontvanger-privésleutel uit de vector
    const sk = await crypto.subtle.importKey('pkcs8', Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(dec(v.recipient_sk))]),
    { name: 'X25519' }, true, ['deriveBits']);
    const kp = { privateKey: sk, publicKey: v.recipient_pk };
    const opened = await H.unseal(v.sealed, kp, { vaultId: v.vault_id, keyId: v.kid, purpose: v.purpose, bind: v.bind });
    same(opened.ph, dec(v.ph));
    same(opened.kh, dec(v.kh));
  }
});

test('negatieve vectoren falen met unseal_failed', async () => {
  for (const n of vectors.negative) {
    const v = vectors.seal_vectors.find((s) => s.name === n.based_on);
    const sk = await crypto.subtle.importKey('pkcs8', Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(u8(H.b64uDecode(v.recipient_sk)))]),
    { name: 'X25519' }, true, ['deriveBits']);
    const kp = { privateKey: sk, publicKey: v.recipient_pk };
    const ow = n.open_with || {};
    let sealed = ow.sealed || v.sealed;
    const flip = n.mutate && n.mutate.ct_flip_byte;
    if (!ow.sealed && (flip !== undefined || /ct/.test(n.name))) {
      const obj = JSON.parse(sealed);
      const ct = u8(H.b64uDecode(obj.ct)); ct[flip || 0] ^= 1; obj.ct = H.b64uEncode(ct);
      sealed = JSON.stringify(obj);
    }
    const keyId = ow.key_id || v.kid;
    await assert.rejects(
      H.unseal(sealed, kp, { vaultId: ow.vault_id || v.vault_id, keyId, purpose: ow.purpose || v.purpose, bind: ow.bind || ow.key_id || v.bind }),
      (e) => e.code === n.expect, n.name,
    );
  }
});

// ───────────── kdbxweb-koppeling ─────────────
async function compositeHash(cred) {
  return u8(await cred.getHash());
}

test('secretFromCredentials → credentialsFromHashes geeft dezelfde samengestelde sleutel als pw + keyfile', async () => {
  const kf = new TextEncoder().encode('0123456789abcdef'.repeat(4)); // 64-hex keyfile
  const pv = kdbxweb.ProtectedValue.fromString('correct horse battery staple');
  const orig = new kdbxweb.Credentials(pv, kbytes(kf));
  await orig.ready;
  const secret = await HK.secretFromCredentials(orig);
  assert.ok(secret.ph && secret.kh);
  // ph = SHA-256(UTF-8(pw)); kh bij 64-hex = de 32 gedecodeerde bytes
  const ph = u8(secret.ph.getBinary());
  same(ph, u8(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('correct horse battery staple'))));
  same(u8(secret.kh.getBinary()), Buffer.from('0123456789abcdef'.repeat(4), 'hex'));
  const back = HK.credentialsFromHashes(secret);
  same(await compositeHash(back), await compositeHash(orig));
});

test('alleen keyfile en alleen wachtwoord: leeg deel blijft leeg (null)', async () => {
  const onlyKf = new kdbxweb.Credentials(null, kbytes(rnd(32)));
  const s1 = await HK.secretFromCredentials(onlyKf);
  assert.equal(s1.ph, null);
  same(await compositeHash(HK.credentialsFromHashes(s1)), await compositeHash(onlyKf));
  const onlyPw = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('wachtwoord123'), null);
  const s2 = await HK.secretFromCredentials(onlyPw);
  assert.equal(s2.kh, null);
  same(await compositeHash(HK.credentialsFromHashes(s2)), await compositeHash(onlyPw));
});

test('wipeSecret wist de ProtectedValues en raakt de Credentials van de kluis niet', async () => {
  const orig = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('wachtwoord123'), kbytes(rnd(32)));
  const before = await compositeHash(orig);
  const secret = await HK.secretFromCredentials(orig);
  const creds = HK.credentialsFromHashes(secret);
  const phPv = secret.ph;
  HK.wipeSecret(secret);
  assert.equal(secret.ph, null);
  assert.ok(u8(phPv.value).every((b) => b === 0));
  same(await compositeHash(orig), before);
  same(await compositeHash(creds), before);
});

test('volledige ronde: Credentials → seal → unseal → Credentials opent identiek', async () => {
  const orig = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('Kluis-wachtwoord!'), kbytes(rnd(64)));
  const secret = await HK.secretFromCredentials(orig);
  const raw = { ph: u8(secret.ph.getBinary()), kh: u8(secret.kh.getBinary()) };
  const { kp, sealed } = await fresh(raw);
  const opened = await H.unseal(sealed, kp, { vaultId: VAULT, keyId: KID });
  const pv = (b) => kdbxweb.ProtectedValue.fromBinary(new Uint8Array(b));
  const creds = HK.credentialsFromHashes({ ph: pv(opened.ph), kh: pv(opened.kh) });
  same(await compositeHash(creds), await compositeHash(orig));
});

// ───────────── meldingen ─────────────
test('Nederlandse meldingen en extra velden op de fout', () => {
  const e = new HK.HwKeyError('recovery_waiting', undefined, { error: 'recovery_waiting', state: 'waiting', release_at: Date.now() / 1000 + 3 * 3600 + 120 });
  assert.equal(e.state, 'waiting');
  assert.match(HK.messageFor(e), /wacht nog 3 u [12] m/);
  assert.equal(HK.messageFor(new HK.HwKeyError('no_prf')), HK.MESSAGES.no_prf);
  assert.equal(HK.messageFor({ name: 'NotAllowedError' }), HK.MESSAGES.cancelled);
  assert.match(HK.messageFor(new HK.HwKeyError('api_500')), /Serverfout \(500\)/);
  for (const c of ['browser_unsupported', 'safari', 'wrong_host', 'no_prf', 'uv_missing', 'not_device_bound', 'synced',
    'attestation_invalid', 'authenticator_not_allowed', 'not_bio_authenticator', 'credential_exists', 'too_many_keys',
    'invalid_challenge', 'sign_count_regression', 'unseal_failed', 'recovery_idle', 'recovery_expired',
    'recovery_consumed', 'recovery_blocked', 'notify_unavailable', 'notify_failed', 'nothing_to_cancel', 'not_blocked',
    'stepup_required', 'stepup_bio_required', 'stepup_unavailable', 'keys_mismatch', 'etag_mismatch', 'stale_copy']) {
    assert.ok(HK.MESSAGES[c], `melding ontbreekt: ${c}`);
  }
});
