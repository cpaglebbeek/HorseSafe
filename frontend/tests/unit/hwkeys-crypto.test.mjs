// v0.2.0-Koblitz — cryptotest voor js/hwkeys.js (Node ≥ 20, geen browser nodig).
// Draai: node --test tests/unit/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const src = readFileSync(new URL('../../js/hwkeys.js', import.meta.url), 'utf8');
const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, fetch: undefined };
ctx.globalThis = ctx;
vm.runInNewContext(src, ctx);
const H = ctx.HorseSafeHwKeys._crypto;
const prf = () => crypto.getRandomValues(new Uint8Array(32));
const secret = { pw: 'correct horse battery staple', kf: H.b64uEncode(crypto.getRandomValues(new Uint8Array(64))) };

test('zelfde PRF-uitvoer → zelfde sleutelpaar (deterministisch)', async () => {
  const p = prf();
  const a = await H.keypairFromPrf(p);
  const b = await H.keypairFromPrf(p);
  assert.equal(a.publicKey, b.publicKey);
  assert.equal(a.publicKey.length, 43);
  assert.notEqual((await H.keypairFromPrf(prf())).publicKey, a.publicKey);
});

test('verzegelen naar publieke sleutel en openen met PRF', async () => {
  const p = prf();
  const kp = await H.keypairFromPrf(p);
  const sealed = await H.seal(secret, kp.publicKey);  // alleen de publieke sleutel nodig
  const obj = JSON.parse(sealed);
  assert.equal(obj.v, 1);
  assert.ok(!sealed.includes(secret.pw) && !sealed.includes(secret.kf), 'geen klare tekst in de kopie');
  const opened = await H.unseal(sealed, await H.keypairFromPrf(p));
  assert.deepEqual({ ...opened }, secret);
});

test('elke verzegeling is uniek (verse efemere sleutel + iv)', async () => {
  const kp = await H.keypairFromPrf(prf());
  const a = JSON.parse(await H.seal(secret, kp.publicKey));
  const b = JSON.parse(await H.seal(secret, kp.publicKey));
  assert.notEqual(a.epk, b.epk);
  assert.notEqual(a.ct, b.ct);
});

test('verkeerde sleutel kan niet openen', async () => {
  const kp = await H.keypairFromPrf(prf());
  const sealed = await H.seal(secret, kp.publicKey);
  await assert.rejects(H.unseal(sealed, await H.keypairFromPrf(prf())), (e) => e.code === 'unseal_failed');
});

test('gemanipuleerde kopie wordt geweigerd (GCM-tag)', async () => {
  const kp = await H.keypairFromPrf(prf());
  const obj = JSON.parse(await H.seal(secret, kp.publicKey));
  const ct = H.b64uDecode(obj.ct); ct[0] ^= 1; obj.ct = H.b64uEncode(ct);
  await assert.rejects(H.unseal(JSON.stringify(obj), kp), (e) => e.code === 'unseal_failed');
});

test('alleen keyfile (geen wachtwoord) blijft intact', async () => {
  const p = prf();
  const kp = await H.keypairFromPrf(p);
  const opened = await H.unseal(await H.seal({ pw: null, kf: secret.kf }, kp.publicKey), kp);
  assert.equal(opened.pw, null);
  assert.equal(opened.kf, secret.kf);
});
