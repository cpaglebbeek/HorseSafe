// v0.2.0-Koblitz — credentialsForRekey (js/hwkeys.js, §12.6.5): reviewronde 1, bevindingen 4 en 5.
// Node ≥ 20, geen browser nodig. Draai: node --test tests/unit/
//  - bevinding 5: een keyfile van 32 bytes deelt in kdbxweb zijn buffer met keyFileHash; wissen
//    van de invoer mag de nieuwe Credentials niet beschadigen (anders onopenbare kluis na save).
//  - bevinding 4: een onderdeel dat niet wijzigt blijft behouden (pw+keyfile blijft pw+keyfile).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');
vm.runInThisContext(read('../../vendor/kdbxweb/kdbxweb.min.js'));
vm.runInThisContext(read('../../js/hwkeys.js'));
const HK = globalThis.HorseSafeHwKeys;
const kdbxweb = globalThis.kdbxweb;

const PW = 'Oud-kluiswachtwoord-123';
const NEW_PW = 'Nieuw-kluiswachtwoord-456';
const keyfile32 = () => new Uint8Array(32).fill(7);
const keyfileHex = () => new TextEncoder().encode('ab'.repeat(32));

// kdbxweb leidt de KDBX-sleutel af van Credentials.getHash() = SHA-256(ph ‖ kh); twee Credentials
// met dezelfde getHash() openen dezelfde kluis. (Een echte save/load vraagt DOMParser; dat dekt de
// Playwright-test, hier vergelijken we de samengestelde sleutel rechtstreeks.)
async function composite(pw, kf) {
  const c = new kdbxweb.Credentials(pw ? kdbxweb.ProtectedValue.fromString(pw) : null, kf || null);
  return Array.from(new Uint8Array(await c.getHash()));
}
async function creds(pw, kf) {
  const c = new kdbxweb.Credentials(pw ? kdbxweb.ProtectedValue.fromString(pw) : null, kf || null);
  await c.ready;
  return c;
}
const hashOf = async (c) => Array.from(new Uint8Array(await c.getHash()));

test('keyfile van 32 bytes: wissen van de invoer na rekey beschadigt de nieuwe Credentials niet', async () => {
  const current = await creds(PW);
  const kf = keyfile32();
  const { credentials, secret } = await HK.credentialsForRekey({ current, keyFile: kf });
  const want = await composite(PW, keyfile32());
  assert.deepEqual(await hashOf(credentials), want); // zoals de rekey-blob
  kf.fill(0); // hwkeys-ui.js wist de invoer in `finally`
  HK.wipeSecret(secret); // en het verzegelde materiaal
  assert.deepEqual(await hashOf(credentials), want); // de eerstvolgende gewone save
});

test('regressie: zonder kopie wist kdbxweb zijn eigen keyFileHash mee (reden voor de fix)', async () => {
  const kf = keyfile32();
  const c = await creds(null, kf);
  const before = await hashOf(c);
  kf.fill(0);
  assert.notDeepEqual(await hashOf(c), before);
});

test('alleen nieuw wachtwoord: bestaande keyfile blijft (pw+keyfile blijft pw+keyfile)', async () => {
  const current = await creds(PW, keyfileHex());
  const { credentials, secret } = await HK.credentialsForRekey({ current, password: NEW_PW });
  assert.ok(secret.ph && secret.kh);
  HK.wipeSecret(secret);
  const got = await hashOf(credentials);
  assert.deepEqual(got, await composite(NEW_PW, keyfileHex()));
  assert.notDeepEqual(got, await composite(NEW_PW, null));
  // de huidige Credentials (kluis blijft open bij een fout) zijn niet aangetast
  assert.deepEqual(await hashOf(current), await composite(PW, keyfileHex()));
});

test('alleen nieuwe keyfile: bestaand wachtwoord blijft', async () => {
  const current = await creds(PW, keyfileHex());
  const { credentials } = await HK.credentialsForRekey({ current, keyFile: keyfile32() });
  assert.deepEqual(await hashOf(credentials), await composite(PW, keyfile32()));
});

test('expliciet verwijderen: keyfile weg, alleen wachtwoord', async () => {
  const current = await creds(PW, keyfileHex());
  const { credentials, secret } = await HK.credentialsForRekey({ current, removeKeyFile: true });
  assert.equal(secret.kh, null);
  assert.deepEqual(await hashOf(credentials), await composite(PW, null));
});

test('expliciet verwijderen + nieuw: wachtwoord weg, nieuwe keyfile', async () => {
  const current = await creds(PW, keyfileHex());
  const { credentials } = await HK.credentialsForRekey({ current, removePassword: true, keyFile: keyfile32() });
  assert.deepEqual(await hashOf(credentials), await composite(null, keyfile32()));
});

test('ongeldige combinaties worden geweigerd', async () => {
  const pwOnly = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(PW));
  await pwOnly.ready;
  const code = (c) => (e) => e && e.code === c;
  await assert.rejects(() => HK.credentialsForRekey({ current: pwOnly }), code('rekey_nothing'));
  await assert.rejects(
    () => HK.credentialsForRekey({ current: pwOnly, password: NEW_PW, removePassword: true }),
    code('rekey_conflict'),
  );
  await assert.rejects(
    () => HK.credentialsForRekey({ current: pwOnly, removePassword: true }),
    code('rekey_no_factor'),
  );
});
