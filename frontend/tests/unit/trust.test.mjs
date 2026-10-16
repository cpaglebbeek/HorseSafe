// v0.4.0-Montgomery — vectortests voor js/trust.js (vertrouwde browser + telefoonvinger, docs/HARDWARE_KEYS.md §14.2)
// Node ≥ 20, geen browser nodig. Draai: node --test tests/unit/
// Testvectoren: specs/testvectors/trust_v1.json (generator gen_trust_v1.py). Ander pad via HS_TRUST_VECTORS;
// ontbreekt het bestand, dan falen de vectortests (nooit overslaan: JS == Python == Kotlin).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

// Nep-API (alleen voor de flowtests onderaan); hwkeys.js/trust.js lezen HorseSafeAPI pas bij gebruik.
const env = { routes: {}, calls: [] };
const reply = (status, data) => ({ ok: status >= 200 && status < 300, status, data });
function route(name) {
  return async (...args) => {
    env.calls.push({ name, args });
    const h = env.routes[name];
    if (!h) return reply(404, { detail: { error: 'not_found' } });
    return h(...args);
  };
}
globalThis.HorseSafeAPI = {
  base: 'http://api',
  trust: { create: route('trust.create'), list: route('trust.list'), revoke: route('trust.revoke'),
    challenge: route('trust.challenge'), login: route('trust.login') },
  approvals: { create: route('ap.create'), submit: route('ap.submit'), status: route('ap.status'), cancel: route('ap.cancel') },
};

vm.runInThisContext(read('../../vendor/kdbxweb/kdbxweb.min.js'));
vm.runInThisContext(read('../../js/hwkeys.js'));
vm.runInThisContext(read('../../js/trust.js'));
const HK = globalThis.HorseSafeHwKeys;
const T = globalThis.HorseSafeTrust;
const kdbxweb = globalThis.kdbxweb;
const { b64uEncode, b64uDecode } = HK._crypto;
const hex = (b) => Buffer.from(b).toString('hex');
const utf8 = (s) => new TextEncoder().encode(s);

const vectorPath = process.env.HS_TRUST_VECTORS
  || new URL('../../../specs/testvectors/trust_v1.json', import.meta.url).pathname;
const data = existsSync(vectorPath) ? JSON.parse(readFileSync(vectorPath, 'utf8')) : null;
test('testvectoren trust_v1 aanwezig', () => {
  assert.ok(data, `testvectoren ontbreken (${vectorPath})`);
  assert.equal(data.format, 'HorseSafe trust_v1 testvectors');
  assert.equal(data.proof_vectors.length, 2);
});
const proofs = data ? data.proof_vectors : [];
const lv = data ? data.login_vector : null;
const av = data ? data.approval_vector : null;
const neg = (name) => data.negative.find((n) => n.name === name);
const raw = (v) => (v ? b64uDecode(v) : null);

/** K_B uit d_hex (vaste testsleutel); x/y uit de SPKI (laatste 64 bytes van het ongecomprimeerde punt). */
async function vectorKey() {
  const spki = b64uDecode(data.browser_key.pub_b);
  const pt = spki.slice(spki.length - 65);
  assert.equal(pt[0], 0x04);
  const jwk = {
    kty: 'EC', crv: 'P-256',
    d: b64uEncode(Buffer.from(data.browser_key.d_hex, 'hex')),
    x: b64uEncode(pt.slice(1, 33)), y: b64uEncode(pt.slice(33, 65)),
  };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function proofFor(v, change = {}) {
  const f = { ...v, ...change };
  const pt = T._crypto.ptCk(raw(f.ph), raw(f.kh));
  const kb = await T.kBind(pt, f.vault_id);
  return T.proof(kb, T.bindT(f.vault_id, f.browser_id, f.pub_b, f.label));
}

// ───────────── k_bind / bind_t / proof ─────────────
for (const v of proofs) {
  test(`vector ${v.name}: pt_ck, k_bind, bind_t en proof`, async () => {
    const pt = T._crypto.ptCk(raw(v.ph), raw(v.kh));
    assert.equal(new TextDecoder().decode(pt), v.pt_ck);
    assert.equal(hex(await T.kBind(pt, v.vault_id)), v.k_bind_hex);
    assert.equal(hex(T.bindT(v.vault_id, v.browser_id, v.pub_b, v.label)), v.bind_t_hex);
    assert.equal(await proofFor(v), v.proof);
  });

  test(`vector ${v.name}: proofFromSecret uit ProtectedValues (zoals de geopende kluis)`, async () => {
    const pv = (b) => (b ? kdbxweb.ProtectedValue.fromBinary(new Uint8Array(b)) : null);
    const secret = { ph: pv(raw(v.ph)), kh: pv(raw(v.kh)) };
    assert.equal(await T.proofFromSecret({ secret, vaultId: v.vault_id, browserId: v.browser_id, pubB: v.pub_b, label: v.label }), v.proof);
    // Het geheim zelf blijft intact (alleen kopieën worden gewist)
    assert.equal(b64uEncode(secret.kh.getBinary()), v.kh);
  });
}

for (const name of ['ander vault_id', 'ander label', 'andere pub_b']) {
  test(`negatief: ${name} → proof wijkt af`, async () => {
    const n = neg(name);
    const base = proofs.find((p) => p.name === n.based_on);
    assert.notEqual(await proofFor(base, n.change), base.proof);
  });
}

test('negatief: kh null → weigeren (vertrouwen vereist keyfile)', async () => {
  const n = neg('kh null');
  const base = proofs.find((p) => p.name === n.based_on);
  assert.throws(() => T._crypto.ptCk(raw(base.ph), null), (e) => e.code === 'trust_needs_keyfile');
  const ptNoKh = HK._crypto.encodePlaintext(raw(base.ph), null);
  await assert.rejects(T.kBind(ptNoKh, base.vault_id), (e) => e.code === 'trust_needs_keyfile');
  const secret = { ph: kdbxweb.ProtectedValue.fromBinary(raw(base.ph)), kh: null };
  await assert.rejects(T.proofFromSecret({ secret, vaultId: base.vault_id, browserId: base.browser_id, pubB: base.pub_b, label: base.label }),
    (e) => e.code === 'trust_needs_keyfile');
});

test('bind_t/login_t/req_t weigeren een veld met \\0', () => {
  const v = proofs[0];
  assert.throws(() => T.bindT(v.vault_id, v.browser_id, v.pub_b, 'a\0b'), (e) => e.code === 'invalid_request');
  assert.throws(() => T.loginT(lv.challenge_id, lv.challenge, lv.browser_id, 'x\0y'), (e) => e.code === 'invalid_request');
  assert.throws(() => T.reqT(av.approval_id, av.vault_id, av.browser_id, av.epk_l, av.nonce_l, 1.5), (e) => e.code === 'invalid_request');
});

test('labelregel (§13.5): 1–64 tekens, geen stuur-/opmaaktekens', () => {
  assert.ok(T.labelOk('Chrome – laptop'));
  assert.ok(!T.labelOk(''));
  assert.ok(!T.labelOk('x'.repeat(65)));
  assert.ok(!T.labelOk('Chrome‮potlal'));
  assert.ok(!T.labelOk('a\nb'));
});

// ───────────── login_t / req_t (bytes) ─────────────
test('login_t: bytes gelijk aan de vector (challenge als b64u én als bytes)', () => {
  assert.equal(hex(T.loginT(lv.challenge_id, lv.challenge, lv.browser_id, lv.email_lc)), lv.login_t_hex);
  assert.equal(hex(T.loginT(lv.challenge_id, b64uDecode(lv.challenge), lv.browser_id, lv.email_lc)), lv.login_t_hex);
});

test('req_t: bytes gelijk aan de vector', () => {
  assert.equal(hex(T.reqT(av.approval_id, av.vault_id, av.browser_id, av.epk_l, b64uDecode(av.nonce_l), av.created_at)), av.req_t_hex);
  assert.equal(hex(T.reqT(av.approval_id, av.vault_id, av.browser_id, av.epk_l, av.nonce_l, av.created_at)), av.req_t_hex);
});

// ───────────── P1363-handtekeningen ─────────────
test('verify: vector-handtekeningen (raw r‖s) kloppen met pub_b', async () => {
  assert.equal(data.browser_key.pub_b, lv.pub_b);
  assert.ok(await T.verify(lv.pub_b, Buffer.from(lv.login_t_hex, 'hex'), lv.sig));
  assert.ok(await T.verify(av.pub_b, Buffer.from(av.req_t_hex, 'hex'), av.sig_req));
  assert.equal(b64uDecode(av.sig_req).length, 64);
});

test('negatief: ander created_at → sig_req ongeldig', async () => {
  const n = neg('ander created_at');
  const t = T.reqT(av.approval_id, av.vault_id, av.browser_id, av.epk_l, av.nonce_l, n.change.created_at);
  assert.equal(await T.verify(av.pub_b, t, av.sig_req), false);
});

test('verify: verkeerde lengte, rommel en andere sleutel → false', async () => {
  const t = Buffer.from(lv.login_t_hex, 'hex');
  assert.equal(await T.verify(lv.pub_b, t, b64uDecode(lv.sig).slice(0, 63)), false);
  assert.equal(await T.verify(lv.pub_b, t, '!!'), false);
  const other = await T.generateBrowserKey();
  assert.equal(await T.verify(other.pubB, t, lv.sig), false);
});

test('signRaw: eigen handtekening met de vectorsleutel is 64 B en klopt met pub_b', async () => {
  const key = await vectorKey();
  const t = T.loginT(lv.challenge_id, lv.challenge, lv.browser_id, lv.email_lc);
  const sig = await T.signRaw(key, t);
  assert.equal(sig.length, 64);
  assert.ok(await T.verify(lv.pub_b, t, sig));
});

test('generateBrowserKey: P-256, niet exporteerbaar, pub_B = SPKI-DER (91 B)', async () => {
  const k = await T.generateBrowserKey();
  assert.equal(k.privateKey.extractable, false);
  assert.equal(k.privateKey.algorithm.namedCurve, 'P-256');
  assert.equal(b64uDecode(k.pubB).length, 91);
  const t = utf8('test');
  assert.ok(await T.verify(k.pubB, t, await T.signRaw(k.privateKey, t)));
});

// ───────────── relay openen ─────────────
async function vectorEl() {
  return { privateKey: await T._crypto.importX25519Private(b64uDecode(av.e_l_sk)), publicKey: av.epk_l };
}

test('relay: resp openen met e_l_sk geeft ph en kh', async () => {
  const out = await T.openRelay({ resp: av.resp, eL: await vectorEl(), vaultId: av.vault_id, approvalId: av.approval_id, nonceL: av.nonce_l, raw: true });
  assert.equal(b64uEncode(out.ph), av.ph);
  assert.equal(b64uEncode(out.kh), av.kh);
  assert.equal(hex(HK._crypto.buildAad('relay', av.vault_id, av.relay_bind)), av.relay_aad_hex);
});

test('relay: openen als ProtectedValues → credentialsFromHashes', async () => {
  const s = await T.openRelay({ resp: av.resp, eL: await vectorEl(), vaultId: av.vault_id, approvalId: av.approval_id, nonceL: b64uDecode(av.nonce_l) });
  assert.equal(b64uEncode(s.kh.getBinary()), av.kh);
  const c = HK.credentialsFromHashes(s);
  assert.ok(c.keyFileHash && c.passwordHash);
  HK.wipeSecret(s);
});

test('negatief: andere nonce bij openen → unseal_failed', async () => {
  const n = neg('andere nonce bij openen');
  await assert.rejects(
    T.openRelay({ resp: av.resp, eL: await vectorEl(), vaultId: av.vault_id, approvalId: av.approval_id, nonceL: n.change.nonce_l, raw: true }),
    (e) => e.code === 'unseal_failed',
  );
});

test('negatief: ander vault_id of approval_id (eigen verwachting) → unseal_failed', async () => {
  const eL = await vectorEl();
  await assert.rejects(T.openRelay({ resp: av.resp, eL, vaultId: '00000000-0000-4000-8000-000000000000', approvalId: av.approval_id, nonceL: av.nonce_l, raw: true }),
    (e) => e.code === 'unseal_failed');
  await assert.rejects(T.openRelay({ resp: av.resp, eL, vaultId: av.vault_id, approvalId: '00000000-0000-4000-8000-000000000001', nonceL: av.nonce_l, raw: true }),
    (e) => e.code === 'unseal_failed');
});

test('relay: purpose "store" in plaats van "relay" gaat niet open', async () => {
  const sealed = (await HK._crypto.sealWith({
    recipientPk: av.epk_l, ph: raw(av.ph), kh: raw(av.kh), purpose: 'store', vaultId: av.vault_id, bind: av.relay_bind, kid: av.approval_id,
  })).sealed;
  await assert.rejects(T.openRelay({ resp: sealed, eL: await vectorEl(), vaultId: av.vault_id, approvalId: av.approval_id, nonceL: av.nonce_l, raw: true }),
    (e) => e.code === 'unseal_failed');
});

test('relay: CK zonder kh wordt geweigerd', async () => {
  const sealed = (await HK._crypto.sealWith({
    recipientPk: av.epk_l, ph: raw(av.ph), kh: null, purpose: 'relay', vaultId: av.vault_id, bind: av.relay_bind, kid: av.approval_id,
  })).sealed;
  await assert.rejects(T.openRelay({ resp: sealed, eL: await vectorEl(), vaultId: av.vault_id, approvalId: av.approval_id, nonceL: av.nonce_l, raw: true }),
    (e) => e.code === 'approval_invalid');
});

test('newRelayKey: X25519, niet exporteerbaar, epk 32 B', async () => {
  const e = await T.newRelayKey();
  assert.equal(e.privateKey.extractable, false);
  assert.equal(b64uDecode(e.publicKey).length, 32);
});

// ───────────── flows met nep-API ─────────────
test('zonder IndexedDB: checkSupport uit, trustBrowser → trust_unsupported, geen records', async () => {
  assert.deepEqual(await T.checkSupport(), { ok: false, reason: 'trust_unsupported' });
  assert.deepEqual(await T.listRecords(), []);
  const v = proofs[0];
  const secret = { ph: null, kh: kdbxweb.ProtectedValue.fromBinary(raw(v.kh)) };
  env.calls = [];
  await assert.rejects(T.trustBrowser({ vaultId: v.vault_id, email: 'a@b.nl', label: 'Chrome – Linux', secret }),
    (e) => e.code === 'trust_unsupported');
  assert.equal(env.calls.length, 0);
  await assert.rejects(T.trustBrowser({ vaultId: v.vault_id, email: 'a@b.nl', label: 'Chrome – Linux', secret: { ph: secret.kh, kh: null } }),
    (e) => e.code === 'trust_needs_keyfile');
});

test('browserLogin: tekent login_t met K_B, stuurt totp; serverfout → browser_login_failed', async () => {
  const key = await vectorKey();
  const record = { browser_id: lv.browser_id, vault_id: av.vault_id, email: 'Christian@Example.com', label: 'x', key };
  let sent = null;
  env.routes['trust.challenge'] = async (email) => {
    assert.equal(email, lv.email_lc);
    return reply(200, { challenge_id: lv.challenge_id, challenge: lv.challenge, expires_at: 0 });
  };
  env.routes['trust.login'] = async (body) => {
    sent = body;
    const ok = await T.verify(lv.pub_b, Buffer.from(lv.login_t_hex, 'hex'), body.sig);
    return ok ? reply(200, { ok: true }) : reply(401, { detail: { error: 'browser_login_failed' } });
  };
  assert.deepEqual(await T.browserLogin({ record, totp: '123 456' }), { ok: true });
  assert.deepEqual(Object.keys(sent).sort(), ['browser_id', 'challenge_id', 'sig', 'totp']);
  assert.equal(sent.totp, '123456');
  env.routes['trust.login'] = async () => reply(401, { detail: { error: 'browser_login_failed' } });
  await assert.rejects(T.browserLogin({ record, totp: '123456' }), (e) => e.code === 'browser_login_failed');
  await assert.rejects(T.browserLogin({ record, totp: '12' }), (e) => e.code === 'invalid_code');
});

/** Nagebootste server + telefoon voor Flow C. decision: 'approve' | 'deny' | 'never' | 'tamper'. */
function approvalServer(decision, { ck }) {
  const st = { approval: null, polls: 0, deleted: false };
  env.routes['ap.create'] = async (vaultId, browserId) => {
    st.approval = { vaultId, browserId, id: 'a1b2c3d4-e5f6-4a7b-8c9d-000000000001', created_at: 1792150000, status: 'draft' };
    return reply(201, { approval_id: st.approval.id, created_at: st.approval.created_at });
  };
  env.routes['ap.submit'] = async (vaultId, id, body) => {
    st.body = body;
    // de server controleert sig_req met pub_B
    const t = T.reqT(id, vaultId, st.approval.browserId, body.epk_L, body.nonce_L, st.approval.created_at);
    if (!(await T.verify(ck.pubB, t, body.sig_req))) return reply(400, { detail: { error: 'signature_invalid' } });
    st.approval.status = 'pending';
    return reply(200, { expires_at: Math.floor(Date.now() / 1000) + 120 });
  };
  env.routes['ap.status'] = async (vaultId, id, wait) => {
    st.polls += 1;
    st.wait = wait;
    if (st.polls < 2 || decision === 'never') return reply(200, { status: 'pending' });
    if (decision === 'deny') return reply(200, { status: 'denied' });
    const bind = `${id}\0${st.body.nonce_L}`;
    const sealVault = decision === 'tamper' ? '00000000-0000-4000-8000-000000000000' : vaultId;
    const { sealed } = await HK._crypto.sealWith({
      recipientPk: st.body.epk_L, ph: raw(av.ph), kh: raw(av.kh), purpose: 'relay', vaultId: sealVault, bind, kid: id,
    });
    return reply(200, { status: 'approved', resp: sealed });
  };
  env.routes['ap.cancel'] = async () => { st.deleted = true; return reply(204, null); };
  return st;
}

test('Flow C: aanvragen → PUT met geldige sig_req → long-poll → goedgekeurd → CK open', async () => {
  const ck = await T.generateBrowserKey();
  const record = { browser_id: av.browser_id, vault_id: av.vault_id, email: 'a@b.nl', label: 'x', key: ck.privateKey };
  const st = approvalServer('approve', { ck });
  const session = await T.startApproval({ vaultId: av.vault_id, record });
  assert.deepEqual(Object.keys(st.body).sort(), ['epk_L', 'nonce_L', 'sig_req']);
  assert.equal(b64uDecode(st.body.nonce_L).length, 32);
  const ticks = [];
  const secret = await T.waitForDecision(session, { onTick: (s) => ticks.push(s) });
  assert.equal(b64uEncode(secret.kh.getBinary()), av.kh);
  assert.equal(b64uEncode(secret.ph.getBinary()), av.ph);
  assert.equal(st.wait, 25);
  assert.ok(ticks[0] <= 120 && ticks[0] >= 119);
  T.wipe(session);
  assert.equal(session.eL, null);
  assert.equal(session.nonceL, null);
  HK.wipeSecret(secret);
});

test('Flow C: geweigerd → approval_denied', async () => {
  const ck = await T.generateBrowserKey();
  const record = { browser_id: av.browser_id, vault_id: av.vault_id, email: 'a@b.nl', label: 'x', key: ck.privateKey };
  approvalServer('deny', { ck });
  const session = await T.startApproval({ vaultId: av.vault_id, record });
  await assert.rejects(T.waitForDecision(session), (e) => e.code === 'approval_denied');
});

test('Flow C: antwoord voor een andere kluis → approval_invalid, niets geopend', async () => {
  const ck = await T.generateBrowserKey();
  const record = { browser_id: av.browser_id, vault_id: av.vault_id, email: 'a@b.nl', label: 'x', key: ck.privateKey };
  approvalServer('tamper', { ck });
  const session = await T.startApproval({ vaultId: av.vault_id, record });
  await assert.rejects(T.waitForDecision(session), (e) => e.code === 'approval_invalid');
});

test('Flow C: verlopen → approval_expired en DELETE', async () => {
  const ck = await T.generateBrowserKey();
  const record = { browser_id: av.browser_id, vault_id: av.vault_id, email: 'a@b.nl', label: 'x', key: ck.privateKey };
  const st = approvalServer('never', { ck });
  const session = await T.startApproval({ vaultId: av.vault_id, record });
  session.startedAt = Date.now() - 119_500; // bijna verlopen
  session.expiresAt = Math.floor(session.startedAt / 1000) + 120;
  await assert.rejects(T.waitForDecision(session), (e) => e.code === 'approval_expired');
  assert.equal(st.deleted, true);
});

test('Flow C: serverfout bij POST (session_too_old) → melding, geen PUT', async () => {
  const ck = await T.generateBrowserKey();
  const record = { browser_id: av.browser_id, vault_id: av.vault_id, email: 'a@b.nl', label: 'x', key: ck.privateKey };
  env.calls = [];
  env.routes['ap.create'] = async () => reply(409, { detail: { error: 'session_too_old' } });
  await assert.rejects(T.startApproval({ vaultId: av.vault_id, record }), (e) => e.code === 'session_too_old' && /opnieuw in/.test(T.messageFor(e)));
  assert.ok(!env.calls.some((c) => c.name === 'ap.submit'));
  await assert.rejects(T.startApproval({ vaultId: 'andere-kluis', record }), (e) => e.code === 'no_trust_record');
});

test('Flow C: 401 session_revoked tijdens het wachten → approval_denied', async () => {
  const ck = await T.generateBrowserKey();
  const record = { browser_id: av.browser_id, vault_id: av.vault_id, email: 'a@b.nl', label: 'x', key: ck.privateKey };
  approvalServer('never', { ck });
  const session = await T.startApproval({ vaultId: av.vault_id, record });
  env.routes['ap.status'] = async () => reply(401, { detail: { error: 'invalid_token', reason: 'session_revoked' } });
  await assert.rejects(T.waitForDecision(session), (e) => e.code === 'approval_denied');
});
