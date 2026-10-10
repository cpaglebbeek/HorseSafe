/* HorseSafe hardware-sleutels v0.2.0-Koblitz — zie docs/HARDWARE_KEYS.md
 *
 * Ontgrendelen met een YubiKey (Bio: vingerafdruk; noodsleutel: lange PIN) via WebAuthn PRF.
 *
 *   PRF-uitvoer (32 B, alleen in de browser)
 *     └─ HKDF ─▶ X25519-privésleutel  ──▶ publieke sleutel staat op de server
 *   ontgrendelmateriaal {pw, kf}  ── ECIES (X25519 + HKDF + AES-256-GCM) ──▶ verzegelde kopie op de server
 *
 * De server kan de kopie niet openen: daarvoor is de PRF-uitvoer nodig, en die verlaat de sleutel
 * alleen na verificatie (vinger of PIN) en alleen naar deze browser-tab. Verzegelen naar de publieke
 * sleutel kan zonder de sleutel zelf — zo hoeft de noodsleutel bij een nieuwe keyfile niet uit de kluis.
 *
 * Werkt ook onder Node ≥ 20 (globalThis.crypto) voor de cryptotests; WebAuthn alleen in de browser.
 */
(function (root) {
  'use strict';

  const subtle = root.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const SEAL_AAD = enc.encode('HorseSafe v1 seal');
  // PKCS#8-omhulsel voor een ruwe X25519-privésleutel (RFC 8410)
  const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
    0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

  class HwKeyError extends Error {
    constructor(code, message) { super(message || code); this.code = code; }
  }

  // ───────────── hulpfuncties ─────────────
  function b64uEncode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uDecode(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  function random(n) { return root.crypto.getRandomValues(new Uint8Array(n)); }

  async function hkdf(ikm, salt, info) {
    const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, k, 256);
    return new Uint8Array(bits);
  }

  // ───────────── crypto ─────────────
  /** Deterministisch X25519-sleutelpaar uit de PRF-uitvoer van een sleutel. */
  async function keypairFromPrf(prf) {
    const seed = await hkdf(new Uint8Array(prf), new Uint8Array(32), 'HorseSafe v1 X25519');
    const priv = await subtle.importKey('pkcs8', concat(PKCS8_X25519, seed), { name: 'X25519' }, true, ['deriveBits']);
    const jwk = await subtle.exportKey('jwk', priv);
    seed.fill(0);
    return { privateKey: priv, publicKey: jwk.x };
  }

  async function sealKey(shared, epkRaw, pubRaw, usage) {
    const keyBytes = await hkdf(shared, concat(epkRaw, pubRaw), 'HorseSafe v1 seal');
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, [usage]);
    keyBytes.fill(0);
    return key;
  }

  /** Verzegel {pw, kf} voor een publieke X25519-sleutel (base64url). Geeft JSON-string terug. */
  async function seal(secret, publicKeyB64) {
    const pubRaw = b64uDecode(publicKeyB64);
    const pub = await subtle.importKey('raw', pubRaw, { name: 'X25519' }, false, []);
    const eph = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, eph.privateKey, 256));
    const epkRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
    const key = await sealKey(shared, epkRaw, pubRaw, 'encrypt');
    shared.fill(0);
    const iv = random(12);
    const plain = enc.encode(JSON.stringify({ pw: secret.pw || null, kf: secret.kf || null }));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: SEAL_AAD }, key, plain);
    plain.fill(0);
    return JSON.stringify({ v: 1, epk: b64uEncode(epkRaw), iv: b64uEncode(iv), ct: b64uEncode(ct) });
  }

  /** Open een verzegelde kopie met het sleutelpaar uit keypairFromPrf. */
  async function unseal(sealed, keypair) {
    const obj = JSON.parse(sealed);
    if (obj.v !== 1) throw new HwKeyError('sealed_version');
    const epkRaw = b64uDecode(obj.epk);
    const epk = await subtle.importKey('raw', epkRaw, { name: 'X25519' }, false, []);
    const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: epk }, keypair.privateKey, 256));
    const key = await sealKey(shared, epkRaw, b64uDecode(keypair.publicKey), 'decrypt');
    shared.fill(0);
    let plain;
    try {
      plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64uDecode(obj.iv), additionalData: SEAL_AAD }, key, b64uDecode(obj.ct));
    } catch (_) {
      throw new HwKeyError('unseal_failed', 'Deze sleutel past niet bij de verzegelde kopie.');
    }
    const bytes = new Uint8Array(plain);
    const out = JSON.parse(dec.decode(bytes));
    bytes.fill(0);
    return out;
  }

  // ───────────── WebAuthn ─────────────
  const FLAG_UV = 0x04;
  const FLAG_BE = 0x08;

  function authFlags(authData) {
    const bytes = new Uint8Array(authData);
    if (bytes.length < 37) throw new HwKeyError('bad_authdata');
    return bytes[32];
  }

  function rpId() { return root.location.hostname; }

  async function isSupported() {
    if (!root.PublicKeyCredential || !root.navigator || !root.navigator.credentials) return false;
    try {
      await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      return true;
    } catch (_) {
      return false;
    }
  }

  /** Nieuwe credential op een externe sleutel; eist verificatie en een niet-gesynchroniseerde sleutel. */
  async function createCredential({ userId, userName, salt, excludeIds }) {
    const cred = await root.navigator.credentials.create({
      publicKey: {
        rp: { name: 'HorseSafe', id: rpId() },
        user: { id: enc.encode(userId), name: userName, displayName: userName },
        challenge: random(32),
        pubKeyCredParams: [
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          residentKey: 'discouraged',
          requireResidentKey: false,
          userVerification: 'required',
        },
        hints: ['security-key'],
        attestation: 'none',
        timeout: 120000,
        excludeCredentials: (excludeIds || []).map((id) => ({ type: 'public-key', id: b64uDecode(id) })),
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    const ext = cred.getClientExtensionResults();
    if (!ext.prf || ext.prf.enabled === false) {
      throw new HwKeyError('no_prf', 'Deze sleutel of browser ondersteunt PRF niet. Gebruik een YubiKey 5/Bio in Chrome of Edge.');
    }
    const authData = cred.response.getAuthenticatorData ? cred.response.getAuthenticatorData() : null;
    if (authData) {
      const flags = authFlags(authData);
      if (!(flags & FLAG_UV)) throw new HwKeyError('no_uv', 'De sleutel heeft geen vingerafdruk of PIN gevraagd.');
      if (flags & FLAG_BE) {
        throw new HwKeyError('synced', 'Dit is een gesynchroniseerde passkey (iCloud/Google). Alleen een fysieke sleutel is toegestaan.');
      }
    }
    const first = ext.prf.results && ext.prf.results.first;
    return { credentialId: b64uEncode(cred.rawId), prf: first ? new Uint8Array(first) : null };
  }

  /** Vraag de sleutel om zijn PRF-uitvoer. keys: [{credential_id, prf_salt}]. */
  async function evaluatePrf(keys) {
    const evalByCredential = {};
    for (const k of keys) evalByCredential[k.credential_id] = { first: b64uDecode(k.prf_salt) };
    const a = await root.navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: rpId(),
        allowCredentials: keys.map((k) => ({ type: 'public-key', id: b64uDecode(k.credential_id) })),
        userVerification: 'required',
        hints: ['security-key'],
        timeout: 120000,
        extensions: { prf: { evalByCredential } },
      },
    });
    if (!(authFlags(a.response.authenticatorData) & FLAG_UV)) {
      throw new HwKeyError('no_uv', 'De sleutel heeft geen vingerafdruk of PIN gevraagd.');
    }
    const ext = a.getClientExtensionResults();
    const first = ext.prf && ext.prf.results && ext.prf.results.first;
    if (!first) throw new HwKeyError('no_prf', 'De sleutel gaf geen PRF-uitvoer terug.');
    return { credentialId: b64uEncode(a.rawId), prf: new Uint8Array(first) };
  }

  // ───────────── API ─────────────
  async function api(method, path, body) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(root.HorseSafeAPI.base + path, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* 204 */ }
    return { ok: res.ok, status: res.status, data };
  }

  const keysPath = (vaultId) => `/vault/${encodeURIComponent(vaultId)}/keys`;

  async function listKeys(vaultId) {
    const r = await api('GET', keysPath(vaultId));
    if (!r.ok) throw new HwKeyError('api_' + r.status);
    return r.data;
  }

  /**
   * Koppel een sleutel aan de kluis. secret = {pw, kf} — het materiaal waarmee deze kluis nu open is.
   * kind: 'bio' (YubiKey Bio, dagelijks) of 'recovery' (reservesleutel uit de kluis, wachttijd).
   */
  async function enroll({ vaultId, kind, label, secret, existingKeys }) {
    const meRes = await api('GET', '/auth/me');
    if (!meRes.ok) throw new HwKeyError('api_' + meRes.status);
    const salt = random(32);
    const created = await createCredential({
      userId: meRes.data.id,
      userName: meRes.data.email,
      salt,
      excludeIds: (existingKeys || []).map((k) => k.credential_id),
    });
    const keyInfo = { credential_id: created.credentialId, prf_salt: b64uEncode(salt) };
    // Sommige sleutels geven bij aanmaken nog geen PRF-uitvoer: dan één keer uitlezen
    const prf = created.prf || (await evaluatePrf([keyInfo])).prf;
    const kp = await keypairFromPrf(prf);
    prf.fill(0);
    const sealed = await seal(secret, kp.publicKey);
    await unseal(sealed, kp); // proef op de som vóór opslaan
    const r = await api('POST', keysPath(vaultId), {
      kind, label, credential_id: keyInfo.credential_id, prf_salt: keyInfo.prf_salt, public_key: kp.publicKey, sealed,
    });
    if (!r.ok) throw new HwKeyError((r.data && r.data.detail && r.data.detail.error) || 'api_' + r.status);
    return r.data;
  }

  /** Ontgrendel met een van de opgegeven sleutels. Geeft {secret, key} terug. */
  async function unlock({ vaultId, keys }) {
    if (!keys.length) throw new HwKeyError('no_keys');
    const { credentialId, prf } = await evaluatePrf(keys);
    const key = keys.find((k) => k.credential_id === credentialId);
    if (!key) throw new HwKeyError('unknown_key');
    const kp = await keypairFromPrf(prf);
    prf.fill(0);
    if (kp.publicKey !== key.public_key) throw new HwKeyError('unseal_failed', 'Deze sleutel hoort niet bij deze kluis.');
    const r = await api('GET', `${keysPath(vaultId)}/${encodeURIComponent(key.id)}/sealed`);
    if (!r.ok) {
      const d = (r.data && r.data.detail) || {};
      throw Object.assign(new HwKeyError(d.error || 'api_' + r.status), { releaseAt: d.release_at });
    }
    return { secret: await unseal(r.data.sealed, kp), key };
  }

  /** Verzegel nieuw ontgrendelmateriaal opnieuw voor alle sleutels — de sleutels hoeven er niet bij te zijn. */
  async function resealAll({ vaultId, keys, secret }) {
    if (!keys.length) return 0;
    const items = [];
    for (const k of keys) items.push({ id: k.id, sealed: await seal(secret, k.public_key) });
    const r = await api('PUT', `${keysPath(vaultId)}/sealed`, { items });
    if (!r.ok) throw new HwKeyError('api_' + r.status);
    return r.data.updated;
  }

  const requestRelease = (vaultId, keyId) => api('POST', `${keysPath(vaultId)}/${encodeURIComponent(keyId)}/release`);
  const cancelRelease = (vaultId, keyId) => api('DELETE', `${keysPath(vaultId)}/${encodeURIComponent(keyId)}/release`);
  const deleteKey = (vaultId, keyId) => api('DELETE', `${keysPath(vaultId)}/${encodeURIComponent(keyId)}`);

  /** Keyfile-bytes ↔ base64url voor het verzegelde materiaal. */
  const keyfileToB64 = (buf) => (buf ? b64uEncode(new Uint8Array(buf)) : null);
  const keyfileFromB64 = (s) => (s ? b64uDecode(s).buffer : null);

  root.HorseSafeHwKeys = {
    HwKeyError,
    isSupported,
    listKeys,
    enroll,
    unlock,
    resealAll,
    requestRelease,
    cancelRelease,
    deleteKey,
    keyfileToB64,
    keyfileFromB64,
    _crypto: { keypairFromPrf, seal, unseal, b64uEncode, b64uDecode },
  };
})(typeof window !== 'undefined' ? window : globalThis);
