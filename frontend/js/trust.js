/* HorseSafe vertrouwde browser + telefoonvinger v0.4.0-Montgomery — contract: docs/HARDWARE_KEYS.md §14 (§11.3)
 *
 *   K_B  = ECDSA P-256 (WebCrypto, extractable:false) in IndexedDB `horsesafe-trust`/`browsers`; herkent de browser.
 *   proof = HMAC(k_bind, bind_t), k_bind = HKDF(CK) — alleen wie de kluis open had kan het maken; de telefoon
 *           controleert het na de vinger. Er staat GEEN ontgrendelmateriaal in de browser (P-CRYPT-09).
 *   Ontgrendelen: per verzoek een tijdelijke X25519-sleutel e_L (extractable:false, alleen RAM); de telefoon
 *           verzegelt CK daarnaar (Seal_v2 purpose "relay"); de browser opent met de EIGEN vault_id/approval_id/nonce.
 *
 * Werkt ook onder Node ≥ 20 (globalThis.crypto) voor de vectortests (tests/unit/trust.test.mjs); IndexedDB en de
 * API alleen in de browser. Zonder IndexedDB/ECDSA/X25519 staat de functie uit met een duidelijke melding.
 */
(function (root) {
  'use strict';

  const HK = root.HorseSafeHwKeys;
  if (!HK) throw new Error('trust.js vereist hwkeys.js');
  const subtle = root.crypto.subtle;
  const enc = new TextEncoder();
  const { b64uEncode, b64uDecode, encodePlaintext } = HK._crypto;
  const HwKeyError = HK.HwKeyError;

  const DB_NAME = 'horsesafe-trust';
  const STORE = 'browsers';
  const APPROVAL_TTL = 120; // s (§14.5)
  const WAIT_S = 25; // long-poll (§14.6)
  const NONCE_BYTES = 32;
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const B64U_RE = /^[A-Za-z0-9_-]+$/;
  // Tekenregel labels (§13.5 stap 1, zelfde als pairing.js): geen Cc/Cf/Cs en geen U+2028/U+2029.
  const CTRL_RE = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;
  // PKCS#8-omhulsel voor een ruwe X25519-privésleutel (RFC 8410) — alleen voor de vectortests
  const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
    0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

  // ───────────── foutmeldingen (aanvulling op hwkeys.js §12.13) ─────────────
  const MESSAGES = {
    trust_unsupported: 'Deze browser kan niet vertrouwd worden (opslag of WebCrypto ontbreekt, of privévenster). Gebruik Chrome, Edge of Firefox buiten een privévenster.',
    trust_needs_keyfile: 'Vertrouwen kan alleen bij een kluis met keyfile.',
    trust_needs_totp: 'Stel eerst de authenticator-app in (Instellingen).',
    trust_exists: 'Deze browser is al vertrouwd voor deze kluis.',
    trust_save_failed: 'De browsersleutel kon niet in deze browser bewaard worden; er is niets vertrouwd.',
    invalid_label: 'Kies een naam van 1 tot 64 tekens, zonder speciale stuurtekens.',
    too_many_browsers: 'Je hebt al 10 vertrouwde browsers. Trek er eerst één in.',
    totp_required: 'Stel eerst de authenticator-app in (Instellingen).',
    browser_exists: 'Deze browser is al vertrouwd.',
    no_trust_record: 'Deze browser is niet vertrouwd voor deze kluis.',
    browser_login_failed: 'Inloggen met deze browser lukte niet. Controleer de code, of log in met je wachtwoord.',
    session_too_old: 'Je sessie is van vóór deze versie. Log opnieuw in om met je telefoon te ontgrendelen.',
    browser_cooldown: 'Een verzoek van deze browser is kort geleden geweigerd. Probeer het over een kwartier opnieuw.',
    approval_open: 'Er loopt al een verzoek. Rond dat eerst af op je telefoon of annuleer het.',
    too_many_approvals: 'Te veel verzoeken in het afgelopen uur. Probeer het later opnieuw.',
    api_429: 'Te veel verzoeken. Probeer het later opnieuw.',
    signature_invalid: 'De handtekening van deze browser werd geweigerd. Vergeet deze browser en vertrouw hem opnieuw.',
    no_phone_key: 'Er is geen telefoon gekoppeld aan deze kluis. Koppel eerst je telefoon (🔑 Sleutels).',
    approval_denied: 'Geweigerd op je telefoon.',
    approval_expired: 'Geen reactie, probeer opnieuw.',
    approval_cancelled: 'Het verzoek is geannuleerd.',
    approval_invalid: 'Het antwoord van de telefoon past niet bij dit verzoek. Er is niets geopend.',
    not_found: 'Deze browser is niet (meer) vertrouwd voor deze kluis, of de kluis bestaat niet.',
  };

  function messageFor(e) {
    if (e && typeof e.code === 'string' && MESSAGES[e.code]) return MESSAGES[e.code];
    return HK.messageFor(e);
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  /** "\0"-gescheiden UTF-8; een veld met "\0" maakt de codering dubbelzinnig → weigeren. */
  function joinFields(fields) {
    for (const f of fields) {
      if (typeof f !== 'string' || f.includes('\0')) throw new HwKeyError('invalid_request');
    }
    return enc.encode(fields.join('\0'));
  }

  function nonceText(nonce) {
    if (typeof nonce === 'string') {
      if (!B64U_RE.test(nonce)) throw new HwKeyError('invalid_request');
      return nonce;
    }
    return b64uEncode(nonce);
  }

  function labelOk(label) {
    return typeof label === 'string' && label.length >= 1 && label.length <= 64 && !CTRL_RE.test(label);
  }

  // ───────────── afleidingen (§14.2) ─────────────
  /** pt_ck = exact de Seal_v2-plaintext {"ph":…,"kh":…}. kh MOET aanwezig zijn (§11.3.7). Aanroeper wist. */
  function ptCk(ph, kh) {
    if (!kh) throw new HwKeyError('trust_needs_keyfile', MESSAGES.trust_needs_keyfile);
    return encodePlaintext(ph || null, kh);
  }

  /** k_bind = HKDF-SHA256(pt_ck, salt = SHA-256("HSv2 bind salt" 0x00 vault_id), info "HSv2 browser bind"). */
  async function kBind(pt, vaultId) {
    if (typeof vaultId !== 'string' || !vaultId) throw new HwKeyError('invalid_request');
    // Zelfde eis als ptCk: een pt_ck zonder kh wordt nooit gebonden.
    const txt = new TextDecoder().decode(pt);
    if (/"kh":null/.test(txt)) throw new HwKeyError('trust_needs_keyfile', MESSAGES.trust_needs_keyfile);
    const salt = new Uint8Array(await subtle.digest('SHA-256', concat(enc.encode('HSv2 bind salt'), Uint8Array.of(0), enc.encode(vaultId))));
    const k = await subtle.importKey('raw', pt, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('HSv2 browser bind') }, k, 256);
    return new Uint8Array(bits);
  }

  /** bind_t = "HSv2 browser" 0 vault_id 0 browser_id 0 pub_B 0 label */
  function bindT(vaultId, browserId, pubB, label) {
    return joinFields(['HSv2 browser', vaultId, browserId, pubB, label]);
  }

  /** proof = b64u(HMAC-SHA256(k_bind, bind_t)) */
  async function proof(kb, t) {
    const key = await subtle.importKey('raw', kb, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return b64uEncode(new Uint8Array(await subtle.sign('HMAC', key, t)));
  }

  /** Proof uit het geopende ontgrendelmateriaal {ph, kh} (ProtectedValues); alle tussenbuffers worden gewist. */
  async function proofFromSecret({ secret, vaultId, browserId, pubB, label }) {
    if (!secret || !secret.kh) throw new HwKeyError('trust_needs_keyfile', MESSAGES.trust_needs_keyfile);
    const ph = secret.ph ? secret.ph.getBinary() : null;
    const kh = secret.kh.getBinary();
    let pt = null;
    let kb = null;
    try {
      pt = ptCk(ph, kh);
      kb = await kBind(pt, vaultId);
      return await proof(kb, bindT(vaultId, browserId, pubB, label));
    } finally {
      if (ph) ph.fill(0);
      kh.fill(0);
      if (pt) pt.fill(0);
      if (kb) kb.fill(0);
    }
  }

  /** login_t = "HSv2 blogin" 0 challenge_id 0 b64u(challenge) 0 browser_id 0 email_lc */
  function loginT(challengeId, challenge, browserId, emailLc) {
    return joinFields(['HSv2 blogin', challengeId, nonceText(challenge), browserId, emailLc]);
  }

  /** req_t = "HSv2 approve" 0 approval_id 0 vault_id 0 browser_id 0 epk_L 0 b64u(nonce_L) 0 created_at */
  function reqT(approvalId, vaultId, browserId, epkL, nonceL, createdAt) {
    if (!Number.isSafeInteger(createdAt) || createdAt < 0) throw new HwKeyError('invalid_request');
    return joinFields(['HSv2 approve', approvalId, vaultId, browserId, epkL, nonceText(nonceL), String(createdAt)]);
  }

  // ───────────── ECDSA P-256 (K_B), handtekening raw r‖s 64 B (P1363 = WebCrypto-standaard) ─────────────
  const ECDSA = { name: 'ECDSA', hash: 'SHA-256' };

  async function generateBrowserKey() {
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const pubB = b64uEncode(new Uint8Array(await subtle.exportKey('spki', kp.publicKey)));
    return { privateKey: kp.privateKey, pubB };
  }

  async function signRaw(privateKey, bytes) {
    const sig = new Uint8Array(await subtle.sign(ECDSA, privateKey, bytes));
    if (sig.length !== 64) throw new HwKeyError('signature_invalid');
    return sig;
  }

  /** Controle met pub_B (b64u SPKI-DER). sig: Uint8Array(64) of b64u. */
  async function verify(pubB, bytes, sig) {
    let raw;
    try {
      raw = typeof sig === 'string' ? b64uDecode(sig) : new Uint8Array(sig);
    } catch (_) { return false; }
    if (raw.length !== 64) return false;
    let key;
    try {
      key = await subtle.importKey('spki', b64uDecode(pubB), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    } catch (_) { return false; }
    return subtle.verify(ECDSA, key, raw, bytes);
  }

  function newBrowserId() {
    if (root.crypto.randomUUID) return root.crypto.randomUUID().toLowerCase();
    const b = root.crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  // ───────────── relay: tijdelijke X25519-sleutel e_L en Seal_v2 openen ─────────────
  async function newRelayKey() {
    const kp = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const epkL = b64uEncode(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
    return { privateKey: kp.privateKey, publicKey: epkL };
  }

  /**
   * Open resp met e_L. De AAD komt uit de EIGEN verwachte vault_id, approval_id en nonce_L (nooit uit resp).
   * Geeft {ph, kh} als ProtectedValues (kdbxweb) — of ruwe bytes met {raw:true} (tests). kh moet aanwezig zijn.
   */
  async function openRelay({ resp, eL, vaultId, approvalId, nonceL, raw = false }) {
    if (!eL || !eL.privateKey || typeof eL.publicKey !== 'string') throw new HwKeyError('unseal_failed');
    const bind = `${approvalId}\0${nonceText(nonceL)}`;
    const out = await HK._crypto.unseal(resp, eL, { vaultId, keyId: approvalId, purpose: 'relay', bind });
    if (!out.kh) {
      if (out.ph) out.ph.fill(0);
      throw new HwKeyError('approval_invalid', MESSAGES.approval_invalid);
    }
    if (raw) return out;
    const k = root.kdbxweb;
    if (!k) {
      if (out.ph) out.ph.fill(0);
      out.kh.fill(0);
      throw new HwKeyError('browser_unsupported', 'kdbxweb niet geladen.');
    }
    try {
      const pv = (b) => (b ? k.ProtectedValue.fromBinary(new Uint8Array(b)) : null);
      return { ph: pv(out.ph), kh: pv(out.kh) };
    } finally {
      if (out.ph) out.ph.fill(0);
      out.kh.fill(0);
    }
  }

  // ───────────── IndexedDB (§14.1) ─────────────
  function idb() {
    try {
      return root.indexedDB || null;
    } catch (_) {
      return null; // bv. geblokkeerde opslag
    }
  }

  function openDb() {
    return new Promise((resolve, reject) => {
      const factory = idb();
      if (!factory) { reject(new HwKeyError('trust_unsupported', MESSAGES.trust_unsupported)); return; }
      let req;
      try {
        req = factory.open(DB_NAME, 1);
      } catch (_) {
        reject(new HwKeyError('trust_unsupported', MESSAGES.trust_unsupported));
        return;
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'browser_id' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(new HwKeyError('trust_unsupported', MESSAGES.trust_unsupported));
      req.onblocked = () => reject(new HwKeyError('trust_unsupported', MESSAGES.trust_unsupported));
    });
  }

  async function tx(mode, fn) {
    const db = await openDb();
    try {
      return await new Promise((resolve, reject) => {
        let t;
        try {
          t = db.transaction(STORE, mode);
        } catch (e) { reject(e); return; }
        const store = t.objectStore(STORE);
        let result;
        try {
          const r = fn(store);
          if (r) r.onsuccess = () => { result = r.result; };
        } catch (e) { reject(e); return; }
        t.oncomplete = () => resolve(result);
        t.onerror = () => reject(t.error || new Error('idb'));
        t.onabort = () => reject(t.error || new Error('idb'));
      });
    } finally {
      db.close();
    }
  }

  function validRecord(r) {
    return r && typeof r === 'object' && typeof r.browser_id === 'string' && UUID_RE.test(r.browser_id)
      && typeof r.vault_id === 'string' && typeof r.email === 'string' && r.key && typeof r.key === 'object';
  }

  /** Alle lokale trust-records ([] zonder IndexedDB of bij een fout). */
  async function listRecords() {
    try {
      const all = await tx('readonly', (s) => s.getAll());
      return Array.isArray(all) ? all.filter(validRecord) : [];
    } catch (_) {
      return [];
    }
  }

  /** Record voor deze kluis (en optioneel dit e-mailadres), of null. */
  async function findRecord({ vaultId, email } = {}) {
    const all = await listRecords();
    const lc = email ? String(email).trim().toLowerCase() : null;
    return all.find((r) => (!vaultId || r.vault_id === vaultId) && (!lc || r.email.toLowerCase() === lc)) || null;
  }

  async function saveRecord(rec) {
    if (!validRecord(rec)) throw new HwKeyError('trust_save_failed', MESSAGES.trust_save_failed);
    try {
      await tx('readwrite', (s) => s.put(rec));
    } catch (_) {
      throw new HwKeyError('trust_save_failed', MESSAGES.trust_save_failed);
    }
    // Teruglezen: een CryptoKey die niet bewaard kan worden (sommige privévensters) faalt hier dicht.
    const back = await listRecords();
    if (!back.some((r) => r.browser_id === rec.browser_id)) throw new HwKeyError('trust_save_failed', MESSAGES.trust_save_failed);
  }

  async function deleteRecord(browserId) {
    try {
      await tx('readwrite', (s) => s.delete(browserId));
      return true;
    } catch (_) {
      return false;
    }
  }

  /** Kan deze browser vertrouwd worden / met de telefoon ontgrendelen? {ok, reason} */
  async function checkSupport() {
    try {
      const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      if (!kp || !kp.privateKey) throw new Error('ecdsa');
      await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      await subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveBits']);
    } catch (_) {
      return { ok: false, reason: 'trust_unsupported' };
    }
    try {
      (await openDb()).close();
    } catch (_) {
      return { ok: false, reason: 'trust_unsupported' };
    }
    return { ok: true, reason: null };
  }

  /**
   * Bestaand record voor (vault_id, e-mail), of een NIEUWE sleutel die nog niet bewaard is ({saved:false}).
   * Pas na een geslaagde POST /trusted-browsers bewaart trustBrowser() hem (geen wees-records).
   */
  async function ensureBrowserKey({ vaultId, email, label }) {
    const existing = await findRecord({ vaultId, email });
    if (existing) return Object.assign({ saved: true }, existing);
    const { privateKey, pubB } = await generateBrowserKey();
    return {
      saved: false,
      browser_id: newBrowserId(),
      vault_id: vaultId,
      email: String(email).trim(),
      label,
      key: privateKey,
      pub_b: pubB,
    };
  }

  // ───────────── API ─────────────
  function api() {
    const a = root.HorseSafeAPI;
    if (!a || !a.trust || !a.approvals) throw new HwKeyError('trust_unsupported', MESSAGES.trust_unsupported);
    return a;
  }

  function errorFrom(status, data) {
    if (status === 422) return new HwKeyError('invalid_request');
    const d = data && data.detail && !Array.isArray(data.detail) && typeof data.detail === 'object' ? data.detail : null;
    // Na weigeren trekt de server de sessie in: 401 invalid_token + reason session_revoked = geweigerd (§14.5).
    if (status === 401 && d && d.reason === 'session_revoked') return new HwKeyError('approval_denied', MESSAGES.approval_denied);
    if (d && typeof d.error === 'string') return new HwKeyError(d.error, MESSAGES[d.error], d);
    if (status === 429) return new HwKeyError('api_429', MESSAGES.api_429);
    return new HwKeyError('api_' + status);
  }

  /** {ok,status,data} → data, of gooi HwKeyError met body.detail.error. */
  async function call(p) {
    const r = await p;
    if (!r.ok) throw errorFrom(r.status, r.data);
    return r.data;
  }

  /**
   * Flow A (§14.3) — vertrouw deze browser. Kluis open, kh aanwezig, step-up via `wrap` (stepup.js withStepUp).
   * secret = {ph, kh} (ProtectedValues) van de geopende kluis. Geeft het bewaarde record.
   */
  async function trustBrowser({ vaultId, email, label, secret, wrap = (fn) => fn() }) {
    if (!secret || !secret.kh) throw new HwKeyError('trust_needs_keyfile', MESSAGES.trust_needs_keyfile);
    if (!labelOk(label)) throw new HwKeyError('invalid_label', MESSAGES.invalid_label);
    if (typeof email !== 'string' || !email.includes('@')) throw new HwKeyError('invalid_request');
    const sup = await checkSupport();
    if (!sup.ok) throw new HwKeyError(sup.reason, MESSAGES[sup.reason]);
    const rec = await ensureBrowserKey({ vaultId, email, label });
    if (rec.saved) throw new HwKeyError('trust_exists', MESSAGES.trust_exists);
    const pr = await proofFromSecret({ secret, vaultId, browserId: rec.browser_id, pubB: rec.pub_b, label });
    const body = { browser_id: rec.browser_id, vault_id: vaultId, pub_B: rec.pub_b, label, proof: pr };
    const data = await wrap(() => call(api().trust.create(body)));
    if (!data || data.browser_id !== rec.browser_id) {
      await call(api().trust.revoke(rec.browser_id)).catch(() => {});
      throw new HwKeyError('api_201');
    }
    const stored = { browser_id: rec.browser_id, vault_id: vaultId, email: rec.email, label, key: rec.key, pub_b: rec.pub_b };
    try {
      await saveRecord(stored);
    } catch (e) {
      // Sleutel niet te bewaren: het vertrouwen op de server meteen weer intrekken.
      await call(api().trust.revoke(rec.browser_id)).catch(() => {});
      throw e;
    }
    return stored;
  }

  /** GET /trusted-browsers → [{browser_id, vault_id, label, created_at, last_used_at}] */
  async function listTrusted() {
    const data = await call(api().trust.list());
    return data && Array.isArray(data.browsers) ? data.browsers : [];
  }

  /** Intrekken op de server (S). 404 = al weg → true. */
  async function revoke(browserId) {
    try {
      await call(api().trust.revoke(browserId));
    } catch (e) {
      if (e && (e.code === 'not_found' || e.code === 'api_404')) return true;
      throw e;
    }
    return true;
  }

  /**
   * "Vergeet deze browser": lokaal record + sleutel weg én DELETE op de server. Lokaal wissen gebeurt altijd
   * (ook als de server niet antwoordt; de sleutel is dan toch onbruikbaar). Geeft {local, server, error?}.
   */
  async function forget(browserId) {
    const local = await deleteRecord(browserId);
    try {
      await revoke(browserId);
      return { local, server: true };
    } catch (e) {
      return { local, server: false, error: e };
    }
  }

  /**
   * Flow B (§14.4) — inloggen met e-mail + handtekening K_B + TOTP. Succes: de server zet de sessiecookie.
   * Elke serverfout wordt `browser_login_failed` (de server geeft bewust geen detail).
   */
  async function browserLogin({ record, totp }) {
    if (!validRecord(record)) throw new HwKeyError('no_trust_record', MESSAGES.no_trust_record);
    const code = String(totp || '').replace(/\s+/g, '');
    if (!/^\d{6,8}$/.test(code)) throw new HwKeyError('invalid_code');
    const emailLc = record.email.trim().toLowerCase();
    const ch = await call(api().trust.challenge(emailLc));
    if (!ch || typeof ch.challenge_id !== 'string' || typeof ch.challenge !== 'string' || !B64U_RE.test(ch.challenge)) {
      throw new HwKeyError('browser_login_failed', MESSAGES.browser_login_failed);
    }
    let challenge;
    try { challenge = b64uDecode(ch.challenge); } catch (_) { challenge = null; }
    if (!challenge || challenge.length !== 32) throw new HwKeyError('browser_login_failed', MESSAGES.browser_login_failed);
    const sig = await signRaw(record.key, loginT(ch.challenge_id, ch.challenge, record.browser_id, emailLc));
    try {
      return await call(api().trust.login({ challenge_id: ch.challenge_id, browser_id: record.browser_id, sig: b64uEncode(sig), totp: code }));
    } catch (e) {
      if (e && (e.code === 'api_429' || e.code === 'rate_limited')) throw e;
      throw new HwKeyError('browser_login_failed', MESSAGES.browser_login_failed);
    }
  }

  /**
   * Flow C stap 1 (§14.5) — verzoek aanmaken en ondertekenen. Geeft een sessie; altijd afsluiten met wipe().
   * POST → {approval_id, created_at} → sig_req over req_t → PUT {epk_L, nonce_L, sig_req} → {expires_at}.
   */
  async function startApproval({ vaultId, record }) {
    if (!validRecord(record) || record.vault_id !== vaultId) throw new HwKeyError('no_trust_record', MESSAGES.no_trust_record);
    const eL = await newRelayKey();
    const nonceL = root.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const session = {
      vaultId, browserId: record.browser_id, approvalId: null, createdAt: null, expiresAt: 0,
      eL, nonceL, startedAt: Date.now(), done: false,
    };
    try {
      const a = await call(api().approvals.create(vaultId, record.browser_id));
      if (!a || typeof a.approval_id !== 'string' || !UUID_RE.test(a.approval_id) || !Number.isSafeInteger(a.created_at)) {
        throw new HwKeyError('api_201');
      }
      session.approvalId = a.approval_id;
      session.createdAt = a.created_at;
      const t = reqT(a.approval_id, vaultId, record.browser_id, eL.publicKey, nonceL, a.created_at);
      const sig = await signRaw(record.key, t);
      const r = await call(api().approvals.submit(vaultId, a.approval_id, {
        epk_L: eL.publicKey, nonce_L: b64uEncode(nonceL), sig_req: b64uEncode(sig),
      }));
      session.expiresAt = r && Number.isFinite(r.expires_at) ? r.expires_at : 0;
      session.startedAt = Date.now();
      return session;
    } catch (e) {
      if (session.approvalId) await cancelApproval(session);
      wipe(session);
      throw e;
    }
  }

  /** Lokale deadline (ms): expires_at, maar nooit verder dan 120 s na de PUT (klokverschil). */
  function deadline(session) {
    const ttl = session.expiresAt - Math.floor(session.startedAt / 1000);
    const secs = ttl > 0 && ttl <= APPROVAL_TTL ? ttl : APPROVAL_TTL;
    return session.startedAt + secs * 1000;
  }

  /** DELETE (best effort, nooit gooien). */
  async function cancelApproval(session, { keepalive = false } = {}) {
    if (!session || session.done || !session.approvalId) return;
    session.done = true;
    try {
      await api().approvals.cancel(session.vaultId, session.approvalId, keepalive ? { keepalive: true } : undefined);
    } catch (_) { /* al verlopen of geannuleerd */ }
  }

  /**
   * Flow C stap 2–6 — long-poll tot een besluit. approved → resp openen → {ph, kh} (ProtectedValues; aanroeper
   * wist met HK.wipeSecret). denied → approval_denied; verlopen → approval_expired (+ DELETE).
   * signal.aborted → 'cancelled' (de aanroeper doet zelf DELETE). onTick(secondsLeft) voor de afteller.
   */
  async function waitForDecision(session, { signal, onTick } = {}) {
    const end = deadline(session);
    let tick = null;
    if (onTick) {
      const t = () => onTick(Math.max(0, Math.ceil((end - Date.now()) / 1000)));
      t();
      tick = setInterval(t, 1000);
    }
    try {
      for (;;) {
        if (signal && signal.aborted) throw new HwKeyError('cancelled');
        const leftMs = end - Date.now();
        if (leftMs <= 0) {
          await cancelApproval(session);
          throw new HwKeyError('approval_expired', MESSAGES.approval_expired);
        }
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), leftMs);
        const onAbort = () => ctrl.abort();
        if (signal) signal.addEventListener('abort', onAbort);
        const wait = Math.max(1, Math.min(WAIT_S, Math.floor(leftMs / 1000)));
        let r = null;
        try {
          r = await api().approvals.status(session.vaultId, session.approvalId, wait, { signal: ctrl.signal });
        } catch (_) {
          r = null; // afgebroken of netwerkfout: lus beslist (deadline/abort/opnieuw)
        } finally {
          clearTimeout(timer);
          if (signal) signal.removeEventListener('abort', onAbort);
        }
        if (signal && signal.aborted) throw new HwKeyError('cancelled');
        if (!r) { await new Promise((res) => setTimeout(res, 1000)); continue; }
        if (r.status === 401) throw errorFrom(401, r.data);
        if (r.status === 410 || r.status === 404) {
          session.done = true;
          throw new HwKeyError('approval_expired', MESSAGES.approval_expired);
        }
        if (!r.ok) {
          if (r.status >= 500) { await new Promise((res) => setTimeout(res, 1000)); continue; }
          throw errorFrom(r.status, r.data);
        }
        const st = r.data && r.data.status;
        if (st === 'approved') {
          session.done = true;
          if (typeof r.data.resp !== 'string') throw new HwKeyError('approval_invalid', MESSAGES.approval_invalid);
          try {
            return await openRelay({
              resp: r.data.resp, eL: session.eL, vaultId: session.vaultId, approvalId: session.approvalId, nonceL: session.nonceL,
            });
          } catch (e) {
            if (e && e.code === 'unseal_failed') throw new HwKeyError('approval_invalid', MESSAGES.approval_invalid);
            throw e;
          }
        }
        if (st === 'denied') { session.done = true; throw new HwKeyError('approval_denied', MESSAGES.approval_denied); }
        if (st === 'expired' || st === 'consumed') { session.done = true; throw new HwKeyError('approval_expired', MESSAGES.approval_expired); }
        if (st === 'cancelled') { session.done = true; throw new HwKeyError('approval_cancelled', MESSAGES.approval_cancelled); }
        // pending/draft: meteen opnieuw (de server hield het verzoek al ≤ 25 s vast)
        if (st !== 'pending' && st !== 'draft') await new Promise((res) => setTimeout(res, 1000));
      }
    } finally {
      if (tick) clearInterval(tick);
    }
  }

  /** e_L en nonce weg. De CryptoKey zelf is niet exporteerbaar; zonder verwijzing ruimt de browser hem op. */
  function wipe(session) {
    if (!session) return;
    if (session.nonceL) session.nonceL.fill(0);
    session.nonceL = null;
    session.eL = null;
  }

  /** Voorstel voor de naam: "Chrome – Linux". */
  function defaultLabel() {
    const nav = root.navigator || {};
    const ua = nav.userAgent || '';
    let b = 'Browser';
    if (/Edg\//.test(ua)) b = 'Edge';
    else if (/Firefox\//.test(ua)) b = 'Firefox';
    else if (/Chrome\/|Chromium\//.test(ua)) b = 'Chrome';
    else if (/Safari\//.test(ua)) b = 'Safari';
    let p = (nav.userAgentData && nav.userAgentData.platform) || '';
    if (!p) {
      if (/Windows/.test(ua)) p = 'Windows';
      else if (/Android/.test(ua)) p = 'Android';
      else if (/iPhone|iPad/.test(ua)) p = 'iOS';
      else if (/Mac OS X|Macintosh/.test(ua)) p = 'macOS';
      else if (/CrOS/.test(ua)) p = 'ChromeOS';
      else if (/Linux/.test(ua)) p = 'Linux';
      else p = nav.platform || 'onbekend';
    }
    return `${b} – ${p}`.replace(CTRL_RE, '').slice(0, 64);
  }

  root.HorseSafeTrust = {
    MESSAGES,
    APPROVAL_TTL,
    messageFor,
    labelOk,
    defaultLabel,
    checkSupport,
    kBind,
    bindT,
    proof,
    proofFromSecret,
    loginT,
    reqT,
    signRaw,
    verify,
    generateBrowserKey,
    ensureBrowserKey,
    newRelayKey,
    openRelay,
    listRecords,
    findRecord,
    saveRecord,
    deleteRecord,
    forget,
    trustBrowser,
    listTrusted,
    revoke,
    browserLogin,
    startApproval,
    waitForDecision,
    cancelApproval,
    deadline,
    wipe,
    // Testingang voor de vectoren (trust_v1.json)
    _crypto: {
      ptCk,
      async importX25519Private(raw32) {
        const pkcs8 = concat(PKCS8_X25519, new Uint8Array(raw32));
        try {
          return await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
        } finally {
          pkcs8.fill(0);
        }
      },
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
