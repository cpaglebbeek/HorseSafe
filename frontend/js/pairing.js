/* HorseSafe telefoon koppelen v0.3.4-Miller — contract: docs/HARDWARE_KEYS.md §13 (Miller deel 2)
 *
 *   browser: s (16 B, crypto.getRandomValues; gaat NOOIT naar de server)
 *     ├─ HKDF "HSv2 pair srv" ─▶ k_srv  → server (POST /devices/pairings)
 *     └─ HKDF "HSv2 pair web" ─▶ k_web  → blijft in deze tab
 *   QR = "hs1p:" + pairing_id + "." + b64u(s)   → de app scant hem en kent dus k_srv én k_web
 *
 *   app claimt: transcript = "HSv2 pair" 0 pairing_id 0 pk_c 0 k_dev_pub 0 k_biosig_pub 0 label 0 model 0 app_version
 *               mac_srv = HMAC(k_srv, transcript)  (controleert de server)
 *               mac_web = HMAC(k_web, transcript)  (controleert de browser: de server kent k_web niet en kan
 *                                                   dus geen andere pk_c laten verzegelen zonder dat dit faalt)
 *   SAS = uint32_be(SHA-256("HSv2 pair sas" 0 transcript)[0..4]) mod 10^6 — de gebruiker vergelijkt hem met de
 *         telefoon (verkeerd toestel gescand).
 *   Klopt → Seal_v2(pk_c, CK, "store", vault_id, key_id) met de seal-functie uit hwkeys.js → POST confirm.
 *
 * s en k_web worden na afloop (bevestigd, geannuleerd, verlopen of mislukt) met fill(0) gewist.
 * Werkt ook onder Node ≥ 20 (globalThis.crypto) voor de vectortests (tests/unit/pairing.test.mjs).
 */
(function (root) {
  'use strict';

  const HK = root.HorseSafeHwKeys;
  if (!HK) throw new Error('pairing.js vereist hwkeys.js');
  const subtle = root.crypto.subtle;
  const enc = new TextEncoder();
  const { b64uEncode, b64uDecode, hex } = HK._crypto;
  const HwKeyError = HK.HwKeyError;

  const QR_PREFIX = 'hs1p:';
  const S_BYTES = 16;
  const PAIRING_TTL = 300; // s (§13.4)
  const POLL_MS = 1000; // §13.3 stap 3
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const B64U_RE = /^[A-Za-z0-9_-]+$/;
  // Zelfde tekenregel als de server (§13.5 stap 1): geen stuurtekens (Cc, incl. \0), Unicode-opmaaktekens (Cf,
  // bv. U+202E die de leesrichting omdraait), losse surrogaten (Cs) en U+2028/U+2029 in label/model/app_version.
  // Gecontroleerd vóórdat label/model getoond worden: wat de gebruiker ziet, is wat er staat.
  const CTRL_RE = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;

  // ───────────── foutmeldingen (aanvulling op hwkeys.js §12.13) ─────────────
  const MESSAGES = {
    pairing_untrusted: 'Koppeling niet vertrouwd — mogelijk gemanipuleerd. De koppeling is afgebroken en er is niets verzegeld. Probeer het opnieuw; gebeurt dit vaker, neem dan contact op met de beheerder.',
    pairing_not_found: 'Deze koppeling bestaat niet meer (verlopen of geannuleerd). Begin opnieuw.',
    pairing_expired: 'De QR-code is verlopen. Begin opnieuw.',
    pairing_cancelled: 'De koppeling is geannuleerd (bijvoorbeeld omdat elders een nieuwe koppeling is gestart).',
    sas_rejected: 'Je gaf aan dat de code niet klopt. De koppeling is geannuleerd en er is niets verzegeld.',
    too_many_pairings: 'Te veel koppelpogingen in het afgelopen uur. Probeer het later opnieuw.',
    api_429: 'Te veel koppelpogingen in het afgelopen uur. Probeer het later opnieuw.',
    too_many_devices: 'Je hebt al het maximum van 5 telefoons gekoppeld. Verwijder eerst een toestel.',
    pairing_unsupported: 'Deze browser kan geen telefoon koppelen (WebCrypto X25519/HKDF ontbreekt). Gebruik Chrome, Edge of Firefox.',
    pairing_not_claimed: 'De telefoon heeft de koppeling (nog) niet afgerond.',
    device_not_found: 'Dit toestel bestaat niet meer. De lijst is bijgewerkt.',
    pairing_key_exists: 'Koppeling niet vertrouwd — de server gaf een sleutelnummer op dat al bij je kluis hoort (mogelijk gemanipuleerd). Er is niets verzegeld of vastgelegd. Probeer het opnieuw; gebeurt dit vaker, neem dan contact op met de beheerder.',
  };

  function messageFor(e) {
    if (e && typeof e.code === 'string' && MESSAGES[e.code]) return MESSAGES[e.code];
    return HK.messageFor(e);
  }

  // ───────────── cryptografie (§13.1) ─────────────
  function newSecret() {
    return root.crypto.getRandomValues(new Uint8Array(S_BYTES));
  }

  async function hkdf32(ikm, info) {
    const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) }, k, 256);
    return new Uint8Array(bits);
  }

  /** {kSrv, kWeb} (elk 32 B) uit s. De aanroeper wist ze. */
  async function deriveKeys(s) {
    const bytes = s instanceof Uint8Array ? s : new Uint8Array(s);
    if (bytes.length !== S_BYTES) throw new HwKeyError('invalid_request');
    return { kSrv: await hkdf32(bytes, 'HSv2 pair srv'), kWeb: await hkdf32(bytes, 'HSv2 pair web') };
  }

  function qrString(pairingId, s) {
    if (typeof pairingId !== 'string' || !UUID_RE.test(pairingId)) throw new HwKeyError('invalid_request');
    return `${QR_PREFIX}${pairingId}.${b64uEncode(s)}`;
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  /** att_challenge = SHA-256("HSv2 pair att" 0 pairing_id 0 k_srv) — alleen voor de vectortests (de app rekent hem). */
  async function attChallenge(pairingId, kSrv) {
    const z = Uint8Array.of(0);
    return new Uint8Array(await subtle.digest('SHA-256', concat(enc.encode('HSv2 pair att'), z, enc.encode(pairingId), z, kSrv)));
  }

  const TRANSCRIPT_FIELDS = ['pairing_id', 'pk_c', 'k_dev_pub', 'k_biosig_pub', 'label', 'model', 'app_version'];

  /** UTF-8("HSv2 pair" 0 pairing_id 0 pk_c 0 k_dev_pub 0 k_biosig_pub 0 label 0 model 0 app_version) */
  function transcript(f) {
    const parts = ['HSv2 pair'];
    for (const name of TRANSCRIPT_FIELDS) {
      const v = f && f[name];
      // Geen enkel veld bevat "\0" (§13.1); anders is de codering niet eenduidig → dicht.
      if (typeof v !== 'string' || v.includes('\0')) throw new HwKeyError('pairing_untrusted');
      parts.push(v);
    }
    return enc.encode(parts.join('\0'));
  }

  async function hmacKey(k, usage) {
    return subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
  }

  /** HMAC-SHA256(k, t) — voor de vectortests; de controle gebruikt verifyMac. */
  async function mac(k, t) {
    return new Uint8Array(await subtle.sign('HMAC', await hmacKey(k, 'sign'), t));
  }

  /** Timing-safe: WebCrypto HMAC-verify vergelijkt in constante tijd. */
  async function verifyMac(k, t, macB64u) {
    if (typeof macB64u !== 'string' || macB64u.length !== 43 || !B64U_RE.test(macB64u)) return false;
    let m;
    try { m = b64uDecode(macB64u); } catch (_) { return false; }
    if (m.length !== 32) return false;
    return subtle.verify('HMAC', await hmacKey(k, 'verify'), m, t);
  }

  async function sas(t) {
    const d = new Uint8Array(await subtle.digest('SHA-256', concat(enc.encode('HSv2 pair sas'), Uint8Array.of(0), t)));
    const n = ((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]; // uint32_be zonder tekenbit
    return String(n % 1000000).padStart(6, '0');
  }

  // ───────────── claim controleren (vorm + mac_web) ─────────────
  function isB64u(v, { exact, max, bytes } = {}) {
    if (typeof v !== 'string' || !v.length || !B64U_RE.test(v)) return false;
    if (exact && v.length !== exact) return false;
    if (max && v.length > max) return false;
    if (bytes) {
      try { if (b64uDecode(v).length !== bytes) return false; } catch (_) { return false; }
    }
    return true;
  }

  function textOk(v, min, max) {
    return typeof v === 'string' && v.length >= min && v.length <= max && !CTRL_RE.test(v);
  }

  /** Vormcontrole van de claim zoals de server die doorgeeft (§13.4/§13.5 stap 1). Fout → pairing_untrusted. */
  function checkClaimShape(claim, pairingId) {
    if (!claim || typeof claim !== 'object' || Array.isArray(claim)) throw new HwKeyError('pairing_untrusted');
    // De claim in §13.4 heeft geen pairing_id; staat hij er toch in, dan moet hij de eigen sessie zijn.
    if (claim.pairing_id !== undefined && claim.pairing_id !== pairingId) throw new HwKeyError('pairing_untrusted');
    if (typeof claim.key_id !== 'string' || !UUID_RE.test(claim.key_id)
      || typeof claim.device_id !== 'string' || !claim.device_id.length || claim.device_id.length > 64
      || !isB64u(claim.pk_c, { exact: 43, bytes: 32 })
      || !isB64u(claim.k_dev_pub, { max: 200 })
      || !isB64u(claim.k_biosig_pub, { max: 200 })
      || !textOk(claim.label, 1, 64)
      || !textOk(claim.model, 0, 64)
      || !textOk(claim.app_version, 0, 32)) {
      throw new HwKeyError('pairing_untrusted');
    }
  }

  /**
   * Controleer de claim met k_web. Geeft {sas, transcript} of gooit pairing_untrusted.
   * Het pairing_id in het transcript is altijd het EIGEN id van deze sessie (nooit uit de claim).
   */
  async function verifyClaim({ pairingId, kWeb }, claim) {
    checkClaimShape(claim, pairingId);
    const t = transcript({
      pairing_id: pairingId,
      pk_c: claim.pk_c,
      k_dev_pub: claim.k_dev_pub,
      k_biosig_pub: claim.k_biosig_pub,
      label: claim.label,
      model: claim.model,
      app_version: claim.app_version,
    });
    if (!(await verifyMac(kWeb, t, claim.mac_web))) throw new HwKeyError('pairing_untrusted');
    return { sas: await sas(t), transcript: t };
  }

  /** Vormcontrole van een Seal_v2-kopie, gelijk aan validate_sealed op de server (§12.5). */
  function checkSealedShape(sealed, keyId) {
    if (typeof sealed !== 'string' || sealed.length > 1024) return false;
    let o;
    try { o = JSON.parse(sealed); } catch (_) { return false; }
    if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
    const keys = Object.keys(o);
    if (keys.length !== 5 || !['v', 'kid', 'epk', 'iv', 'ct'].every((k) => keys.includes(k))) return false;
    return o.v === 2 && o.kid === keyId
      && isB64u(o.epk, { exact: 43 }) && isB64u(o.iv, { exact: 16 })
      && typeof o.ct === 'string' && B64U_RE.test(o.ct) && o.ct.length >= 40 && o.ct.length <= 400;
  }

  // ───────────── API ─────────────
  function apiBase() { return (root.HorseSafeAPI && root.HorseSafeAPI.base) || ''; }

  function errorFrom(status, data) {
    if (status === 422) return new HwKeyError('invalid_request');
    const d = data && data.detail && !Array.isArray(data.detail) && typeof data.detail === 'object' ? data.detail : null;
    if (d && typeof d.error === 'string') return new HwKeyError(d.error, MESSAGES[d.error], d);
    if (status === 429) return new HwKeyError('api_429', MESSAGES.api_429);
    return new HwKeyError('api_' + status);
  }

  async function request(method, path, json, { keepalive = false } = {}) {
    const opts = { method, credentials: 'include', headers: {}, keepalive };
    if (json !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(json);
    }
    const res = await root.fetch(apiBase() + path, opts);
    let data = null;
    if (res.status !== 204) {
      try { data = await res.json(); } catch (_) { data = null; }
    }
    if (!res.ok) throw errorFrom(res.status, data);
    return data;
  }

  const pairingPath = (id) => `/devices/pairings/${encodeURIComponent(id)}`;

  /** Kan deze browser koppelen? (HKDF + X25519 voor Seal_v2; geen WebAuthn nodig.) */
  async function checkSupport() {
    try {
      await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      await subtle.importKey('raw', new Uint8Array(16), 'HKDF', false, ['deriveBits']);
      return { ok: true, reason: null };
    } catch (_) {
      return { ok: false, reason: 'pairing_unsupported' };
    }
  }

  /**
   * Stap 1 (SU): s maken, k_srv naar de server, QR-string teruggeven.
   * Geeft een sessie {pairingId, vaultId, expiresAt, qr, kWeb, ...}. Altijd afsluiten met wipe(session).
   * De aanroeper vangt 403 stepup_required af (stepup.js) en roept start dan opnieuw aan.
   */
  async function start({ vaultId }) {
    if (typeof vaultId !== 'string' || !vaultId) throw new HwKeyError('no_secret');
    const s = newSecret();
    let keys = null;
    try {
      keys = await deriveKeys(s);
      const data = await request('POST', '/devices/pairings', { vault_id: vaultId, k_srv: b64uEncode(keys.kSrv) });
      if (!data || typeof data.pairing_id !== 'string' || !UUID_RE.test(data.pairing_id)) throw new HwKeyError('api_201');
      const session = {
        pairingId: data.pairing_id,
        vaultId,
        expiresAt: Number(data.expires_at) || 0,
        startedAt: Date.now(),
        qr: qrString(data.pairing_id, s),
        kWeb: keys.kWeb,
        claim: null,
        sas: null,
        done: false,
      };
      keys.kWeb = null; // eigendom naar de sessie (wordt in wipe() gewist)
      return session;
    } finally {
      s.fill(0); // s zelf is niet meer nodig: alleen nog als tekst in de QR
      if (keys) {
        keys.kSrv.fill(0);
        if (keys.kWeb) keys.kWeb.fill(0);
      }
    }
  }

  /** Lokale deadline (ms): expires_at van de server, maar nooit verder dan TTL na start (klokverschil). */
  function deadline(session) {
    const ttl = session.expiresAt - Math.floor(session.startedAt / 1000);
    const secs = ttl > 0 && ttl <= PAIRING_TTL ? ttl : PAIRING_TTL;
    return session.startedAt + secs * 1000;
  }

  /** GET /devices/pairings/{id} → {status, expires_at, claim?} */
  async function status(session) {
    return request('GET', pairingPath(session.pairingId));
  }

  /** DELETE (best effort; nooit gooien). Annuleren, "Klopt niet", verlopen, mac_web fout. */
  async function cancel(session, { keepalive = false } = {}) {
    if (!session || session.done) return;
    session.done = true;
    try {
      await request('DELETE', pairingPath(session.pairingId), undefined, { keepalive });
    } catch (_) {
      /* verlopen/al geannuleerd: niets te doen */
    }
  }

  /**
   * Stap 3: pollen tot `claimed`, dan mac_web controleren en de SAS rekenen.
   * Geeft {claim, sas}. Fout mac_web → DELETE + pairing_untrusted. Verlopen → DELETE + pairing_expired.
   * `signal.aborted` → stopt stil met 'cancelled'. onTick(secondsLeft) voor de aftelling.
   */
  async function waitForClaim(session, { signal, onTick, pollMs = POLL_MS } = {}) {
    const end = deadline(session);
    for (;;) {
      if (signal && signal.aborted) throw new HwKeyError('cancelled');
      const left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      if (onTick) onTick(left);
      if (left <= 0) {
        await cancel(session);
        throw new HwKeyError('pairing_expired');
      }
      let st = null;
      try {
        st = await status(session);
      } catch (e) {
        if (e && (e.code === 'not_found' || e.code === 'api_404' || e.code === 'pairing_not_found')) {
          session.done = true;
          throw new HwKeyError('pairing_not_found');
        }
        if (e && (e.code === 'not_authenticated' || e.code === 'invalid_token' || e.code === 'api_401')) throw e;
        st = null; // tijdelijke netwerk-/serverfout: blijven pollen tot de deadline
      }
      if (signal && signal.aborted) throw new HwKeyError('cancelled');
      if (st && st.status === 'cancelled') { session.done = true; throw new HwKeyError('pairing_cancelled'); }
      if (st && st.status === 'claimed') {
        try {
          const r = await verifyClaim(session, st.claim);
          session.claim = st.claim;
          session.sas = r.sas;
          return { claim: st.claim, sas: r.sas };
        } catch (e) {
          await cancel(session); // claimed-device wordt door de server verwijderd (§13.4)
          throw e instanceof HwKeyError && e.code === 'pairing_untrusted' ? e : new HwKeyError('pairing_untrusted');
        }
      }
      if (st && st.status !== 'pending' && st.status !== 'claimed') {
        await cancel(session);
        throw new HwKeyError('pairing_not_found');
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  /**
   * key_id komt van de server en valt NIET onder mac_web (staat niet in het transcript). Een kwaadwillende
   * server zou zo het key_id van een bestaande sleutel kunnen opgeven, zodat de pin van die sleutel (bv. een
   * YubiKey) door pk_c vervangen wordt. Daarom: weigeren als key_id al in de sleutellijst van de kluis staat
   * of al vastgelegd is (pins uit de KDBX). Faalt dicht: lijst niet op te halen → geen koppeling.
   */
  async function checkKeyIdFree(session, pins) {
    const keyId = session.claim.key_id;
    const pinned = pins();
    if (!pinned || typeof pinned !== 'object' || Object.prototype.hasOwnProperty.call(pinned, keyId)) {
      throw new HwKeyError('pairing_key_exists', MESSAGES.pairing_key_exists);
    }
    const list = await HK.listKeys(session.vaultId);
    if (list.keys.some((k) => k && k.id === keyId)) throw new HwKeyError('pairing_key_exists', MESSAGES.pairing_key_exists);
  }

  /**
   * Stap 4 ("Klopt"): key_id controleren → Seal_v2(pk_c, CK, "store", vault_id, key_id) + vormcontrole → POST confirm.
   * secret = {ph, kh} (ProtectedValues) van de geopende kluis. pins() = vastgelegde {key_id: public_key} uit de
   * KDBX (verplicht). pin(key_id, pk_c) legt de ontvanger vast in de KDBX vóór de confirm (zelfde regel als
   * enroll, R15: anders weigeren reseal/rekey dit toestel). Geeft het sleutelobject (12.6.3, met device).
   */
  async function confirm(session, { secret, pin, pins }) {
    if (!session || !session.claim || !session.sas) throw new HwKeyError('pairing_not_claimed');
    if (!secret) throw new HwKeyError('no_secret');
    if (typeof pins !== 'function') throw new HwKeyError('pin_save_failed');
    await checkKeyIdFree(session, pins); // vóór seal en pin
    const claim = session.claim;
    const raw = { ph: secret.ph ? secret.ph.getBinary() : null, kh: secret.kh ? secret.kh.getBinary() : null };
    let sealed;
    try {
      sealed = await HK._crypto.seal(claim.pk_c, raw, { vaultId: session.vaultId, keyId: claim.key_id });
    } finally {
      if (raw.ph) raw.ph.fill(0);
      if (raw.kh) raw.kh.fill(0);
    }
    // Terug-openen kan niet zonder sk_c (staat alleen in de telefoon): alleen vormcontrole (§13.3 stap 4).
    if (!checkSealedShape(sealed, claim.key_id)) throw new HwKeyError('invalid_sealed');
    if (typeof pin === 'function') {
      try {
        await pin(claim.key_id, claim.pk_c);
      } catch (e) {
        throw e instanceof HwKeyError ? e : new HwKeyError('pin_save_failed');
      }
    }
    const key = await request('POST', `${pairingPath(session.pairingId)}/confirm`, { sealed });
    session.done = true;
    return key;
  }

  /** s is al gewist in start(); hier k_web en de sessiegegevens. */
  function wipe(session) {
    if (!session) return;
    if (session.kWeb) session.kWeb.fill(0);
    session.kWeb = null;
    session.qr = null;
    session.claim = null;
    session.sas = null;
  }

  async function listDevices() {
    return request('GET', '/devices');
  }

  async function revokeDevice(deviceId) {
    await request('DELETE', `/devices/${encodeURIComponent(deviceId)}`);
    return true;
  }

  root.HorseSafePairing = {
    MESSAGES,
    PAIRING_TTL,
    messageFor,
    checkSupport,
    start,
    status,
    waitForClaim,
    verifyClaim,
    confirm,
    cancel,
    wipe,
    deadline,
    listDevices,
    revokeDevice,
    qrString,
    // Testingang voor de vectoren (pair_v1.json), zoals hwkeys.js _crypto
    _crypto: {
      newSecret, deriveKeys, attChallenge, transcript, mac, verifyMac, sas, checkClaimShape, checkSealedShape, hex,
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
