/* HorseSafe hardware-sleutels v0.2.0-Koblitz — contract: docs/HARDWARE_KEYS.md §12
 *
 * Ontgrendelen met een YubiKey (Bio: vingerafdruk; noodsleutel: lange PIN) via WebAuthn PRF.
 *
 *   PRF-uitvoer (32 B, alleen in deze tab)
 *     └─ HKDF ─▶ X25519-privésleutel sk_c   (publieke sleutel pk_c staat op de server)
 *   ontgrendelmateriaal CK = {ph, kh}  ── Seal_v2 (X25519 + HKDF + AES-256-GCM, AAD) ──▶ verzegelde kopie
 *
 *   ph = SHA-256(UTF-8(wachtwoord)), kh = keyfile-hash volgens kdbxweb. Nooit het leesbare wachtwoord
 *   of de keyfile zelf (P-CRYPT-09). kdbxweb rekent met SHA-256(ph || kh), dus {ph, kh} opent de KDBX
 *   precies zoals wachtwoord + keyfile.
 *
 * Challenges, rpId en PRF-salts komen van de server; de server controleert attestation, UV, BE en
 * de assertion. De client controleert daarnaast zelf (defense in depth) en faalt dicht.
 *
 * Werkt ook onder Node ≥ 20 (globalThis.crypto) voor de cryptotests; WebAuthn alleen in de browser.
 */
(function (root) {
  'use strict';

  const subtle = root.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // rpId is vast (§12.2): ook via een serveralias blijft het icthorsecloud.nl. localhost alleen in dev.
  const RP_ID = 'icthorsecloud.nl';
  const HOME_URL = 'https://icthorsecloud.nl/HorseSafe/';
  const DEV_HOSTS = ['localhost'];

  const SEAL_VERSION = 2;
  const PURPOSES = ['store', 'relay'];
  // PKCS#8-omhulsel voor een ruwe X25519-privésleutel (RFC 8410)
  const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
    0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

  // ───────────── foutmeldingen (§12.13) ─────────────
  const MESSAGES = {
    browser_unsupported: 'Deze browser kan niet met een YubiKey ontgrendelen. Gebruik Chrome of Edge op de laptop.',
    safari: 'Deze browser kan niet met een YubiKey ontgrendelen. Gebruik Chrome of Edge op de laptop.',
    wrong_host: 'Hardware-sleutels werken alleen op icthorsecloud.nl. Open HorseSafe daar.',
    no_prf: 'Deze sleutel of browser ondersteunt de benodigde functie (PRF) niet. Gebruik een YubiKey 5 of Bio in Chrome of Edge.',
    uv_missing: 'De sleutel heeft geen vingerafdruk of PIN gevraagd.',
    no_uv: 'De sleutel heeft geen vingerafdruk of PIN gevraagd.',
    up_missing: 'De sleutel is niet aangeraakt. Probeer het opnieuw.',
    not_device_bound: 'Dit is een gesynchroniseerde passkey. Alleen een fysieke YubiKey is toegestaan.',
    synced: 'Dit is een gesynchroniseerde passkey. Alleen een fysieke YubiKey is toegestaan.',
    attestation_invalid: 'Deze sleutel wordt niet geaccepteerd. Gebruik een YubiKey Bio (of YubiKey 5 als noodsleutel).',
    authenticator_not_allowed: 'Deze sleutel wordt niet geaccepteerd. Gebruik een YubiKey Bio (of YubiKey 5 als noodsleutel).',
    alg_not_allowed: 'Deze sleutel wordt niet geaccepteerd. Gebruik een YubiKey Bio (of YubiKey 5 als noodsleutel).',
    not_bio_authenticator: 'Voor dagelijks gebruik is een YubiKey Bio nodig. Een gewone YubiKey kan alleen als noodsleutel.',
    credential_exists: 'Deze sleutel is al gekoppeld.',
    too_many_keys: 'Het maximum aantal sleutels voor deze kluis is bereikt.',
    invalid_challenge: 'De aanvraag is verlopen. Probeer het opnieuw.',
    too_many_challenges: 'Te veel openstaande aanvragen. Wacht een paar minuten en probeer het opnieuw.',
    sign_count_regression: 'Deze sleutel gedraagt zich verdacht (teller ging terug). Ontgrendel met je keyfile en controleer je sleutels.',
    unseal_failed: 'Deze sleutel past niet bij de verzegelde kopie.',
    stale_copy: 'Kopie verouderd. Ontgrendel één keer met wachtwoord/keyfile en klik Bijwerken.',
    recovery_idle: 'Vraag eerst vrijgave van de noodsleutel aan.',
    recovery_waiting: 'De noodsleutel is nog niet vrijgegeven (wacht nog …).',
    recovery_expired: 'Het venster van de noodsleutel is verlopen. Vraag opnieuw vrijgave aan.',
    recovery_consumed: 'Deze vrijgave is al gebruikt. Vraag opnieuw vrijgave aan.',
    recovery_blocked: 'De noodsleutel is geblokkeerd. Hef de blokkade op met je YubiKey Bio.',
    notify_unavailable: 'Meldingen werken niet. Vrijgave van de noodsleutel is tijdelijk uitgeschakeld.',
    notify_failed: 'De melding kon niet verstuurd worden; de vrijgave is niet gestart. Probeer het later opnieuw.',
    nothing_to_cancel: 'Er loopt geen vrijgave om te annuleren.',
    not_blocked: 'Deze noodsleutel is niet geblokkeerd.',
    not_recovery_key: 'Dit is geen noodsleutel.',
    stepup_required: 'Bevestig eerst met je YubiKey Bio (of authenticator-code).',
    stepup_bio_required: 'Opheffen kan alleen met je YubiKey Bio.',
    stepup_unavailable: 'Stel eerst een authenticator-app (TOTP) in of koppel een YubiKey Bio.',
    stepup_method_not_allowed: 'Je hebt een YubiKey Bio gekoppeld; bevestig daarmee in plaats van met een code.',
    no_bio_keys: 'Er is geen YubiKey Bio gekoppeld.',
    invalid_code: 'De code klopt niet.',
    too_many_attempts: 'Te veel mislukte pogingen. Wacht een kwartier en probeer het opnieuw.',
    keys_mismatch: 'De sleutellijst is intussen gewijzigd. Herlaad en probeer opnieuw.',
    etag_mismatch: 'De kluis is elders gewijzigd. Herlaad en probeer opnieuw.',
    if_match_required: 'De kluis is elders gewijzigd. Herlaad en probeer opnieuw.',
    blob_too_large: 'De kluis is te groot om op te slaan.',
    no_usable_keys: 'Er is geen bruikbare sleutel voor deze kluis. Ontgrendel met wachtwoord/keyfile.',
    key_blocked: 'Deze sleutel is geblokkeerd.',
    credential_mismatch: 'Deze sleutel hoort niet bij deze kluis.',
    unknown_key: 'Deze sleutel hoort niet bij deze kluis.',
    invalid_sealed: 'De verzegelde kopie heeft een ongeldige vorm.',
    origin_mismatch: 'De aanvraag kwam van een onverwacht adres. Open HorseSafe via icthorsecloud.nl.',
    rp_id_mismatch: 'De aanvraag kwam van een onverwacht adres. Open HorseSafe via icthorsecloud.nl.',
    bad_client_data: 'De browser gaf een ongeldig antwoord. Probeer het opnieuw.',
    bad_authenticator_data: 'De sleutel gaf een ongeldig antwoord. Probeer het opnieuw.',
    assertion_invalid: 'De handtekening van de sleutel klopt niet.',
    cancelled: 'Geannuleerd of verlopen. Probeer het opnieuw en raak je sleutel aan.',
    no_secret: 'Open de kluis eerst met wachtwoord/keyfile.',
    invalid_request: 'Ongeldige aanvraag.',
    not_found: 'Niet gevonden.',
    not_authenticated: 'Je bent uitgelogd. Log opnieuw in.',
    invalid_token: 'Je sessie is verlopen. Log opnieuw in.',
    mfa_required: 'Bevestig eerst je tweede factor.',
    stepup_cooldown: 'Bevestigen met een authenticator-code kan tijdelijk niet: kort geleden is een YubiKey Bio verwijderd of de authenticator-app ingesteld.',
    stepup_key_too_new: 'Opheffen kan alleen met een YubiKey Bio die al gekoppeld was vóór de blokkade. Verwijder anders de noodsleutel en koppel hem opnieuw.',
    totp_already_configured: 'Er is al een authenticator-app ingesteld. Schakel die eerst uit met een geldige code.',
    rekey_nothing: 'Kies een nieuw wachtwoord, een nieuwe keyfile, of verwijder er één.',
    rekey_conflict: 'Kies per onderdeel óf een nieuwe waarde óf verwijderen, niet allebei.',
    rekey_no_factor: 'De kluis moet een wachtwoord of een keyfile houden.',
    keys_changed: 'De sleutellijst is intussen gewijzigd. Controleer de sleutels en probeer opnieuw.',
    key_pin_mismatch: 'De publieke sleutel van een gekoppelde sleutel wijkt af van wat je kluis bij het koppelen vastlegde. Er is mogelijk met de server geknoeid; er is niets verzegeld. Verwijder die sleutel en koppel hem opnieuw.',
    key_not_pinned: 'Een gekoppelde sleutel staat niet in je kluis vastgelegd (koppelen niet afgerond, of de kluis is buiten HorseSafe bewerkt); er is niets verzegeld. Verwijder die sleutel en koppel hem opnieuw.',
    pin_save_failed: 'De sleutel kon niet in je kluis worden vastgelegd; hij is niet gekoppeld. Probeer het opnieuw.',
    key_pin_conflict: 'Dit sleutelnummer staat al met een andere sleutel in je kluis vastgelegd. Er is mogelijk met de server geknoeid; er is niets vastgelegd of gekoppeld.',
    rekey_unknown: 'Er kwam geen duidelijk antwoord van de server; onbekend of het wijzigen is doorgevoerd.',
    rekey_not_applied: 'Het wijzigen is niet doorgevoerd (de server gaf geen duidelijk antwoord). Je huidige wachtwoord/keyfile blijft gelden; probeer het opnieuw.',
  };

  class HwKeyError extends Error {
    constructor(code, message, extra) {
      super(message || MESSAGES[code] || code);
      this.name = 'HwKeyError';
      this.code = code;
      if (extra) {
        for (const [k, v] of Object.entries(extra)) {
          if (k !== 'error' && k !== 'message' && !(k in this)) this[k] = v;
        }
      }
    }
  }

  function remaining(ts) {
    const s = Math.max(0, Math.round(ts - Date.now() / 1000));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return h ? `${h} u ${m} m` : `${m} m`;
  }

  /** Nederlandse melding voor een fout (HwKeyError, DOMException of iets anders). */
  function messageFor(e) {
    if (!e) return 'Onbekende fout.';
    const code = e.code;
    if (code === 'recovery_waiting' && e.release_at) {
      return `De noodsleutel is nog niet vrijgegeven (wacht nog ${remaining(e.release_at)}).`;
    }
    if (code === 'stepup_cooldown' && e.retry_at) {
      return `${MESSAGES.stepup_cooldown} Dat kan weer over ${remaining(e.retry_at)}, of bevestig met je YubiKey Bio.`;
    }
    if ((code === 'key_pin_mismatch' || code === 'key_not_pinned') && e.label) {
      return MESSAGES[code].replace('een gekoppelde sleutel', `"${e.label}"`).replace('Een gekoppelde sleutel', `"${e.label}"`);
    }
    if (typeof code === 'string' && MESSAGES[code]) return MESSAGES[code];
    if (typeof code === 'string' && code.startsWith('api_')) return `Serverfout (${code.slice(4)}). Probeer het opnieuw.`;
    if (e.name === 'NotAllowedError' || e.name === 'AbortError') return MESSAGES.cancelled;
    return e.message || String(e);
  }

  // ───────────── hulpfuncties ─────────────
  function b64uEncode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uDecode(str) {
    if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new HwKeyError('invalid_b64u');
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  function equalBytes(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  function random(n) { return root.crypto.getRandomValues(new Uint8Array(n)); }

  async function hkdf(ikm, salt, info) {
    const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, k, 256);
    return new Uint8Array(bits);
  }

  async function importX25519Private(raw32) {
    const pkcs8 = concat(PKCS8_X25519, raw32);
    try {
      return await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
    } finally {
      pkcs8.fill(0);
    }
  }

  async function publicFromPrivate(priv) {
    const jwk = await subtle.exportKey('jwk', priv);
    return jwk.x; // b64u zonder padding, 43 tekens
  }

  // ───────────── Seal_v2 (§12.5) ─────────────
  /** Deterministisch X25519-sleutelpaar uit 32 bytes PRF-uitvoer. */
  async function keypairFromPrf(prf) {
    const bytes = new Uint8Array(prf);
    if (bytes.length !== 32) throw new HwKeyError('no_prf');
    const seed = await hkdf(bytes, new Uint8Array(32), 'HorseSafe v2 X25519');
    try {
      const priv = await importX25519Private(seed);
      return { privateKey: priv, publicKey: await publicFromPrivate(priv) };
    } finally {
      seed.fill(0);
    }
  }

  /** AAD = "HSv2" 0x00 purpose 0x00 vault_id 0x00 bind */
  function buildAad(purpose, vaultId, bind) {
    if (!PURPOSES.includes(purpose)) throw new HwKeyError('invalid_purpose');
    if (typeof vaultId !== 'string' || typeof bind !== 'string') throw new HwKeyError('invalid_request');
    const z = Uint8Array.of(0);
    return concat(enc.encode('HSv2'), z, enc.encode(purpose), z, enc.encode(vaultId), z, enc.encode(bind));
  }

  /** Exact {"ph":<v>,"kh":<v>} — deze volgorde, geen spaties; <v> = "<b64u 32 B>" of null. */
  function encodePlaintext(ph, kh) {
    if (!ph && !kh) throw new HwKeyError('no_secret');
    for (const v of [ph, kh]) if (v && v.length !== 32) throw new HwKeyError('invalid_secret');
    const val = (v) => (v ? `"${b64uEncode(v)}"` : 'null');
    return enc.encode(`{"ph":${val(ph)},"kh":${val(kh)}}`);
  }

  function decodePlaintext(bytes) {
    let obj;
    try {
      obj = JSON.parse(dec.decode(bytes));
    } catch (_) {
      throw new HwKeyError('unseal_failed');
    }
    const keys = obj && typeof obj === 'object' ? Object.keys(obj) : [];
    if (keys.length !== 2 || keys[0] !== 'ph' || keys[1] !== 'kh') throw new HwKeyError('unseal_failed');
    const get = (v) => {
      if (v === null) return null;
      const b = b64uDecode(v);
      if (b.length !== 32) throw new HwKeyError('unseal_failed');
      return b;
    };
    const out = { ph: get(obj.ph), kh: get(obj.kh) };
    obj.ph = obj.kh = null;
    if (!out.ph && !out.kh) throw new HwKeyError('unseal_failed');
    return out;
  }

  async function sealKey(shared, epkRaw, pubRaw, usage) {
    const keyBytes = await hkdf(shared, concat(epkRaw, pubRaw), 'HorseSafe v2 seal');
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, [usage]);
    return { key, keyBytes };
  }

  async function x25519(priv, pubRaw) {
    const pub = await subtle.importKey('raw', pubRaw, { name: 'X25519' }, false, []);
    const ss = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256));
    if (ss.every((b) => b === 0)) throw new HwKeyError('unseal_failed');
    return ss;
  }

  /**
   * Seal_v2 met expliciete invoer (testingang en kern van seal()).
   * ph/kh: Uint8Array(32) of null. ephemeralSk/iv optioneel (tests), anders willekeurig.
   * Geeft {sealed, aad, k, pt} — k en pt alleen voor de vectortests; de aanroeper wist ze.
   */
  async function sealWith({ recipientPk, ph, kh, purpose, vaultId, bind, kid, ephemeralSk, iv }) {
    const pubRaw = typeof recipientPk === 'string' ? b64uDecode(recipientPk) : new Uint8Array(recipientPk);
    if (pubRaw.length !== 32) throw new HwKeyError('invalid_public_key');
    const eph = ephemeralSk
      ? await importX25519Private(new Uint8Array(ephemeralSk))
      : (await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])).privateKey;
    const epkRaw = b64uDecode(await publicFromPrivate(eph));
    const ss = await x25519(eph, pubRaw);
    const { key, keyBytes } = await sealKey(ss, epkRaw, pubRaw, 'encrypt');
    ss.fill(0);
    const nonce = iv ? new Uint8Array(iv) : random(12);
    if (nonce.length !== 12) throw new HwKeyError('invalid_iv');
    const aad = buildAad(purpose, vaultId, bind);
    const pt = encodePlaintext(ph, kh);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, pt));
    const sealed = JSON.stringify({ v: SEAL_VERSION, kid, epk: b64uEncode(epkRaw), iv: b64uEncode(nonce), ct: b64uEncode(ct) });
    return { sealed, aad, k: keyBytes, pt };
  }

  /** Verzegel ruwe {ph, kh} naar een publieke sleutel, purpose "store", gebonden aan vault en sleutel. */
  async function seal(publicKeyB64, raw, { vaultId, keyId }) {
    const r = await sealWith({
      recipientPk: publicKeyB64, ph: raw.ph, kh: raw.kh, purpose: 'store', vaultId, bind: keyId, kid: keyId,
    });
    r.k.fill(0);
    r.pt.fill(0);
    return r.sealed;
  }

  /**
   * Open een Seal_v2-kopie. De AAD komt uit de VERWACHTE vault_id en key_id (nooit uit sealed.kid).
   * Geeft ruwe {ph, kh} (Uint8Array(32) | null) terug; de aanroeper wist ze na gebruik.
   */
  async function unseal(sealed, keypair, { vaultId, keyId, purpose = 'store', bind }) {
    let obj;
    try {
      obj = JSON.parse(sealed);
    } catch (_) {
      throw new HwKeyError('unseal_failed');
    }
    if (!obj || obj.v !== SEAL_VERSION || obj.kid !== keyId) throw new HwKeyError('unseal_failed');
    let epkRaw;
    let iv;
    let ct;
    try {
      epkRaw = b64uDecode(obj.epk);
      iv = b64uDecode(obj.iv);
      ct = b64uDecode(obj.ct);
    } catch (_) {
      throw new HwKeyError('unseal_failed');
    }
    if (epkRaw.length !== 32 || iv.length !== 12) throw new HwKeyError('unseal_failed');
    const ss = await x25519(keypair.privateKey, epkRaw);
    const { key, keyBytes } = await sealKey(ss, epkRaw, b64uDecode(keypair.publicKey), 'decrypt');
    ss.fill(0);
    keyBytes.fill(0);
    const aad = buildAad(purpose, vaultId, bind === undefined ? keyId : bind);
    let plain;
    try {
      plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));
    } catch (_) {
      throw new HwKeyError('unseal_failed');
    }
    try {
      return decodePlaintext(plain);
    } finally {
      plain.fill(0);
    }
  }

  // ───────────── kdbxweb-koppeling (§12.5) ─────────────
  function kdbx() {
    const k = root.kdbxweb;
    if (!k) throw new HwKeyError('browser_unsupported', 'kdbxweb niet geladen.');
    return k;
  }

  function pvFromBytes(bytes) {
    // fromBinary XOR't in place op new Uint8Array(arg): met een Uint8Array is dat een kopie.
    return kdbx().ProtectedValue.fromBinary(new Uint8Array(bytes));
  }

  function wipePv(pv) {
    if (pv && pv.value && pv.salt) {
      pv.value.fill(0);
      pv.salt.fill(0);
    }
  }

  /** CK als ProtectedValues uit een kdbxweb.Credentials (na het openen van de KDBX). */
  async function secretFromCredentials(cred) {
    if (!cred) throw new HwKeyError('no_secret');
    if (cred.ready) await cred.ready;
    const copy = (pv) => {
      if (!pv) return null;
      const b = pv.getBinary();
      try {
        if (b.length !== 32) throw new HwKeyError('invalid_secret');
        return pvFromBytes(b);
      } finally {
        b.fill(0);
      }
    };
    const secret = { ph: copy(cred.passwordHash), kh: copy(cred.keyFileHash) };
    if (!secret.ph && !secret.kh) throw new HwKeyError('no_secret');
    return secret;
  }

  /** kdbxweb.Credentials uit {ph, kh}; kdbxweb rekent SHA-256(ph || kh), gelijk aan pw + keyfile. */
  function credentialsFromHashes(secret) {
    if (!secret || (!secret.ph && !secret.kh)) throw new HwKeyError('no_secret');
    const k = kdbx();
    const c = new k.Credentials(null, null);
    const copy = (pv) => {
      if (!pv) return undefined;
      const b = pv.getBinary();
      try { return pvFromBytes(b); } finally { b.fill(0); }
    };
    c.passwordHash = copy(secret.ph);
    c.keyFileHash = copy(secret.kh);
    return c;
  }

  /**
   * Nieuwe Credentials voor /rekey (§12.6.5). Een onderdeel dat niet wijzigt blijft het huidige
   * (uit `current`), tenzij het expliciet verwijderd wordt — zo blijft pw+keyfile pw+keyfile.
   * kdbxweb XOR't een keyfile van 32 bytes in place en houdt die buffer vast; daarom krijgt
   * kdbxweb altijd een eigen kopie en delen de teruggegeven Credentials geen geheugen met
   * `keyFile` (de aanroeper mag `keyFile` dus gewoon wissen).
   * Geeft {credentials, secret}; de aanroeper wist `secret` met wipeSecret.
   */
  async function credentialsForRekey({ current, password = null, keyFile = null, removePassword = false, removeKeyFile = false }) {
    if ((password && removePassword) || (keyFile && removeKeyFile)) throw new HwKeyError('rekey_conflict');
    if (!password && !keyFile && !removePassword && !removeKeyFile) throw new HwKeyError('rekey_nothing');
    const k = kdbx();
    const cur = await secretFromCredentials(current);
    let fresh = null;
    try {
      fresh = new k.Credentials(
        password ? k.ProtectedValue.fromString(password) : null,
        keyFile ? new Uint8Array(keyFile) : null,
      );
      await fresh.ready;
      const copy = (pv) => {
        if (!pv) return null;
        const b = pv.getBinary();
        try { return pvFromBytes(b); } finally { b.fill(0); }
      };
      const pick = (changed, freshPv, curPv, remove) => {
        if (changed) return copy(freshPv);
        return remove ? null : copy(curPv);
      };
      const secret = {
        ph: pick(!!password, fresh.passwordHash, cur.ph, removePassword),
        kh: pick(!!keyFile, fresh.keyFileHash, cur.kh, removeKeyFile),
      };
      if (!secret.ph && !secret.kh) throw new HwKeyError('rekey_no_factor');
      return { secret, credentials: credentialsFromHashes(secret) };
    } finally {
      wipeSecret(cur);
      if (fresh) { wipePv(fresh.passwordHash); wipePv(fresh.keyFileHash); }
    }
  }

  function wipeSecret(secret) {
    if (!secret) return;
    wipePv(secret.ph);
    wipePv(secret.kh);
    secret.ph = null;
    secret.kh = null;
  }

  /** ProtectedValues → ruwe bytes (aanroeper wist). */
  function rawFromSecret(secret) {
    if (!secret || (!secret.ph && !secret.kh)) throw new HwKeyError('no_secret');
    return { ph: secret.ph ? secret.ph.getBinary() : null, kh: secret.kh ? secret.kh.getBinary() : null };
  }

  function wipeRaw(raw) {
    if (!raw) return;
    if (raw.ph) raw.ph.fill(0);
    if (raw.kh) raw.kh.fill(0);
  }

  // ───────────── vastgelegde ontvangers (pins, reviewronde 2) ─────────────
  /*
   * De server levert de publieke sleutels; wie vault_keys.public_key kan wijzigen (DB-schrijftoegang,
   * gemanipuleerde back-up) zou bij de volgende reseal/rekey het echte {ph, kh} naar zijn eigen sleutel
   * laten verzegelen. Daarom legt de client bij het koppelen {key_id: public_key} vast IN de versleutelde
   * KDBX (Meta/CustomData, beschermd door de KDBX-HMAC; de server kan het lezen noch vervalsen) en
   * verzegelt hij alleen naar sleutels die daar exact zo in staan. KeePassXC laat CustomData staan.
   */
  const PIN_FIELD = 'HorseSafe.KeyPins.v1';

  /** {key_id: public_key} uit de geopende kluis (leeg als er niets of iets van een andere vault staat). */
  function readPins(db, vaultId) {
    const item = db && db.meta && db.meta.customData && db.meta.customData.get(PIN_FIELD);
    if (!item || typeof item.value !== 'string') return {};
    try {
      const obj = JSON.parse(item.value);
      if (!obj || obj.v !== 1 || obj.vault_id !== vaultId || !obj.keys || typeof obj.keys !== 'object') return {};
      const out = {};
      for (const [kid, pk] of Object.entries(obj.keys)) if (typeof pk === 'string') out[kid] = pk;
      return out;
    } catch (_) {
      return {};
    }
  }

  /**
   * Leg key_id → public_key vast in de geopende kluis (in RAM; de aanroeper slaat de kluis op).
   * Een bestaande pin wordt NOOIT door een andere publieke sleutel vervangen (key_pin_conflict): het key_id komt
   * van de server, en een overschreven pin zou reseal/rekey naar een sleutel van de aanvaller laten verzegelen.
   * Dezelfde sleutel opnieuw vastleggen mag (idempotent).
   */
  function pinKey(db, vaultId, keyId, publicKey) {
    if (!db || !db.meta) throw new HwKeyError('no_secret');
    if (typeof keyId !== 'string' || !keyId) throw new HwKeyError('invalid_request');
    if (typeof publicKey !== 'string' || b64uDecode(publicKey).length !== 32) throw new HwKeyError('invalid_public_key');
    const current = readPins(db, vaultId);
    if (Object.prototype.hasOwnProperty.call(current, keyId) && current[keyId] !== publicKey) {
      throw new HwKeyError('key_pin_conflict', undefined, { key_id: keyId });
    }
    if (!db.meta.customData) db.meta.customData = new Map();
    const keys = Object.assign({}, current, { [keyId]: publicKey });
    db.meta.customData.set(PIN_FIELD, { value: JSON.stringify({ v: 1, vault_id: vaultId, keys }), lastModified: new Date() });
  }

  /** Faalt dicht als een ontvanger niet (of anders) is vastgelegd; vóór er iets verzegeld wordt. */
  function checkPins(keys, pins) {
    if (!pins || typeof pins !== 'object') throw new HwKeyError('key_not_pinned');
    for (const k of keys) {
      const pinned = Object.prototype.hasOwnProperty.call(pins, k.id) ? pins[k.id] : null;
      if (!pinned) throw new HwKeyError('key_not_pinned', undefined, { key_id: k.id, label: k.label });
      if (pinned !== k.public_key) throw new HwKeyError('key_pin_mismatch', undefined, { key_id: k.id, label: k.label });
    }
  }

  /** Status per sleutel voor de UI: 'ok' | 'missing' | 'mismatch'. */
  function pinStatus(key, pins) {
    if (!pins || !Object.prototype.hasOwnProperty.call(pins, key.id)) return 'missing';
    return pins[key.id] === key.public_key ? 'ok' : 'mismatch';
  }

  // ───────────── omgeving ─────────────
  function isSafari(ua) {
    if (/iPhone|iPad|iPod/.test(ua)) return true;
    if (/Macintosh/.test(ua) && root.navigator && root.navigator.maxTouchPoints > 1) return true; // iPadOS
    return /Safari/.test(ua) && !/Chrome|Chromium|Edg|Firefox/.test(ua);
  }

  function hostAllowed(host) {
    return host === RP_ID || DEV_HOSTS.includes(host);
  }

  /** Fail-closed controle vooraf. */
  async function checkSupport() {
    if (!root.PublicKeyCredential || !root.navigator || !root.navigator.credentials) {
      return { ok: false, reason: 'browser_unsupported' };
    }
    if (isSafari(root.navigator.userAgent || '')) return { ok: false, reason: 'safari' };
    const host = root.location ? root.location.hostname : '';
    if (!hostAllowed(host)) return { ok: false, reason: 'wrong_host', link: HOME_URL };
    try {
      await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    } catch (_) {
      return { ok: false, reason: 'browser_unsupported' };
    }
    return { ok: true, reason: null };
  }

  async function requireSupport() {
    const s = await checkSupport();
    if (!s.ok) throw new HwKeyError(s.reason, undefined, s.link ? { link: s.link } : undefined);
  }

  /** De rpId uit de serveropties moet de vaste rpId zijn (of localhost in dev) én bij deze host horen. */
  function checkRpId(rpId) {
    const host = root.location.hostname;
    if (rpId !== host || !hostAllowed(rpId)) throw new HwKeyError('wrong_host', undefined, { link: HOME_URL });
  }

  // ───────────── WebAuthn ─────────────
  const FLAG_UP = 0x01;
  const FLAG_UV = 0x04;
  const FLAG_BE = 0x08;
  const FLAG_BS = 0x10;

  function checkFlags(authData) {
    const bytes = authData ? new Uint8Array(authData) : null;
    if (!bytes || bytes.length < 37) throw new HwKeyError('bad_authenticator_data');
    const f = bytes[32];
    if (!(f & FLAG_UP)) throw new HwKeyError('up_missing');
    if (!(f & FLAG_UV)) throw new HwKeyError('no_uv');
    if (f & (FLAG_BE | FLAG_BS)) throw new HwKeyError('synced');
    return f;
  }

  function mapDomError(e) {
    if (e instanceof HwKeyError) return e;
    if (e && e.name === 'InvalidStateError') return new HwKeyError('credential_exists');
    if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) return new HwKeyError('cancelled');
    if (e && e.name === 'SecurityError') return new HwKeyError('wrong_host', undefined, { link: HOME_URL });
    if (e && e.name === 'NotSupportedError') return new HwKeyError('browser_unsupported');
    return e;
  }

  async function webauthn(kind, options) {
    try {
      return await root.navigator.credentials[kind]({ publicKey: options });
    } catch (e) {
      throw mapDomError(e);
    }
  }

  function prfFirst(cred) {
    const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!first) throw new HwKeyError('no_prf');
    const out = new Uint8Array(first.slice ? first.slice(0) : first);
    if (out.length !== 32) throw new HwKeyError('no_prf');
    return out;
  }

  function assertionBody(a) {
    checkFlags(a.response.authenticatorData);
    return {
      credential_id: b64uEncode(a.rawId),
      client_data_json: b64uEncode(a.response.clientDataJSON),
      authenticator_data: b64uEncode(a.response.authenticatorData),
      signature: b64uEncode(a.response.signature),
      user_handle: a.response.userHandle && a.response.userHandle.byteLength ? b64uEncode(a.response.userHandle) : null,
    };
  }

  // ───────────── API ─────────────
  function apiBase() { return (root.HorseSafeAPI && root.HorseSafeAPI.base) || ''; }

  function errorFrom(status, data) {
    if (status === 422) return new HwKeyError('invalid_request');
    const d = data && data.detail && !Array.isArray(data.detail) && typeof data.detail === 'object' ? data.detail : null;
    if (d && typeof d.error === 'string') return new HwKeyError(d.error, undefined, d);
    return new HwKeyError('api_' + status);
  }

  async function request(method, path, { json, form, headers } = {}) {
    const opts = { method, credentials: 'include', headers: Object.assign({}, headers || {}) };
    if (json !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(json);
    } else if (form) {
      opts.body = form;
    }
    const res = await root.fetch(apiBase() + path, opts);
    let data = null;
    if (res.status !== 204) {
      try { data = await res.json(); } catch (_) { data = null; }
    }
    if (!res.ok) throw errorFrom(res.status, data);
    return { data, headers: res.headers, status: res.status };
  }

  const vaultPath = (vaultId) => `/vault/${encodeURIComponent(vaultId)}`;
  const keysPath = (vaultId) => `${vaultPath(vaultId)}/keys`;
  const keyPath = (vaultId, keyId) => `${keysPath(vaultId)}/${encodeURIComponent(keyId)}`;

  async function options(body) {
    return (await request('POST', '/webauthn/options', { json: body })).data;
  }

  /** 12.6.3 → {keys, notify_available, stepup_until} */
  async function listKeys(vaultId) {
    const { data } = await request('GET', keysPath(vaultId));
    if (!data || !Array.isArray(data.keys)) throw new HwKeyError('api_200');
    return data;
  }

  /**
   * 12.6.1 — koppel een YubiKey. secret = {ph, kh} (ProtectedValues) van de nu geopende kluis.
   * kind: 'bio' (YubiKey Bio, dagelijks) of 'recovery' (noodsleutel, wachttijd).
   */
  async function enroll({ vaultId, kind, label, secret, pin }) {
    await requireSupport();
    if (!secret) throw new HwKeyError('no_secret');
    if (typeof pin !== 'function') throw new HwKeyError('pin_save_failed');
    const o = await options({ purpose: 'register', vault_id: vaultId, kind });
    checkRpId(o.rp && o.rp.id);
    const timeout = o.timeout_ms || 120000;

    const cred = await webauthn('create', {
      rp: { id: o.rp.id, name: o.rp.name },
      user: { id: b64uDecode(o.user.id), name: o.user.name, displayName: o.user.display_name },
      challenge: b64uDecode(o.create.challenge),
      pubKeyCredParams: (o.pub_key_cred_params || [-8, -7]).map((alg) => ({ type: 'public-key', alg })),
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'discouraged',
        requireResidentKey: false,
        userVerification: 'required',
      },
      attestation: 'direct',
      hints: ['security-key'],
      timeout,
      excludeCredentials: (o.exclude_credentials || []).map((id) => ({ type: 'public-key', id: b64uDecode(id) })),
      extensions: { prf: {} },
    });
    if (!cred || !cred.response || typeof cred.response.getAuthenticatorData !== 'function') {
      throw new HwKeyError('browser_unsupported');
    }
    checkFlags(cred.response.getAuthenticatorData());
    const cext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    if (!cext.prf || cext.prf.enabled !== true) throw new HwKeyError('no_prf');
    // Eventuele PRF-resultaten uit create worden genegeerd: één codepad via get (§12.6.1 stap 2).
    const credentialId = b64uEncode(cred.rawId);
    const transports = typeof cred.response.getTransports === 'function' ? cred.response.getTransports() : undefined;

    const a = await webauthn('get', {
      challenge: b64uDecode(o.assert.challenge),
      rpId: o.rp.id,
      allowCredentials: [{ type: 'public-key', id: new Uint8Array(cred.rawId) }],
      userVerification: 'required',
      hints: ['security-key'],
      timeout,
      extensions: { prf: { evalByCredential: { [credentialId]: { first: b64uDecode(o.prf_salt) } } } },
    });
    if (b64uEncode(a.rawId) !== credentialId) throw new HwKeyError('credential_mismatch');
    const assertion = assertionBody(a);
    const prf = prfFirst(a);
    let kp;
    try {
      kp = await keypairFromPrf(prf);
    } finally {
      prf.fill(0);
    }

    const raw = rawFromSecret(secret);
    let sealed;
    try {
      sealed = await seal(kp.publicKey, raw, { vaultId, keyId: o.key_id });
      // Proef op de som vóór opslaan: zelf openen en vergelijken.
      const back = await unseal(sealed, kp, { vaultId, keyId: o.key_id });
      const same = equalBytes(back.ph || new Uint8Array(0), raw.ph || new Uint8Array(0))
        && equalBytes(back.kh || new Uint8Array(0), raw.kh || new Uint8Array(0))
        && !!back.ph === !!raw.ph && !!back.kh === !!raw.kh;
      wipeRaw(back);
      if (!same) throw new HwKeyError('unseal_failed');
    } finally {
      wipeRaw(raw);
    }

    const body = {
      key_id: o.key_id,
      kind,
      label,
      create: {
        challenge_id: o.create.challenge_id,
        credential_id: credentialId,
        client_data_json: b64uEncode(cred.response.clientDataJSON),
        attestation_object: b64uEncode(cred.response.attestationObject),
      },
      assert: Object.assign({ challenge_id: o.assert.challenge_id }, assertion),
      public_key: kp.publicKey,
      sealed,
    };
    if (transports && transports.length) body.create.transports = transports;
    // Eerst vastleggen in de kluis (pin), dan pas koppelen: een sleutel die de server kent maar de kluis
    // niet, krijgt bij reseal/rekey nooit materiaal. Een pin zonder serversleutel is onschadelijk.
    try {
      await pin(o.key_id, kp.publicKey);
    } catch (e) {
      throw e instanceof HwKeyError ? e : new HwKeyError('pin_save_failed');
    }
    return (await request('POST', keysPath(vaultId), { json: body })).data;
  }

  /**
   * 12.6.2 — ontgrendel met een gekoppelde sleutel (Bio, of een vrijgegeven noodsleutel).
   * Geeft {secret: {ph, kh} als ProtectedValues, key}. Gebruik credentialsFromHashes(secret).
   */
  async function unlock({ vaultId }) {
    await requireSupport();
    const [o, list] = await Promise.all([options({ purpose: 'unlock', vault_id: vaultId }), listKeys(vaultId)]);
    checkRpId(o.rp_id);
    const allow = o.allow_credentials || [];
    if (!allow.length) throw new HwKeyError('no_usable_keys');
    const evalByCredential = {};
    for (const k of allow) evalByCredential[k.credential_id] = { first: b64uDecode(k.prf_salt) };
    const a = await webauthn('get', {
      challenge: b64uDecode(o.challenge),
      rpId: o.rp_id,
      allowCredentials: allow.map((k) => ({ type: 'public-key', id: b64uDecode(k.credential_id) })),
      userVerification: 'required',
      hints: ['security-key'],
      timeout: o.timeout_ms || 120000,
      extensions: { prf: { evalByCredential } },
    });
    const assertion = assertionBody(a);
    const item = allow.find((k) => k.credential_id === assertion.credential_id);
    const key = item ? list.keys.find((k) => k.id === item.key_id) : null;
    if (!item || !key) throw new HwKeyError('unknown_key');
    const prf = prfFirst(a);
    let kp;
    try {
      kp = await keypairFromPrf(prf);
    } finally {
      prf.fill(0);
    }
    // pk uit de PRF moet bij deze sleutel horen, anders is het de verkeerde sleutel of kopie.
    if (kp.publicKey !== key.public_key) throw new HwKeyError('unseal_failed');

    const { data } = await request('POST', `${keyPath(vaultId, key.id)}/unlock`, {
      json: Object.assign({ challenge_id: o.challenge_id }, assertion),
    });
    if (!data || data.id !== key.id) throw new HwKeyError('unseal_failed');
    const raw = await unseal(data.sealed, kp, { vaultId, keyId: key.id });
    try {
      return { secret: { ph: raw.ph ? pvFromBytes(raw.ph) : null, kh: raw.kh ? pvFromBytes(raw.kh) : null }, key };
    } finally {
      wipeRaw(raw);
    }
  }

  async function sealItems({ vaultId, keys, secret, pins }) {
    checkPins(keys, pins); // vóór er iets van {ph, kh} wordt verzegeld
    const raw = rawFromSecret(secret);
    try {
      const items = [];
      for (const k of keys) {
        items.push({ id: k.id, sealed: await seal(k.public_key, raw, { vaultId, keyId: k.id }) });
      }
      return items;
    } finally {
      wipeRaw(raw);
    }
  }

  /** 12.6.4 (SU) — verzegel alle sleutels opnieuw met het materiaal waarmee de kluis nu open is. */
  async function resealAll({ vaultId, keys, secret, pins }) {
    if (!keys || !keys.length) return 0;
    const items = await sealItems({ vaultId, keys, secret, pins });
    const { data } = await request('PUT', `${keysPath(vaultId)}/sealed`, { json: { items } });
    return data.updated;
  }

  /**
   * 12.6.5 (SU + If-Match) — nieuwe KDBX-blob en alle kopieën in één atomaire stap.
   *
   * Een expliciete weigering van de server (HwKeyError met servercode, of een 4xx) betekent: niets
   * doorgevoerd. Geen of een onduidelijk antwoord (netwerkfout, 5xx/504 zonder code) kan óók betekenen dat
   * de server al gecommit heeft; dan gooit rekey `rekey_unknown` en controleert de aanroeper met
   * `rekeyLanded` of de etag van de server gelijk is aan de hash van de verstuurde blob.
   */
  async function rekey({ vaultId, etag, blob, keys, secret, pins }) {
    if (!etag) throw new HwKeyError('if_match_required');
    const items = await sealItems({ vaultId, keys: keys || [], secret, pins });
    const form = new root.FormData();
    form.append('blob', new root.Blob([blob], { type: 'application/octet-stream' }), 'vault.kdbx');
    form.append('sealed', JSON.stringify({ items }));
    let res;
    try {
      res = await request('PUT', `${vaultPath(vaultId)}/rekey`, { form, headers: { 'If-Match': etag } });
    } catch (e) {
      if (isUnknownOutcome(e)) throw new HwKeyError('rekey_unknown', undefined, { cause: e });
      throw e;
    }
    const { data, headers } = res;
    return { vault: data.vault, resealed: data.resealed, etag: headers.get('etag') || (data.vault && data.vault.etag) };
  }

  /** Geen antwoord of een 5xx zonder servercode: de uitkomst is onbekend (mogelijk wél gecommit). */
  function isUnknownOutcome(e) {
    if (!(e instanceof HwKeyError)) return true; // TypeError van fetch, afgebroken verbinding, …
    return /^api_(5\d\d|0)$/.test(e.code) || e.code === 'rekey_unknown';
  }

  /** SHA-256 (hex) van de blob, zoals de server de etag berekent (storage_service._hash_bytes). */
  async function blobEtag(blob) {
    const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
    return hex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
  }

  /**
   * Na `rekey_unknown`: is de verstuurde blob de huidige servervault?
   * → {state: 'landed', etag} | {state: 'not_landed', etag} | {state: 'unknown'}
   */
  async function rekeyLanded({ vaultId, blob }) {
    const want = await blobEtag(blob);
    try {
      const { data } = await request('GET', '/vault');
      const meta = Array.isArray(data) ? data.find((v) => v.id === vaultId) : null;
      if (!meta || typeof meta.etag !== 'string') return { state: 'unknown' };
      return meta.etag === want ? { state: 'landed', etag: want } : { state: 'not_landed', etag: meta.etag };
    } catch (_) {
      return { state: 'unknown' };
    }
  }

  const keyAction = (method, suffix) => async (vaultId, keyId) => (await request(method, keyPath(vaultId, keyId) + suffix)).data;
  const requestRelease = keyAction('POST', '/release');
  const cancelRelease = keyAction('DELETE', '/release');
  const block = keyAction('POST', '/block');
  const unblock = keyAction('DELETE', '/block');
  async function deleteKey(vaultId, keyId) {
    await request('DELETE', keyPath(vaultId, keyId));
    return true;
  }

  /** 12.8 — step-up met de YubiKey Bio (method 'bio') of, zonder Bio, met een TOTP-code. */
  async function stepUp({ method, code }) {
    if (method === 'totp') {
      return (await request('POST', '/auth/stepup', { json: { method: 'totp', code: String(code || '').trim() } })).data;
    }
    if (method !== 'bio') throw new HwKeyError('invalid_request');
    await requireSupport();
    const o = await options({ purpose: 'stepup' });
    checkRpId(o.rp_id);
    const allow = o.allow_credentials || [];
    if (!allow.length) throw new HwKeyError('no_bio_keys');
    const a = await webauthn('get', {
      challenge: b64uDecode(o.challenge),
      rpId: o.rp_id,
      allowCredentials: allow.map((k) => ({ type: 'public-key', id: b64uDecode(k.credential_id) })),
      userVerification: 'required',
      hints: ['security-key'],
      timeout: o.timeout_ms || 120000,
    });
    const body = Object.assign({ method: 'bio', challenge_id: o.challenge_id }, assertionBody(a));
    return (await request('POST', '/auth/stepup', { json: body })).data;
  }

  root.HorseSafeHwKeys = {
    HwKeyError,
    RP_ID,
    HOME_URL,
    MESSAGES,
    messageFor,
    checkSupport,
    listKeys,
    enroll,
    unlock,
    resealAll,
    rekey,
    rekeyLanded,
    isUnknownOutcome,
    blobEtag,
    readPins,
    pinKey,
    pinStatus,
    requestRelease,
    cancelRelease,
    block,
    unblock,
    deleteKey,
    stepUp,
    secretFromCredentials,
    credentialsFromHashes,
    credentialsForRekey,
    wipeSecret,
    _crypto: {
      keypairFromPrf, seal, unseal, sealWith, buildAad, encodePlaintext, b64uEncode, b64uDecode, hex,
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
