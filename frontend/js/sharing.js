/* HorseSafe sharing v0.0.6-Adleman
 *
 * ECDH-P256 (WebCrypto native) + AES-GCM voor wrapped private-key.
 * Server kent: pubkey (plain), encrypted_privkey (AES-GCM), encrypted_payload (share-content).
 * Server kent NIET: private-key, share-content, master-key.
 *
 * Schema voor share-payload (base64-encoded JSON):
 *   { ephemeral_pubkey: <base64 raw>, iv: <base64>, ciphertext: <base64> }
 *
 * Encrypted-private-key blob:
 *   { iv: <base64>, ciphertext: <base64 JWK> }
 *   AES-key = PBKDF2(master-pw, "horsesafe-keypair-v1" + user-id, 100000, SHA-256)
 */
(function () {
  'use strict';

  // ─── base64 helpers ───
  function b64encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }
  function b64decode(s) {
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  // ─── PBKDF2: master-pw → 256-bit AES-key (voor private-key wrap) ───
  async function deriveWrapKey(masterPw, userId) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(masterPw), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode('horsesafe-keypair-v1:' + userId),
        iterations: 100000,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ─── Keypair-generatie ───
  async function generateKeypair(masterPw, userId) {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);

    // Wrap private-jwk met AES-GCM
    const wrapKey = await deriveWrapKey(masterPw, userId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(privJwk));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, plaintext);

    return {
      pubkey: b64encode(new TextEncoder().encode(JSON.stringify(pubJwk))),
      encrypted_privkey: b64encode(new TextEncoder().encode(
        JSON.stringify({ iv: b64encode(iv), ciphertext: b64encode(ct) })
      )),
    };
  }

  // ─── Unwrap private-key (in browser) ───
  async function unwrapPrivateKey(masterPw, userId, encryptedPrivkeyB64) {
    const wrapKey = await deriveWrapKey(masterPw, userId);
    const wrapped = JSON.parse(new TextDecoder().decode(b64decode(encryptedPrivkeyB64)));
    const iv = new Uint8Array(b64decode(wrapped.iv));
    const ct = b64decode(wrapped.ciphertext);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrapKey, ct);
    const privJwk = JSON.parse(new TextDecoder().decode(plain));
    return crypto.subtle.importKey(
      'jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits', 'deriveKey']
    );
  }

  async function importPubkey(pubkeyB64) {
    const pubJwk = JSON.parse(new TextDecoder().decode(b64decode(pubkeyB64)));
    return crypto.subtle.importKey(
      'jwk', pubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
  }

  // ─── Share-encryptie: AES-GCM met ephemeral ECDH-shared-secret ───
  async function encryptForRecipient(recipientPubkeyB64, plaintextStr) {
    const recipientPubkey = await importPubkey(recipientPubkeyB64);
    // Ephemeral key-pair
    const eph = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
    );
    const sharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: recipientPubkey },
      eph.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, sharedKey,
      new TextEncoder().encode(plaintextStr),
    );
    const ephPubJwk = await crypto.subtle.exportKey('jwk', eph.publicKey);
    return b64encode(new TextEncoder().encode(JSON.stringify({
      ephemeral_pubkey: ephPubJwk,
      iv: b64encode(iv),
      ciphertext: b64encode(ct),
    })));
  }

  async function decryptFromSender(myPrivkey, encryptedPayloadB64) {
    const payload = JSON.parse(new TextDecoder().decode(b64decode(encryptedPayloadB64)));
    const ephPub = await crypto.subtle.importKey(
      'jwk', payload.ephemeral_pubkey, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephPub },
      myPrivkey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const iv = new Uint8Array(b64decode(payload.iv));
    const ct = b64decode(payload.ciphertext);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sharedKey, ct);
    return new TextDecoder().decode(plain);
  }

  window.HorseSafeSharing = {
    generateKeypair,
    unwrapPrivateKey,
    encryptForRecipient,
    decryptFromSender,
  };
})();
