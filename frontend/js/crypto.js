/* HorseSafe crypto layer v0.0.2-Hellman
 *
 * Wrapper rond kdbxweb (UMD-global) + argon2-browser (UMD-global) +
 * clipboard-manager met best-effort 10s wipe.
 *
 * Master-pw en KDBX-content blijven UITSLUITEND in browser-RAM.
 */
(function () {
  'use strict';

  // Wire kdbxweb up to argon2-browser. Beide zijn UMD via <script>.
  // argon2-browser exposeert window.argon2.hash(...).
  // NB: v0.0.2-Hellman maakt nieuwe vaults aan met AES-KDF (geen Argon2);
  // de Argon2-bridge staat klaar voor v0.0.3+ en voor import van Argon2-vaults.
  if (window.kdbxweb && window.argon2) {
    window.kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type, version) => {
      const argon2Type = (type === 0) ? window.argon2.ArgonType.Argon2d :
                         (type === 1) ? window.argon2.ArgonType.Argon2i :
                                        window.argon2.ArgonType.Argon2id;
      const result = await window.argon2.hash({
        pass: new Uint8Array(password),
        salt: new Uint8Array(salt),
        time: iterations,
        mem: Math.floor(memory / 1024),  // kdbxweb levert bytes; argon2-browser eist KiB
        hashLen: length,
        parallelism,
        type: argon2Type,
        // argon2.wasm wordt vanaf dit pad gefetcht (relatief aan page-URL).
        // Onze vault.html staat op /vault.html, dus 'vendor/argon2' resolveert correct.
        distPath: 'vendor/argon2',
      });
      return result.hash.buffer;
    });
  } else {
    console.warn('[HorseSafe] kdbxweb of argon2 niet geladen — crypto.js niet bruikbaar');
  }

  /**
   * Maak een nieuwe lege KDBX4-database in browser.
   * Returnt {kdbx: Kdbx, credentials, masterKey}.
   *
   * masterKey = ArrayBuffer (composiet via kdbxweb intern).
   */
  async function createDatabase(masterPassword, name = 'HorseSafe Vault') {
    const kdb = window.kdbxweb;
    const credentials = new kdb.Credentials(kdb.ProtectedValue.fromString(masterPassword));
    const db = kdb.Kdbx.create(credentials, name);

    // KDBX4 default-KDF is Argon2d. POC v0.0.2-Hellman gebruikt **AES-KDF** voor
    // snelheid en omdat argon2-browser-WASM in headless Chromium niet stabiel
    // initialiseert. AES-KDF is KDBX-spec-conform en opent in KeePassXC-desktop.
    // Argon2id-KDF voor nieuwe vaults wordt ingeschakeld vanaf v0.0.3+ na
    // verificatie dat argon2-bridge robuust werkt.
    db.header.setKdf(kdb.Consts.KdfId.Aes);
    return { db, credentials };
  }

  /**
   * Laad een KDBX-blob met master-pw. Returnt Kdbx-instance.
   * Throws bij verkeerd wachtwoord (kdbxweb.KdbxError).
   */
  async function openDatabase(blobBuffer, masterPassword) {
    const kdb = window.kdbxweb;
    const credentials = new kdb.Credentials(kdb.ProtectedValue.fromString(masterPassword));
    return await kdb.Kdbx.load(blobBuffer, credentials);
  }

  /** Serialiseer Kdbx terug naar ArrayBuffer (encrypted). */
  async function saveDatabase(db) {
    return await db.save();
  }

  /** Voeg entry toe aan default-groep. */
  function addEntry(db, { title, username, password, url, notes }) {
    const kdb = window.kdbxweb;
    const group = db.getDefaultGroup();
    const entry = db.createEntry(group);
    if (title)    entry.fields.set('Title', title);
    if (username) entry.fields.set('UserName', username);
    if (password) entry.fields.set('Password', kdb.ProtectedValue.fromString(password));
    if (url)      entry.fields.set('URL', url);
    if (notes)    entry.fields.set('Notes', notes);
    return entry;
  }

  /** Lijst alle entries uit default-groep + sub-groepen. */
  function listEntries(db) {
    const all = [];
    function walk(group) {
      for (const entry of group.entries) {
        all.push(entry);
      }
      for (const sub of group.groups) walk(sub);
    }
    walk(db.getDefaultGroup());
    return all.map(e => ({
      uuid:     e.uuid.id,
      title:    e.fields.get('Title') || '',
      username: e.fields.get('UserName') || '',
      password: e.fields.get('Password'),  // ProtectedValue
      url:      e.fields.get('URL') || '',
      notes:    e.fields.get('Notes') || '',
      _entry:   e,
    }));
  }

  /** Verwijder entry op uuid. */
  function deleteEntry(db, uuid) {
    function walk(group) {
      for (let i = 0; i < group.entries.length; i++) {
        if (group.entries[i].uuid.id === uuid) {
          db.remove(group.entries[i]);
          return true;
        }
      }
      for (const sub of group.groups) if (walk(sub)) return true;
      return false;
    }
    return walk(db.getDefaultGroup());
  }

  /** Genereer random wachtwoord. */
  function generatePassword(length = 20) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+';
    const buf = new Uint32Array(length);
    crypto.getRandomValues(buf);
    let out = '';
    for (let i = 0; i < length; i++) out += chars[buf[i] % chars.length];
    return out;
  }

  /**
   * Clipboard-copy met best-effort 10s wipe.
   * onTick(secondsLeft) wordt elke 100ms aangeroepen voor progressbar.
   */
  async function copyWithWipe(text, onTick, onDone) {
    await navigator.clipboard.writeText(text);
    const DURATION_MS = 10000;
    const start = performance.now();
    const tick = () => {
      const elapsed = performance.now() - start;
      const remaining = Math.max(0, DURATION_MS - elapsed);
      if (onTick) onTick(remaining / DURATION_MS);
      if (remaining > 0) {
        return setTimeout(tick, 100);
      }
      // Best-effort wipe: alleen mogelijk als tab focus heeft
      navigator.clipboard.writeText('[HorseSafe wiped]').catch(() => {});
      if (onDone) onDone();
    };
    tick();
  }

  window.HorseSafeCrypto = {
    createDatabase,
    openDatabase,
    saveDatabase,
    addEntry,
    listEntries,
    deleteEntry,
    generatePassword,
    copyWithWipe,
  };
})();
