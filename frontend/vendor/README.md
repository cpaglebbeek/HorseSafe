# frontend/vendor/

Vendored third-party libraries voor de HorseSafe-frontend. **Niet via npm in productie** — direct geladen als statisch `<script>`-asset om build-step te vermijden (zie PRINCIPLES.md P-DEV-02).

## kdbxweb/
- **Versie:** 2.1.1
- **Licentie:** MIT (zie `kdbxweb/LICENSE.MIT`)
- **Bron:** https://github.com/keeweb/kdbxweb
- **Bestand:** `kdbxweb.min.js` (135 KB UMD-bundle — exposeert globaal `kdbxweb`-object)
- **Doel:** KDBX3/KDBX4 read/write in browser

## argon2/
- **Versie:** argon2-browser 1.18.0
- **Licentie:** MIT (zie `argon2/LICENSE.MIT`)
- **Bron:** https://github.com/antelle/argon2-browser
- **Bestanden:**
  - `argon2-bundled.min.js` (45 KB — JS met embedded WASM, geen aparte fetch nodig)
  - `argon2.wasm` (25 KB — losse WASM, voor SIMD-pad indien beschikbaar)
- **Doel:** Argon2id KDF in browser. Wordt bij init aan kdbxweb gekoppeld via `kdbxweb.CryptoEngine.setArgon2Impl(...)`.

## Update-procedure (niet via npm install in productie)

```bash
cd /tmp
mkdir vendor-update && cd vendor-update
npm pack kdbxweb argon2-browser
tar -xzf kdbxweb-*.tgz -C kdbxweb-dist
tar -xzf argon2-browser-*.tgz -C argon2-dist
cp kdbxweb-dist/package/dist/kdbxweb.min.js  frontend/vendor/kdbxweb/
cp argon2-dist/package/dist/argon2-bundled.min.js frontend/vendor/argon2/
cp argon2-dist/package/dist/argon2.wasm            frontend/vendor/argon2/
# update DEPENDENCIES.md met nieuwe versies + commit
```
