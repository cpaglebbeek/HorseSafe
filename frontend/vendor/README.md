# frontend/vendor/

Vendored third-party libraries voor de HorseSafe-frontend. **Niet via npm in productie** — direct geladen als statisch `<script>`-asset om build-step te vermijden (zie PRINCIPLES.md P-DEV-02).

## kdbxweb/
- **Versie:** 2.1.1
- **Licentie:** MIT (zie `kdbxweb/LICENSE.MIT`)
- **Bron:** https://github.com/keeweb/kdbxweb
- **Bestand:** `kdbxweb.min.js` (135 KB UMD-bundle — exposeert globaal `kdbxweb`-object)
- **Doel:** KDBX3/KDBX4 read/write in browser

## qrcode/
- **Versie:** qrcode-generator 2.0.4
- **Licentie:** MIT (zie `qrcode/LICENSE.MIT`)
- **Bron:** Kazuhiko Arase — http://www.d-project.com/
- **Bestanden:**
  - `qrcode.js` (55 KB — QR Code generator, exposeert globaal `qrcode`-functie)
  - `qrcode_UTF8.js` (793 B — UTF-8 encoding helper)
- **Doel:** TOTP-otpauth-URL renderen als QR-code voor Authenticator-apps (Google Authenticator / Authy / etc.); sinds v0.3.4-Miller ook de koppel-QR `hs1p:<pairing_id>.<b64u s>` in S17 (`js/pairing-ui.js`, foutcorrectie M, als SVG-elementen opgebouwd via `getModuleCount`/`isDark` — geen innerHTML, geen inline script, past in CSP `script-src 'self'`)
- **Controle (14-10-2026):** byte-gelijk aan `dist/` van npm `qrcode-generator@2.0.4` (`npm pack qrcode-generator@2.0.4`)
- **SHA-256:**
  - `qrcode.js` — `79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c`
  - `qrcode_UTF8.js` — `e522d64003b332e29271fdce4993ed3ae2934c8947f41654bd324ddcfa2de301`
  - `LICENSE.MIT` — `91a34af6a2dfe121adbc7ffe32c86d483d1d251d43be54b405d9ac3ca7d0bcb3`

## sheetjs/
- **Versie:** xlsx (SheetJS Community Edition) 0.18.5
- **Licentie:** Apache-2.0 (zie `sheetjs/LICENSE.APACHE-2.0`)
- **Bron:** https://github.com/SheetJS/sheetjs (community 0.18.x, oude npm-published versie; nieuwere versies via cdn.sheetjs.com)
- **Bestand:** `xlsx.mini.min.js` (245 KB — minimale variant zonder styling/codepage, voldoende voor onze plaintext-import/export)
- **Doel:** XLSX-parsing (`.xlsx` workbook → JSON-rijen) en building (entries → workbook) voor import/export-wizards
- **Globale namespace:** `window.XLSX`

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
