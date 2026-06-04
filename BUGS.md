# BUGLIST.md — HorseSafe

> Conform `feedback_debug_buglist_protocol.md`: alle bugs met kleurcode + RCA op 3 niveaus.

Kleurcodes:
- 🟢 **Groen** = snel herstel (fysiek niveau)
- 🟡 **Geel** = out-of-physical-box (logische architectuur)
- 🔴 **Rood** = out-of-the-box (conceptueel redesign + security-audit)
- 🔁 **Loop** = debug-loop — nieuwe invalshoek nodig

---

## Open bugs

### HS-BUG-005 — kdbxweb 2.1.1 browser-side faalt op KeePassXC 2.x XML keyfile + op 32-byte raw keyfile

**Kleur:** 🟡 Geel (logische architectuur — KDBX-keyfile-format-restrictie)
**Status:** RESOLVED 2026-06-05 (via format-shift naar 64-hex-ASCII keyfile)
**Versie ontdekt:** v0.0.9-Bellare (browser-test van pw + keyfile-vault-open)
**Versie opgelost:** v0.0.9-Bellare (zelfde sessie — Node-resave-roundtrip)

**Symptoom:** Vault openen via `crypto.subtle` in browser geeft `KdbxError: InvalidKey` ondanks dat zowel pykeepass (Python) als kdbxweb in Node dezelfde db+pw+keyfile-combinatie correct ontsleutelen. SHA-256 van blob op server = identiek aan lokale blob; pw-only-pad werkt; alleen pw+keyfile faalt vanuit de browser.

**RCA — drie niveaus:**
- **Functioneel:** Eindgebruiker kan KeePassXC-`.keyx` (XML 2.0) keyfiles uit zijn lokale workflow niet hergebruiken voor HorseSafe-vault-open via de webclient. Foutmelding "InvalidKey" misleidt naar "verkeerd wachtwoord" — diagnose duurt onnodig lang.
- **Technisch:** `kdbxweb 2.1.1` `Credentials.setKeyFile()` heeft twee paden die in browser anders uitkomen dan in Node:
  1. **32-byte raw**: short-circuit `keyFileHash = ProtectedValue.fromBinary(keyFile)` zonder hashing — bug in roundtrip (save/load berekenen verschillende master-keys).
  2. **XML 2.0 met `<Data Hash="...">`**: parsing via `XmlUtils.parse` valt onder browser-native `DOMParser` (CSP COEP `require-corp` + whitespace-handling) anders dan Node-`@xmldom/xmldom`. Resultaat: andere keyfileHash → mismatch master-key.
  3. **64-hex-char ASCII pad** (`/^[a-f\d]{64}$/i`): hex-decode is identiek in alle runtimes → consistent.
- **Architectonisch:** HorseSafe-cardinaal §2 "KDBX4-compat" + `kdf_in_use: AES-KDF (KeePassXC-CLI-verified)` veronderstelt dat alle kdbxweb-keyfile-formaten interoperabel zijn met KeePassXC-desktop. Praktijk: kdbxweb 2.1.1 ondersteunt **drie input-paden** met **verschillende compatibiliteits-profielen** in browser. Verwachting "default KeePassXC 2.x XML keyfile" (CLAUDE.md cardinaal cryptografische defaults) klopt niet voor de browser-runtime.

**Fix (workaround, niet upstream-fix):**
- Node-runtime kdbxweb gebruikt om vault te re-encrypteren met **64-hex-char ASCII keyfile** (32 random bytes → hex → ASCII-bytes → `.keyx` met 64 bytes).
- Database lokaal (`~/Downloads/Database.kdbx` + `Database.keyx`) overschreven met v5-pair; originelen als `.bak-20260605` bewaard.
- Server-vault via `PUT /vault/{id}` met etag-match geüpdatet naar v5-blob (6887 B, etag `99f60239d80c...`).
- `kdbxweb`-browser kan v5 nu zonder issue openen — bewezen door 3-runtime roundtrip (Node-kdbxweb + pykeepass + KeePassXC-spec).

**Preventie:**
- **Cryptografische default-update**: HorseSafe genereert voortaan keyfiles in 64-hex-char ASCII-format (niet KeePass 2.x XML). Update CLAUDE.md "Cryptografische defaults" tabel volgt in v0.1.0-Massey.
- **CI-uitbreiding**: voeg `kdbxweb-browser ↔ pykeepass ↔ KeePassXC-CLI`-roundtrip toe met alle drie keyfile-formaten als fixture; markeer XML-2.0 en 32-byte raw als "import-only, niet voor generate".
- **Upstream-issue**: rapport naar `antelle/kdbxweb` voor 32-byte-raw save/load-inconsistentie + XML-2.0-browser-DOMParser-pad (TODO).
- **Documentatie**: `ARCHITECTURE.md §1.3` keyfile-tabel uitbreiden met "import-compatibel vs generate-default".

---

### HS-BUG-004 — vault.html mist `js/auth.js` → uitloggen-knop reageert niet

**Kleur:** 🟡 Geel (logische architectuur — script-dependency-graph)
**Status:** RESOLVED 2026-05-22 (commit `e04cebc`)
**Versie ontdekt:** v0.0.7-Bellare (post-CSP-fix intern-test)
**Versie opgelost:** v0.0.7-Bellare (zelfde dag)

**Symptoom:** "Uitloggen"-knop op vault-pagina reageert niet. Geen redirect naar login. Browser-console toont geen error.

**RCA — drie niveaus:**
- **Functioneel:** Uitloggen-actie heeft geen effect; gebruiker blijft op vault-pagina.
- **Technisch:** `vault.html` laadt `js/auth.js` niet (script-include ontbrak). `main.js` riep `window.HorseSafeAuth?.logout?.()` aan met optional-chaining → silent fallthrough als `HorseSafeAuth` undefined → click-handler complete zonder error of effect.
- **Architectonisch:** Script-dependency-graph werd niet per-HTML gevalideerd. Optional-chaining-pattern (`?.method?.()`) verbergt missing-script-bugs door silent no-op i.p.v. zichtbare ReferenceError.

**Fix:**
- `vault.html`: `<script src="js/auth.js"></script>` toegevoegd vóór `main.js`.
- `main.js`: `window.HorseSafeAuth?.logout?.()` → `window.HorseSafeAuth.logout()` (laat fouten zichtbaar worden bij toekomstige missing-script in plaats van silent fail).
- Commit `e04cebc` + rsync naar HC55.

**Preventie:**
- Toekomstige HTMLs: valideren dat alle `window.HorseSafe*`-referenties bijbehorende `<script src>` hebben.
- CI-check: grep voor `window\.HorseSafe[A-Z]\w*` in `*.js` en cross-checken tegen `<script src>` in HTMLs die die js-files laden.
- Optional-chaining alleen voor genuine-optionele dependencies (bv. extension-injectie), niet voor verwachte same-page modules.

---

### HS-BUG-003 — CSP blokkeert inline scripts → "Account aanmaken" reageert niet

**Kleur:** 🔴 Rood (frontend onbruikbaar in productie)
**Status:** RESOLVED 2026-05-22
**Versie ontdekt:** v0.0.7-Bellare (productie intern-test)
**Versie opgelost:** v0.0.7-Bellare (zelfde dag — hotfix in commit 1931267)

**Symptoom:** "Account aanmaken"-knop reageert niet. Geen form opent. Browser-console toont CSP-violation: `Refused to execute inline script because it violates the following Content Security Policy directive`.

**RCA — drie niveaus:**
- **Functioneel:** Alle UI-knoppen op 5 HTMLs reageren niet — frontend onbruikbaar
- **Technisch:** Productie-CSP `script-src 'self' 'wasm-unsafe-eval'` (geen `'unsafe-inline'`). 5 HTMLs hadden inline `<script>`-blocks voor page-init / event-binding → geblokkeerd
- **Architectonisch:** Lokaal dev (`python -m http.server`) stuurt geen CSP → inline-scripts werkten daar. Productie via nginx + backend-middleware enforce't strict. Playwright-e2e in CI gebruikt ook plain http.server → testdekking-gap

**Fix:**
- Extract inline `<script>` blocks naar 5 externe files:
  - `js/page-index.js`, `js/page-login.js`, `js/page-shares.js`, `js/page-import.js`, `js/page-export.js`
- HTMLs vervangen inline-blok door `<script src="js/page-X.js">`
- Commit `1931267` + rsync naar HC55 (geen nginx-reload nodig)

**Preventie:**
- Toekomstige HTMLs: ALLE logica in externe files
- CI-check toevoegen: grep voor `<script>` zonder `src=` attribuut in HTMLs
- Playwright-e2e overstappen naar `devserver.py` (CSP-headers actief)

---

### HS-BUG-002 — basic-auth popup op /HorseSafe (zonder trailing slash)

**Kleur:** 🟡 Geel
**Status:** RESOLVED 2026-05-22
**Versie ontdekt:** v0.0.7-Bellare (productie-deploy)
**Versie opgelost:** v0.0.7-Bellare (zelfde dag — hotfix in nginx-snippet)

**Symptoom:** User die `horsecloud55.ddns.net/HorseSafe` typt (zonder trailing slash) kreeg HorseCloud basic-auth-popup. Gemeld tijdens intern-test van Christian.

**RCA — drie niveaus:**
- **Functioneel:** Onverwachte basic-auth-popup op trailing-slash-loze URL
- **Technisch:** Nginx `location /HorseSafe/ {}` matcht `/HorseSafe/x` maar NIET de exacte URI `/HorseSafe`. Request valt door naar `location / {}` die `auth_basic "HorseCloud"` heeft
- **Architectonisch:** Nginx-snippet ontbreekt exact-match-redirect voor de trailing-slash-loze variant. Standaard-praktijk om expliciet te redirect

**Fix:**
- `scripts/nginx_snippet.conf`: extra `location = /HorseSafe { auth_basic off; return 301 /HorseSafe/; }` toegevoegd
- Diff in commit `6861cf1`
- Deploy: scp + `nginx -t && systemctl reload nginx`
- Verify: `curl -I /HorseSafe` → 301 + Location → /HorseSafe/ → 200 OK

**Preventie:**
- Future deploys: include `location =` exact-match-redirects voor alle prefix-locations naast root-paths
- Smoke-test uitgebreid worden om beide trailing-slash-varianten te checken

---

### HS-BUG-001 — argon2-browser WASM hangt in headless Chromium

**Kleur:** 🟡 Geel
**Status:** open (gemitigeerd, definitief deferred naar v1.0-Bernstein productie-pre-release)
**Versie ontdekt:** v0.0.2-Hellman (2026-05-21)
**Versie heroverweging:**
- v0.0.3-Merkle — `frontend/devserver.py` retry-vector aangemaakt
- v0.0.5-Shamir (2026-05-21) — retry-vector aanwezig + KeePassXC-CLI oracle-test bewijst dat AES-KDF-vaults volledig roundtrippen naar KeePassXC-desktop. Argon2id-default niet kritiek voor disaster-recovery (KDBX4 + AES-KDF is spec-conform). **Definitief deferred** naar v1.0-Bernstein productie-pre-release pen-test, waar de KDF-default opnieuw geëvalueerd wordt (mogelijk samen met PQC-overweging zoals Argon2id → Kyber-derived).

**Symptoom:** `kdbxweb.Kdbx.create()` met default-Argon2d-KDF hangt op `db.save()` in headless Chromium via Playwright. Geen fout, geen timeout in browser — gewoon nooit klaar. `argon2-bundled.min.js` + `argon2.wasm` correct geladen, `window.argon2` en `window.kdbxweb` beide aanwezig. Hash-call resolveert nooit.

**RCA — drie niveaus:**
- **Functioneel:** Vault-creation in browser blokkeert voor onbepaalde tijd. Gebruiker ziet "spinner forever" zonder error.
- **Technisch:** `argon2-bundled.min.js` initialiseert WASM-binary via emscripten-loader. In headless Chromium met `python -m http.server` als origin: ofwel MIME-type-check op `argon2.wasm` mismatcht (server stuurt `application/octet-stream` ipv `application/wasm`), ofwel crossOriginIsolated-eis (geen COOP/COEP op static-server) blokkeert SharedArrayBuffer-pad. argon2-browser hangt zonder errorbericht.
- **Architectonisch:** Frontend-static-serve-stack heeft geen COOP+COEP-headers in dev. Productie-nginx kan dit wel (SecurityHeadersMiddleware in backend doet dit voor /api responses, niet voor static frontend).

**Mitigatie v0.0.2:** Nieuwe vaults gebruiken **AES-KDF** (`db.header.setKdf(KdfId.Aes)` na `Kdbx.create()`). KDBX-spec-conform, snel, geen externe WASM-deps, opent in KeePassXC-desktop. Argon2-bridge blijft staan in crypto.js voor toekomstige Argon2-vault-imports (Fase 5).

**Fix v0.0.3 (target):**
- Test argon2-browser in echte Chrome/Firefox/Safari (niet headless) — werkt het daar wel?
- Custom dev-server-script die COOP+COEP + correcte WASM MIME-type stuurt
- Of: vervang argon2-browser door alternatief WASM-package (bv. `hash-wasm`)
- Of: houd Argon2id strikt server-side voor account-pw + houd AES-KDF voor vault-laag (server kent vault-blob niet, dus geen privacy-issue)

## Gepland te traceren (preventief)

| ID | Voorzien type | Beschrijving | Mitigatie-strategie |
|---|---|---|---|
| HS-BUG-PRE-001 | 🟡 Geel | KDBX4-round-trip via kdbxweb produceert bestand dat KeePassXC weigert | CI-test: schrijf met kdbxweb → open met KeePassXC-CLI (`keepassxc-cli ls`) |
| HS-BUG-PRE-002 | 🟡 Geel | Argon2id-perf in browser onacceptabel op zwakke devices (mobiel) | Benchmark t=12/m=128MiB op iPhone X-equivalent; fallback t=8/m=64MiB met UI-warning |
| HS-BUG-PRE-003 | 🔴 Rood | Clipboard-wipe faalt → pw blijft na 10s | Documenteer in UI ("best-effort"); v0.2 = extensie |
| HS-BUG-PRE-004 | 🟡 Geel | Optimistic-lock-conflict bij snelle multi-tab edit | Tonen "vault is elders gewijzigd, kies versie" dialog |
| HS-BUG-PRE-005 | 🟢 Groen | Magic-link e-mail wordt als spam gemarkeerd | SPF+DKIM check op iCt_Horse magic-link bridge |
| HS-BUG-PRE-006 | 🟡 Geel | TOTP-drift > 30s door device-clock-skew | RFC 6238 ±1 window-tolerance (= ±30s) instellen in pyotp |
| HS-BUG-PRE-007 | 🔴 Rood | Backend logt per ongeluk KDBX-blob in stderr | strict-mode logging: alleen request-pad + status, nooit body |
| HS-BUG-PRE-008 | 🟡 Geel | Import-CSV met UTF-8-BOM crasht parser | Fixture-tests met BOM, UTF-16, Windows-1252 |
| HS-BUG-PRE-009 | 🟢 Groen | XLSX-export wordt > 50 MB bij grote vaults | Streaming-write met openpyxl write-only mode |
| HS-BUG-PRE-010 | 🟡 Geel | Browser-extensie native-message verliest sync met tab | Heartbeat-protocol elke 5s |

## Resolved bugs

_Nog niets — repo is skeleton-only._

---

## RCA-template (verplicht bij elke bug-resolutie)

```markdown
### HS-BUG-NNN — <korte titel>

**Kleur:** 🟢/🟡/🔴/🔁
**Status:** open / in-progress / resolved
**Versie ontdekt:** v0.x.y-Codename
**Versie opgelost:** v0.x.y-Codename

**Symptoom:** ...

**RCA — drie niveaus:**
- **Functioneel:** wat zag de gebruiker / wat brak in de feature
- **Technisch:** welke code / config / library / data was de directe oorzaak
- **Architectonisch:** welke ontwerpkeuze maakte deze bug mogelijk

**Fix:**
- Diff: <link naar commit>
- Test: <link naar test-bestand>

**Preventie:**
- Welke check zou dit in de toekomst vangen?
```
