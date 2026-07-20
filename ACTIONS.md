# Openstaande Acties — HorseSafe

> Laatst bijgewerkt: 2026-07-20

## 🆕 2026-07-20 — v0.1.0-Massey (public launch, deels)

- [x] ~~**icthorse.nl/HorseSafe/ LIVE** — Hostinger subdir-.htaccess 302 → HC55, beide casings, e2e geverifieerd~~ ✅
- [x] ~~**Pen-test-checklist v0.1.0** — 8 punten tegen LIVE; 1 fix (OpenAPI-docs dicht in productie via `docs_enabled=false`), rest groen; SECURITY.md-tabel~~ ✅
- [x] ~~**Versie-bump** 0.0.10-Goldwasser → 0.1.0-Massey (config.py + version.json)~~ ✅
- [x] ~~**Backend pytest** 68/68 groen (incl. nieuwe docs-off test)~~ ✅
- [x] ~~**Deploy HC55** — git pull + docs-env + restart; health toont 0.1.0-Massey; /api/docs → 404~~ ✅
- [x] ~~**Privacy-statement finaal** (0.1.0) + LAUNCH_PREP.md (LinkedIn-draft + sitemap-entry)~~ ✅
- [ ] 🚧 **BLOKKEREND: git-history-scrub** — plaintext-wachtwoorden (`[REDACTED-PREFIX]*`) in history; scrub-procedure in LAUNCH_PREP.md §1. Public-go pas hierna.
- [ ] **Repo PUBLIC + AGPL-3.0** — na scrub (LAUNCH_PREP.md §2)
- [ ] **Sitemap + LinkedIn** — na public (LAUNCH_PREP.md §3-4)
- [ ] **Backup Storagebox** — GEBLOKKEERD op Storagebox SSH-credentials (LAUNCH_PREP.md §5)
- [ ] **Magic-link mail** — GEBLOKKEERD op Gmail App Password (LAUNCH_PREP.md §5)
- [ ] **Dashboard health-tile** — nieuwe feature in Dashboard-repo, uitgesteld (LAUNCH_PREP.md §6)

## 🆕 2026-07-20 — v0.0.10-Goldwasser (test-rerun + HS-BUG-006 unlock-foutmelding)

- [x] ~~**Backend pytest rerun** — 67/67 groen (Python 3.14 venv)~~ ✅ 2026-07-20
- [x] ~~**Playwright e2e rerun** — eerst 4/5 (regressie ontdekt), na fix **5/5 groen**~~ ✅ 2026-07-20
- [x] ~~**HS-BUG-006 fix** — `vault-ui.js` toont bij `InvalidKey` weer "Verkeerd wachtwoord of verkeerde keyfile." i.p.v. rauwe foutcode; BUGS.md-entry met RCA~~ ✅ 2026-07-20
- [x] ~~**Versie-bump** — config.py + version.json → 0.0.10-Goldwasser~~ ✅ 2026-07-20
- [ ] **KeePassXC-CLI roundtrip** — draait in CI bij push (lokaal geen keepassxc-cli); CI-status verifiëren na push
- [ ] **Deploy naar HC55** — vault-ui.js + version.json + backend config.py + service-restart + live-health-check

## 🆕 2026-06-05 — v0.0.9-Bellare (Keyfile vault-open + per-entry live TOTP + KeePass-migratie)

- [x] ~~**Wipe LIVE DB + vault-dir** op HorseCloud55 (2 users → 0)~~ ✅ 2026-06-04
- [x] ~~**Register `cglebbeek@gmail.com`** met account-pw `[REDACTED-ACCOUNT-PW]`~~ ✅ 2026-06-04
- [x] ~~**Vault-upload** — 33 entries uit `~/Downloads/Database.kdbx` (KeePass-import) als vault-blob~~ ✅ 2026-06-04
- [x] ~~**Frontend keyfile-input** — `vault.html` + `crypto.js` `openDatabase(pw, keyfile)` + `vault-ui.js` file-arrayBuffer~~ ✅ 2026-06-04
- [x] ~~**Versie-bump** — version.json 0.0.8-Rogaway → 0.0.9-Bellare~~ ✅ 2026-06-04
- [x] ~~**Keyfile-format-shift** naar 64-hex-ASCII (HS-BUG-005 workaround) — vault v5 + lokale pair vervangen~~ ✅ 2026-06-05
- [x] ~~**Per-entry TOTP-renderer** — `js/totp.js` RFC 6238 via WebCrypto + UI rij + interval-lifecycle~~ ✅ 2026-06-05
- [x] ~~**Deploy naar HC55** — rsync frontend (`vault.html`, 4 js-files, `version.json`) + service active~~ ✅ 2026-06-05
- [x] ~~**Live smoke-test** — login + vault-open met pw+keyfile + TOTP-codes zichtbaar (GitHub + Exact Online)~~ ✅ 2026-06-05
- [x] ~~**Backend version-string fix** — `config.py` `app_version` `0.0.8-Rogaway` → `0.0.9-Bellare`; LIVE-health geverifieerd~~ ✅ 2026-06-05 P2 (commit cdd4aa8)
- [x] ~~**pytest 67/67 + playwright 5/5 + KeePassXC-CLI roundtrip** rerun met nieuwe keyfile + TOTP-flow~~ ✅ 2026-07-20 v0.0.10-Goldwasser (pytest 67/67 + playwright 5/5 lokaal; oracle via CI)
- [x] ~~**UI_DESIGN.md** TOTP-cell + keyfile-input documenteren~~ ✅ 2026-06-05 P2
- [x] ~~**DESIGN_TOKENS.md** monospace 1.3em letter-spacing 0.15em + TOTP-tokens~~ ✅ 2026-06-05 P2 (`--hs-totp-*`)
- [x] ~~**DEPENDENCIES.md** `crypto.subtle.sign('HMAC')` browser-native dependency~~ ✅ 2026-06-05 P2 (WebCrypto-rij uitgebreid + nieuwe `js/totp.js`-rij)
- [x] ~~**SEQUENCE_DIAGRAMS.md** TOTP-render-loop + keyfile-vault-open-flow~~ ✅ 2026-06-05 P2 (SQ-8 nieuw + SQ-4 reaffirmed in ARCHITECTURE §2.4)
- [x] ~~**docs/screens/S06_unlock.md + S07_content.md** content-update met TOTP-rij + keyfile-input + format-restrictie-tabel~~ ✅ 2026-06-05 P3
- [ ] **docs/screens/** screenshots toevoegen (PNG van detail-pane + unlock-form) — visuele referentie, low-prio
- [ ] **Upstream-issue kdbxweb** — open op `antelle/kdbxweb` voor XML 2.0 + 32-byte raw inconsistentie. Issue-body = `BUGS.md` HS-BUG-005 RCA-tekst (gebruiker-actie: kopieer naar https://github.com/antelle/kdbxweb/issues/new)
- [x] ~~**/opt/horsesafe/web/ cleanup** — devserver.py, node_modules, package.json, package-lock.json, playwright.config.ts, README.md, tests/, test-results/ verwijderd; LIVE-health geverifieerd na cleanup~~ ✅ 2026-06-05 P3
- [x] ~~**BUGS.md HS-BUG-004 doc-entry** (pre-existing gap — commit e04cebc had fix maar geen doc-entry)~~ ✅ 2026-06-05 P3

## 🆕 2026-05-18 — v0.0.8-Rogaway (XLSX-import + XLSX-export)

- [x] ~~**SheetJS vendoren** — `frontend/vendor/sheetjs/xlsx.mini.min.js` (0.18.5, Apache-2.0, 245 KB)~~ ✅ 2026-05-18
- [x] ~~**`parseXlsx` + `buildXlsx`** in `frontend/js/import-export.js`~~ ✅ 2026-05-18
- [x] ~~**UI** — xlsx-optie in import.html + export.html dropdowns, script-include~~ ✅ 2026-05-18
- [x] ~~**Versie-bump** — config.py + version.json → 0.0.8-Rogaway~~ ✅ 2026-05-18
- [ ] **Deploy naar HC55** — git pull + rsync frontend (vendor + js + html) + restart systemd
- [ ] **Live-verificatie** — XLSX-export download op live + reimport-round-trip

## 🆕 2026-05-21 — newp Fase 2 → Fase 3+

Skeleton + ontwerp-documenten af. Volgende stappen vereisen akkoord:

- [ ] **GitHub-remote aanmaken** — `gh repo create cpaglebbeek/HorseSafe --private` + initial push (wacht op akkoord in deze sessie)
- [ ] **Tarball consume + extract** — `/bugcheck consume 103502_keepassxc-2.7.12-src.tar.xz_ecc9c5` → kopie in `specs/keepassxc-source/` als referentie (LEZEN-only, geen vendoring) (wacht op akkoord)
- [ ] **/sanitycheck draaien** op skeleton (newp-fase N+1, verplicht)
- [x] ~~**Fase 1 — Backend skeleton** — FastAPI-app met /auth/register, /auth/login, /vault, /vault/{id} GET+PUT (geen MFA nog, alleen auth-laag 1). Doel: lokaal draaien met `uvicorn`. Geen deploy.~~ ✅ 2026-05-21 — 15/15 tests, 96% coverage, smoke-test ok
- [x] ~~**Fase 2 — Frontend POC** — HTML+vanilla-JS met kdbxweb. Login + vault-unlock + 1 entry tonen. Geen UI-polish.~~ ✅ 2026-05-21 — kdbxweb+argon2 vendored, S1/S2/S6/S7 schermen LIVE, e2e playwright 2/2 groen, full roundtrip (registreer + login + vault-create in browser + entry + pw-toggle + lock + reopen) werkt
- [x] ~~**Fase 3 — MFA integratie** — magic-link bridge naar iCt_Horse + TOTP setup-flow~~ ✅ 2026-05-21 — TOTP RFC 6238 + AES-GCM-encrypted-at-rest secret + Gmail SMTP magic-link + vault-MFA-gate; backend 25/25 pytest + frontend 3/3 playwright; qrcode-generator vendored; settings-page + mfa-challenge-page LIVE
- [x] ~~**Fase 4 — Admin-pagina** — user-CRUD + storage-stats + audit-log-viewer + MFA-backup-codes + admin-rescue~~ ✅ 2026-05-21 — admin.html (S11) + backup-codes.html (S13) + 6 admin-endpoints + 3 auth-endpoints (/me, backup-codes/{generate,verify}) + bcrypt-hashed backup-codes (single-use) + DB-migrate runner + CLI promote-admin; backend 40/40 pytest + frontend 5/5 playwright
- [x] ~~**Fase 5 — Import/export + KDBX-roundtrip-oracle**~~ ✅ 2026-05-21 — KDBX3/4 + Bitwarden JSON + KeePass-CSV import/export (XLSX uitgesteld v0.0.7+) + admin-CSV-audit-export + account-pw-change + KeePassXC-CLI oracle in CI; backend 54/54 pytest + frontend 5/5 playwright; client-side parse (zero-knowledge intact); BUG-001 definitief deferred naar v1.0-Bernstein
- [x] ~~**Fase 6 — Vault-sharing**~~ ✅ 2026-05-21 — ECDH-P256 (WebCrypto native) + AES-GCM-wrapped private-key + per-entry share + inbox/decline/accept; backend 67/67 pytest + 4 nieuwe audit-events + DB-migratie 004; frontend shares.html + js/sharing.js + keypair-gen in settings + Deel-knop in vault; zero-knowledge intact (server kent alleen pubkeys + opaque ciphertexts)
- [ ] **Browser-extensie** (v0.2.0+) — MV3, autocomplete, échte clipboard-wipe (uitgesteld, optioneel)
- [x] ~~**Fase 7 — Productie-deploy HC55**~~ ✅ 2026-05-22 — LIVE op https://horsecloud55.ddns.net/HorseSafe/ ; systemd + nginx-snippet + backup-cron actief; auth_basic off voor /HorseSafe/-paths (eigen JWT+MFA); live-smoke-test groen (health + register + login + vault + me + logout)
- [ ] **v0.1.0-Massey** — public launch: icthorse.nl/HorseSafe/ subdomain + externe pen-test + open-source AGPL + Dashboard-tile + LinkedIn-aankondiging

## Niet-blokkerende vervolgvragen (WhatIf-uitloop)

- [ ] **Wachtwoord-policy globaal config** — wil je een per-server-policy (min-lengte 12, ...) afdwingen voor account-pw? Of laissez-faire? (open)
- [ ] **GDPR DPIA** — voor latere dienst-aanbieding aan zakelijke klanten: DPIA-template opstellen wanneer eerste betalende klant? (uitstellen tot v0.1.0)
- [ ] **Open-source moment** — bij welke versie public maken? Default-voorstel was v0.1.0 zodra MFA + KDBX-compat bewezen werkt. Akkoord blijft? (open)
- [ ] **Codenaam v0.0.1** — Rijndael past bij Daemen+Rijmen (AES-ontwerpers). Akkoord? Of liever start met Diffie? (default: Rijndael)
- [ ] **CI-platform** — GitHub Actions voor tests (gratis voor private repo's tot 2000 min/maand)? (default: ja)
- [ ] **Disaster-recovery user-flow** — moet user expliciet aangemoedigd worden om elke 30 dagen een KDBX-export te downloaden? E-mail-reminder? (open)

## Backlog (lange termijn)

- [ ] **Shared vaults** (v0.2+) — re-encryptie per ontvanger
- [ ] **Offline-modus** (v0.1+) — ServiceWorker-cache laatste blob
- [ ] **FIDO2/WebAuthn** (v0.3+) — hardware-token MFA-laag
- [ ] **Mobile-app** (v1.0?) — native Android (Kotlin Compose) wrapper
- [ ] **CLI-tool** — `horsesafe-cli` voor scripts (KeePassXC-cli equivalent)
- [ ] **Audit-export** — user kan eigen audit-log downloaden
- [ ] **Vault-templates** — pre-defined categorieën (Email, Banking, Social, Work) voor new-vault-bootstrap
- [ ] **TOTP-codes in entries** — entry kan TOTP-secret bevatten → preview-code in UI (KeePassXC-feature)
- [ ] **Yubico OTP / OnlyKey** — als extra MFA-optie

## Afgerond

- [x] ~~Repo-skeleton + ontwerp-documenten~~ ✅ 2026-05-21
- [x] ~~Naamkeuze HorseSafe + codenaam-thema Cryptografen + v0.0.0-Rijndael~~ ✅ 2026-05-21
- [x] ~~WhatIf-akkoord op 22 punten (alle defaults)~~ ✅ 2026-05-21
- [x] ~~GitHub-remote `cpaglebbeek/HorseSafe` (PRIVATE) aanmaken + initial push~~ ✅ 2026-05-21
- [x] ~~Tarball-consume + extract naar `Meta_iCt_Horse_Diensten/sources/keepassxc-source/`~~ ✅ 2026-05-21
- [x] ~~`/sanitycheck` op skeleton (newp-fase N+1)~~ ✅ 2026-05-21 (PASS ~95%)
- [x] ~~P2: `docs/screens/` + `.github/workflows/ci.yml` + `Meta_Master/TODO_VASTLEGGING.md` entry~~ ✅ 2026-05-21
- [x] ~~**Fase 1 — Backend FastAPI-skeleton v0.0.1-Diffie**~~ ✅ 2026-05-21 (15/15 tests groen, 96% coverage, smoke-test ok)
