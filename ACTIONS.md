# Openstaande Acties — HorseSafe

> Laatst bijgewerkt: 2026-10-14

## 🆕 2026-10-14 — telefoon-ontgrendelen naar voren (Miller deel 2 → Montgomery)

Doel Christian: HorseSafe op de laptop openen zonder YubiKey, alleen met de telefoonvinger. Besluiten: `docs/HARDWARE_KEYS.md` §11.2. Sessie: `prompts/2026-10-14_telefoon_ontgrendelen.md`.

- [x] ~~**Besluiten** — volgorde omgedraaid, één app met INTERNET, code van 6 cijfers + commitment-SAS i.p.v. QR~~ ✅ 14-10
- [x] ~~**Besluit R4 release-keystore**~~ ✅ 14-10 — eigen keystore (a), uitvoering in fase A
- [ ] **Fase A — Miller deel 2 (0.3.4)**: bouwplan (WhatIf) + akkoord; migratie 006, device-API, key-attestation, web "Telefoon koppelen", app INTERNET/QR/SAS/Keystore/Seal.kt, emulator `hb-horsesafe`
- [ ] **Fase B — Montgomery (0.4.0)**: contract §5 herschrijven volgens §11.2 + akkoord; migratie 007, approvals, web "Ontgrendel met telefoon", app goedkeuringskaart; veldtest laptop + telefoon

## 🆕 2026-10-12 — v0.3.0-Miller deel 1 (Android: YubiKey inrichten en keuren)

Bouwplan + kritiekcorrecties: akkoord Christian 12-10. Ontwerp: `docs/HARDWARE_KEYS.md` §4.1, §7.1, §10, §11.1. Bouwen/testen/publiceren/checklist: `android/README.md`. Sessie: `prompts/2026-10-12_miller_deel1.md`.

**Gedaan**
- [x] ~~**`android/` gebouwd** — één module `:app`, yubikit 3.0.1, geen INTERNET; inrichten (nieuw + hervatten), keuren zonder/met PIN, PIN wijzigen, vingers beheren, oefenen, rapport (whitelist, serial-HMAC, export/import)~~ ✅ 12-10
- [x] ~~**Tests** — `testDebugUnitTest` 250/250, `lintRelease` 0 errors (16 warnings), `verifyYubikitHashes` 4/4, `verifyNoSlf4jProvider` groen (build-box via `remote-gradle.sh`)~~ ✅ 12-10
- [x] ~~**Release-APK lokaal op HC55** — versionCode 300 / 0.3.0-Miller, sha256 `1efcec3b…6cfd`, `scripts/verify_apk.sh` GROEN (signer `32491e0f…3f17`)~~ ✅ 12-10
- [x] ~~**Versie** — `version.json` 0.3.0 Miller (phase 11), `backend/config.py` + `test_health.py` 0.3.0-Miller (pytest 196/196), `frontend/vault.html` footer~~ ✅ 12-10
- [x] ~~**Docs** — HARDWARE_KEYS §4.1/§7/§9/§10/§11.1, THREAT_MODEL R4 + R16–R21, ROADMAP, CHANGELOG, UI_DESIGN + `docs/screens/M00..M12`, `android/README.md`, README-status~~ ✅ 12-10

**Open (Miller deel 1)**
- [ ] **Commit** — per bestand `git add` (nooit `-A`; `.github/workflows/ci.yml` NIET meenemen), aparte commit voor de versie-bump; daarna push (akkoord Christian)
- [ ] **Bevestigen door Christian** — release-build blokkeert PIN-schermen ook bij alleen ontwikkelaarsopties aan (advies: ja); antwoorden op de open vragen van het plan waar nu volgens advies gebouwd is (§11.1)
- [x] ~~**Emulator-smoke** — `android/scripts/smoke.sh` op hb-root (na WhatIf + akkoord; gedeelde infra): start, `logcat -b crash` leeg, FLAG_SECURE; ook InitializationProvider-verwijdering en dispatchKeyEvent controleren~~ ✅ 2026-10-12 — release-APK op emulator-5584 (Android 16) en emulator-5554 (Android 14): 0 FATAL, proces leeft, screencap zwart (FLAG_SECURE), M0 toont ADB-blokkade. Niet gedaan: dispatchKeyEvent met hardwaretoetsen
- [ ] **Hardwaretest (Christian)** — eerst wisbare testsleutel: min 63 accepteert, 0x1D aanwezig, firmware Bio ≥ 5.7.2 / YK5 ≥ 5.7.0, USB op de Fold6, U2F na alwaysUv, NFC-timeouts, FLAG_SECURE vs Link to Windows/DeX, `adb_wifi_enabled` leesbaar; dan echte Bio + noodsleutel; resultaten in `version.json`
- [x] ~~**Publicatie** — `apk-publish.sh HorseSafe HorseSafe-v0.3.0-Miller-release.apk` (release-artefact, lokaal gebouwd) na smoke + akkoord; update-aanbod in de HorseAPK-app aantonen~~ ✅ 2026-10-12 23:04 UTC — HorseAPK manifest: versionCode 300, sha256 1efcec3b…6cfd, signer 32491e0f…3f17. Open: update-aanbod in de HorseAPK-app op de Fold6 aantonen (Christian)
- [ ] **Server-side minPinLength/credProtect-patch** (Koblitz 0.2.x) — afdwingen bij koppelen + MPE weigeren via veld `variant` in `aaguids.json` (THREAT_MODEL R18); eerst Chrome-ondersteuning meten
- [ ] **androidTest** met fake-`KeyLink` ("M4 geblokkeerd bij ADB/a11y", kritiek 11) — vraagt test-afhankelijkheden + emulator
- [ ] **Attestation-vectoren** in `specs/testvectors/attestation/` met clientDataJSON + `backend/tests/test_attestation_vectors.py`
- [ ] **CI-job `android`** (aparte commit, `gh auth refresh -s workflow`); de structuuraudit breekt niet op `android/` (alleen aanwezigheid van vaste dirs gecontroleerd), maar `android` staat ook niet in de lijst
- [ ] **Docs** — ARCHITECTURE, COMPONENT_DIAGRAM, SEQUENCE_DIAGRAMS (SQ-13 inrichten, SQ-14 keuren), DEPENDENCIES (yubikit-licenties), SECURITY, DPIA (korte herbeoordeling); `/ModelArchDSL update` voor `ac_android`
- [ ] **Release-keystore** — eigen keystore buiten de repo of debug-keystore bewust aanvaarden (R4, kritiek 13)
- [ ] **Miller deel 2 (0.3.1)** — ontgrendelen op de telefoon, koppelen (QR + SAS), telefoon-credential, device-API, migratie 006, in-app update; pas na de veldtest en een nieuw akkoord

## 🆕 2026-10-10 — v0.2.0-Koblitz (hardware-sleutels in het web, server-geverifieerd)

Ontwerp + bindend contract: `docs/HARDWARE_KEYS.md` (§12). Besluiten Christian 10-10-2026: §11 (bindend).

**Gedaan**
- [x] ~~**WIP veiliggesteld** — onafgemaakt werk van sessie 42d3ff7c ongewijzigd gecommit (`9000044`)~~ ✅ 2026-10-10
- [x] ~~**Verkenning WIP** — zes bevindingen vastgelegd als HS-BUG-007 (fail-open, audit vóór verificatie, blokkerende SMTP, migratiepatroon)~~ ✅ 2026-10-10
- [x] ~~**Ontwerp + besluiten** — `docs/HARDWARE_KEYS.md` met Koblitz API-contract; besluiten 1-7 vastgesteld~~ ✅ 2026-10-10
- [x] ~~**P-CRYPT-09** in `PRINCIPLES.md` (+ P-AUTH-07 step-up, P-AUTH-08 device-bound, P-OPS-07 meldkanaal) en `CLAUDE.md:53` geherformuleerd (besluit 1)~~ ✅ 2026-10-10
- [x] ~~**ROADMAP herschikt** — Koblitz, Miller, Montgomery, Lange; Schneier e.v. doorgeschoven (besluit 2)~~ ✅ 2026-10-10
- [x] ~~**Documentenset bijgewerkt** — README, API, DATA_MODEL, THREAT_MODEL, SECURITY, DPIA (herbeoordeling §9), ARCHITECTURE, SEQUENCE_DIAGRAMS (SQ-9..12), COMPONENT_DIAGRAM, CHANGELOG, BUGS, version.json (0.2.0-Koblitz, schema 5)~~ ✅ 2026-10-10
- [x] ~~**Vertrouwensanker gevendord** — `backend/data/yubico_fido_roots.pem` + `aaguids.json` met bouwscripts in `backend/tools/`~~ ✅ 2026-10-10
- [x] ~~**Versie-bump** — `config.py` `app_version` = `0.2.0-Koblitz`; `version.json` 0.2.0 Koblitz~~ ✅ 2026-10-10

**Open (Koblitz)**
- [ ] **Deploy v0.2.1** — alleen nodig om `devserver.py`/`README.md` uit de webroot te halen en de versie te tonen; volgens het runbook met backup (akkoord Christian)
- [ ] **CI v0.2.1 groen op GitHub** controleren na de push
- [x] ~~**e2e-specs admin/mfa/smoke omzetten naar `tests/e2e-stack.ts`** — ze wijzen nu naar :3997 = LIVE productie (10/11-10 alleen OPTIONS/429, geen schrijfverzoeken aangekomen)~~ ✅ 2026-10-11 (v0.2.1)
- [x] ~~**`scripts/deploy_hc55.sh` rsync-excludes** (`tests/`, `package*.json`, `node_modules/`, `devserver.py`, `README.md`) + script-header/.env-sjabloon bijwerken; DEPLOYMENT.md is verouderd~~ ✅ 2026-10-11 (v0.2.1)
- [x] ~~**Bouw afronden volgens §12** — backend (migratie 005 herschreven, py_webauthn, step-up, rekey, recovery block/unblock, mailer) en frontend (`hwkeys.js`, `hwkeys-ui.js`, `stepup.js`, ontgrendelscherm, rekey-flow); per onderdeel tegen §12.14 afvinken~~ ✅ 2026-10-11 (commit 68e4695, 3 adversariële reviewrondes, 16 bevindingen gefixt)
- [x] ~~**Testvectoren Seal_v2** — `specs/testvectors/seal_v2.json` + `gen_seal_v2.py`~~ ✅ 2026-10-10 (reviewronde 2; pytest + `node --test` zonder skips)
- [x] ~~**LIVE v0.1.0-Massey kwetsbaar voor HS-BUG-008 punt 1 en 5**~~ ✅ 2026-10-11 vervallen: Koblitz (met fix) is live
- [x] ~~**Tests meten en in `version.json` zetten**~~ ✅ 2026-10-11 — pytest 196/196, `node --test` 59/59, Playwright 10/10; kdbx-oracle-CI nog te meten
- [ ] **CI-jobs** — `node --test` en Playwright-WebAuthn in `.github/workflows/ci.yml`: wijziging klaar (lokaal, niet gecommit), push vereist `gh auth refresh -s workflow` door Christian
- [ ] **HS-BUG-007 sluiten** zodra de tests in §12.14 groen zijn
- [x] ~~**SMTP-gegevens in `/opt/horsesafe/.env`** — `HORSESAFE_SMTP_HOST/PORT/USER/PASSWORD/FROM` uit ClaudeSecrets (Christian); daarna aantoonbaar mail afgeleverd vanaf HC55 via 587/STARTTLS (acceptatie 5)~~ ✅ 2026-10-11 — Hostinger 587, 250 + afgeleverd in inbox
- [x] ~~**Deploy HC55** — rsync met `--exclude tests/ --exclude 'package*.json' --exclude node_modules/`, migratie 005, restart; live `/api/health` = `0.2.0-Koblitz` met `test_attestation:false` (acceptatie 6)~~ ✅ 2026-10-11 00:32 UTC — DB/vaults/.env-backup in `/opt/horsesafe/backups-predeploy/`, schema 5, post_deploy_smoke groen
- [ ] **YubiKeys inrichten** — sinds 12-10 met de HorseSafe-app (v0.3.0-Miller deel 1, `android/README.md`): eerst de testsleutel, dan Bio (PIN 63, minimum 63, alwaysUv, 2-3 vingers) en noodsleutel (PIN 63 alleen op papier, apart)
- [ ] **Veldtest** — Bio in Chrome op de laptop koppelen en ontgrendelen; Windows Hello-passkey wordt geweigerd (acceptatie 7)
- [x] ~~**GDPR_COMPLIANCE.md / PRIVACY_STATEMENT.md** — SMTP-provider als (sub)verwerker en sleutelmetadata opnemen (volgt uit DPIA §9; buiten de Koblitz-docsscope van 10-10)~~ ✅ 2026-10-11 (v0.2.1)
- [x] ~~**UI_DESIGN.md + docs/screens/** — ontgrendelscherm YubiKey/Keyfile, sleutelbeheer, step-up-dialoog documenteren~~ ✅ 2026-10-11 (v0.2.1)

## 📋 Gepland — v0.3.x-Miller deel 2 en verder — NIET in deze fase

- [x] ~~`android/` in deze repo met README~~ ✅ 12-10 (deel 1)
- [x] ~~YubiKey inrichten vanuit de app~~ ✅ 12-10 (deel 1; hardwaretest open)
- [ ] Telefoon koppelen (QR + SAS), `kind='phone'` met Keystore `BIOMETRIC_STRONG`, nooit `DEVICE_CREDENTIAL`
- [ ] Migratie 006 (`pairings`, `device_nonces`), device-API (`/devices…`, `/device/v1/*`), `/app/latest` + `/app/download`
- [ ] Noodsleutel blokkeren/deblokkeren vanaf de telefoon (`sig_biosig`, telefoonvinger als tweede step-up-methode)
- [ ] Meldingen via polling, geen FCM (besluit 6)
- [ ] Test-emulator `hb-horsesafe` (besluit 5); CI-job `android`; publicatie via `/APKDeploy`
- [ ] DPIA herbeoordelen (apparaatgegevens, attestation-ketens)

## 📋 Gepland — v0.4.0-Montgomery (laptop ontgrendelen via telefoon-QR + vinger) — NIET in deze fase

- [ ] Goedkeuringsprotocol (`/vault/{vid}/approvals…`, `/device/v1/approvals/{id}`), Seal_v2 purpose `relay` — `docs/HARDWARE_KEYS.md` §5
- [ ] Migratie 007 (`approvals`, `revoked_sessions`), JWT-claim `sid`
- [ ] Ontgrendelen in de app via WebView + WebMessageListener
- [ ] Veldtest Fold6 + laptop-Chrome → go/no-go voor v0.5.0-Lange (native kluis; niet bouwen vóór die veldtest, besluit 7)

## 🆕 2026-07-21 — v0.1.0-Massey public-go afgerond

- [x] ~~**git-history-scrub** — mirror-clone + git-filter-repo v2.47.0 (single-file script, brew geblokkeerd op Xcode-licentie); 4 replace-rules (3 wachtwoorden — incl. derde vondst live mail-login — + kaal prefix-patroon); verificatie 0 hits over 31 revisies; force-push `de53295`→`073656f`; lokale clone + HC55 `/opt/horsesafe/repo` ge-reset op nieuwe history~~ ✅ 2026-07-21
- [x] ~~**Repo PUBLIC + AGPL-3.0** — LICENSE toegevoegd; `gh repo edit --visibility public`; GitHub detecteert "GNU Affero General Public License v3.0"~~ ✅ 2026-07-21
- [x] ~~**Sitemap** — icthorse.nl had géén sitemap; nieuwe minimale `sitemap.xml` (/, /HorseSafe/) + `Sitemap:`-regel in robots.txt; live geverifieerd~~ ✅ 2026-07-21
- [ ] **LinkedIn-post** — draft staat klaar in LAUNCH_PREP.md §4; publiceren doet Christian zelf na review

## 🆕 2026-07-20 — v0.1.0-Massey (public launch, deels)

- [x] ~~**icthorse.nl/HorseSafe/ LIVE** — Hostinger subdir-.htaccess 302 → HC55, beide casings, e2e geverifieerd~~ ✅
- [x] ~~**Pen-test-checklist v0.1.0** — 8 punten tegen LIVE; 1 fix (OpenAPI-docs dicht in productie via `docs_enabled=false`), rest groen; SECURITY.md-tabel~~ ✅
- [x] ~~**Versie-bump** 0.0.10-Goldwasser → 0.1.0-Massey (config.py + version.json)~~ ✅
- [x] ~~**Backend pytest** 68/68 groen (incl. nieuwe docs-off test)~~ ✅
- [x] ~~**Deploy HC55** — git pull + docs-env + restart; health toont 0.1.0-Massey; /api/docs → 404~~ ✅
- [x] ~~**Privacy-statement finaal** (0.1.0) + LAUNCH_PREP.md (LinkedIn-draft + sitemap-entry)~~ ✅
- [x] ~~🚧 **BLOKKEREND: git-history-scrub** — plaintext-wachtwoorden (`[REDACTED-PREFIX]*`) in history; scrub-procedure in LAUNCH_PREP.md §1. Public-go pas hierna.~~ ✅ 2026-07-21
- [x] ~~**Repo PUBLIC + AGPL-3.0** — na scrub (LAUNCH_PREP.md §2)~~ ✅ 2026-07-21
- [x] ~~**Sitemap** — na public (LAUNCH_PREP.md §3)~~ ✅ 2026-07-21 (LinkedIn-draft blijft open, zie boven)
- [ ] **Backup Storagebox** — GEBLOKKEERD op Storagebox SSH-credentials (LAUNCH_PREP.md §5)
- [ ] **Magic-link mail** — ~~GEBLOKKEERD op Gmail App Password~~ vervangen door de generieke SMTP-mailer (v0.2.0-Koblitz, besluit 4); open tot de SMTP-gegevens in `.env` staan (zie Koblitz-sectie)
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
- [ ] **Browser-extensie** (Schneier, doorgeschoven na Koblitz-Lange) — MV3, autocomplete, échte clipboard-wipe (uitgesteld, optioneel)
- [x] ~~**Fase 7 — Productie-deploy HC55**~~ ✅ 2026-05-22 — LIVE op https://icthorsecloud.nl/HorseSafe/ ; systemd + nginx-snippet + backup-cron actief; auth_basic off voor /HorseSafe/-paths (eigen JWT+MFA); live-smoke-test groen (health + register + login + vault + me + logout)
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
- [ ] **FIDO2/WebAuthn als account-MFA** (Rogaway) — vault-laag is gedekt door v0.2.0-Koblitz
- [ ] **Mobile-app** — Android staat nu op de roadmap als v0.3.0-Miller; iOS blijft research
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
