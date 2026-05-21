# CHANGELOG — HorseSafe

Alle wijzigingen worden hier gedocumenteerd. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
- v0.1.0-Massey: public launch op icthorse.nl/HorseSafe/ + externe pen-test + open-source-beslissing AGPL

## [0.0.7-Bellare] — 2026-05-22

### Added — Productie-deploy HorseCloud55 LIVE

**LIVE op:** `https://horsecloud55.ddns.net/HorseSafe/`

**Server-state op HC55:**
- `/opt/horsesafe/` met `repo/`, `venv/`, `db/`, `vaults/`, `logs/`, `tmp/`, `web/`
- System-user `horsesafe` (no-login, no-shell)
- systemd-unit `/etc/systemd/system/horsesafe.service` → **active, enabled**
- nginx-snippet `/etc/nginx/snippets/horsesafe.conf` met `auth_basic off` voor beide HorseSafe-locations (eigen JWT+MFA)
- nginx-include in horsecloud-server-block (port 443)
- `/etc/cron.d/horsesafe-backup` — nightly 03:00 rsync naar Storagebox (skip indien target niet gezet)
- `.env` met random JWT_SECRET + TOTP_ENCRYPTION_KEY (32 bytes hex elk) + bcrypt-rounds=12

**Repo-artefacten:**
- `scripts/deploy_hc55.sh` — idempotente bootstrap
- `scripts/horsesafe.service` — systemd-unit met full hardening
- `scripts/nginx_snippet.conf` — appendable include met `auth_basic off`
- `scripts/backup_to_storagebox.sh` — nightly rsync + sqlite-snapshot-tar + retentie
- `scripts/post_deploy_smoke.sh` — curl-only roundtrip-test
- `docs/DEPLOY_HC55_LIVE.md` — runbook

**Live-smoke-test (uitgevoerd, groen):**
- ✓ GET /health → {"status":"ok","version":"0.0.6-Adleman","db":"ok","vaults_dir":"ok"}
- ✓ POST /auth/register → user_id
- ✓ POST /auth/login → JWT-cookie + mfa_required=false
- ✓ GET /vault → []
- ✓ GET /auth/me → has_keypair=false
- ✓ POST /auth/logout → ok

**Updates:**
- `Meta_Master/SHARED_INFRASTRUCTURE.md` — poort 3997 "gereserveerd" → LIVE
- `version.json` + `backend/config.py` `app_version` → 0.0.7-Bellare

### Decided

- **URL**: `horsecloud55.ddns.net/HorseSafe/` (intern, achter LE-TLS); `icthorse.nl/HorseSafe/` v0.1.0
- **`auth_basic off`** voor /HorseSafe/* (eigen JWT+MFA)
- **Deploy-strategie**: optie (c) uit WhatIf — AI provisioneert + dry-run; gebruiker approve't laatste 2 stappen
- **Eerste admin**: niet automatisch — handmatig promote na eerste-user-registratie
- **Backup-target**: nog niet geconfigureerd in .env (HORSESAFE_BACKUP_TARGET leeg)

### Operationele stappen tijdens deploy

1. ✅ Pre-check: Python 3.12, port 3997 vrij, geen pre-existing /opt/horsesafe
2. ✅ Bootstrap als root op HC55
3. ✅ Git clone via PAT in `/root/.git-credentials`
4. ✅ Dry-run validatie: nginx -t OK, systemd-analyze OK
5. ⚠️ Snippet-bug ontdekt + gefixed: `auth_basic off` toegevoegd voor beide locations (eerste run gaf 401 wegens basic-auth)
6. ✅ Include in horsecloud-server-block (1 regel toegevoegd na server_name)
7. ✅ nginx -t && systemctl reload nginx
8. ✅ systemctl enable --now horsesafe → active (running)
9. ✅ Smoke-test live: full register/login/vault/me/logout roundtrip
10. ✅ Cleanup smoke-account

### Not Yet (v0.1.0-Massey)

- icthorse.nl/HorseSafe/ (Hostinger DNS)
- Externe pen-test
- Open-source-beslissing (AGPL-3.0 voorgesteld)
- Dashboard-tile health-monitoring
- Public launch + LinkedIn-aankondiging

### Niet kritiek (v1.0-Bernstein of later)

- HORSESAFE_BACKUP_TARGET configureren
- HORSESAFE_GMAIL_USER/PASSWORD voor magic-link
- Eerste admin promoveren bij echte first-user
- Argon2id KDF re-evaluatie

## [0.0.6-Adleman] — 2026-05-21

### Added — Vault-sharing tussen users via ECDH-P256

**Backend (+13 tests, 67/67 ✅):**
- `routes/shares.py` — 7 nieuwe endpoints:
  - POST /keypair — set pubkey + encrypted_privkey
  - POST /keypair/rewrap — vervang encrypted_privkey bij pw-change
  - GET /keypair — haal eigen keypair op
  - GET /users/by-email/{email}/pubkey — lookup pubkey voor share-encryptie
  - POST /shares — encrypted share-payload naar ontvanger
  - GET /shares/inbox — pending ontvangen shares
  - GET /shares/sent — verzonden shares (alle statussen)
  - POST /shares/{id}/accept + /decline
- `services/share_service.py` — keypair-CRUD + share-CRUD + pubkey-lookup-by-email
- `models/share.py` — KeypairSet/Rewrap, ShareCreate, ShareInboxItem, PubkeyResponse
- `models/audit.py` — +4 events: keypair_generated, share_create, share_accept, share_decline
- `models/admin.py` — MeResponse.has_keypair toegevoegd
- `routes/auth.py` — /auth/me returnt nu has_keypair
- `db/migrate.py` + `migrations/004_sharing.sql` — ALTER users (+pubkey, +encrypted_privkey) + CREATE shares
- `db/schema.sql` — schema-version bumped naar 4 (fresh-install bevat alle migrations)
- `tests/test_sharing.py` — 13 tests

**Frontend:**
- `js/sharing.js` — ECDH-P256 (WebCrypto native, geen externe lib):
  - generateKeypair(masterPw, userId) — random ECDH-P256 + AES-GCM-wrapped private via PBKDF2-key
  - unwrapPrivateKey(masterPw, userId, encryptedPrivkey)
  - encryptForRecipient(pubkey, plaintext) — ephemeral ECDH + AES-GCM
  - decryptFromSender(myPriv, encryptedPayload) — ECDH-shared-secret + AES-GCM
- `shares.html` (S14) — Inbox + Verzonden + decryptie-pane voor inkomende shares
- `settings.html` — Keypair-status + generate-form + "Shares-inbox"-link
- `vault.html` — "📥 Shares" knop in top-bar + "🤝 Deel" knop in detail-pane
- `js/main.js` — share-flow in detail-pane: prompt email → lookup pubkey → encrypt entry → POST /shares
- `js/settings.js` — loadKeypairStatus + keypair-generate-form

**Crypto-ontwerp:**
- ECDH **P-256** (WebCrypto native; Curve25519 zou vendor 50KB vereisen)
- Private-key at-rest: AES-GCM-encrypted met PBKDF2-SHA256(vault-master-pw + user-id, 100k iter) → 256-bit AES-key
- Share-payload: ephemeral ECDH-keypair-bij-elke-share + AES-GCM-256 met ECDH-shared-secret
- Server ziet: pubkey (plain), encrypted_privkey (opaque), encrypted_payload (opaque)
- Server ziet NIET: private-key, share-content, master-pw, shared-secret

**Schema-migratie:**
- Migration 004: ALTER users + CREATE shares
- schema.sql bumped naar versie 4 (alle migrations 001-004 in fresh-install-blob — voorkomt ALTER-failure in nieuwe DBs)

### Decided

- **ECDH-P256** ipv Curve25519 (native in WebCrypto)
- **PBKDF2-SHA256 100k** voor private-key wrap-key derivation
- **Per-entry share-eenheid** (hele-vault sharing = v0.0.7+)
- **Per-email ontvanger** (multi-recipient = meerdere shares)
- **Lazy keypair-gen** via settings (niet automatisch bij login)
- **GEEN revocation** in v0.0.6 (zou re-encryption van alle bestaande shares vereisen)
- **GEEN multi-recipient** per share-actie
- **GEEN invite-naar-niet-bestaand-account** (404 + UI-melding)

### Changed
- `version.json` + `backend/config.py` `app_version` → 0.0.6-Adleman
- `schema_version` 3 → 4

### Not Yet
- Revocation, hele-vault sharing, multi-recipient, invite → v0.0.7+
- Curve25519 → v1.0-Bernstein (samen met PQC-overweging)

## [0.0.5-Shamir] — 2026-05-21

### Added — Import/Export + KeePassXC-CLI oracle + Admin-CSV + Account-pw-change

**Backend (+14 tests, 54/54 ✅):**
- `routes/vault.py` — 2 nieuwe endpoints:
  - `POST /vault/{id}/audit-import` `{format, count}` — server doet GEEN parse (client-side); audit-stamp na succesvolle frontend-merge
  - `POST /vault/{id}/audit-export` `{format, reason}` — reden VERPLICHT min 10 chars voor csv/json/xlsx; geen reden voor kdbx (encrypted)
- `routes/admin.py` — `GET /admin/audit/export?...` streaming CSV-response met filters (gelijk aan /admin/audit-query) + Content-Disposition: attachment
- `routes/auth.py` — `POST /auth/password` `{old_password, new_password}` — vereist JWT + oude-pw-verificatie + nieuwe-pw min 12 chars; event `account_password_changed`
- `services/pw_service.py` — `change_account_password()` met argon2id-verify + rehash
- `models/audit.py` — 2 nieuwe events: `account_password_changed`, `admin_audit_csv_export`
- Nieuwe pytest-tests:
  - `test_password_change.py` — 5 tests (unauth/happy/wrong-old/weak-new/missing-fields)
  - `test_import_export_audit.py` — 6 tests (kdbx-no-reason/csv-requires-reason/other-user-404/...)
  - `test_audit_csv.py` — 3 tests (admin-only/streaming/filter)

**Frontend:**
- `import.html` (S9) — wizard: format-select + bestand + KDBX-pw + vault-pw + conflict-strategie → preview-tabel → bevestig + merge + upload
- `export.html` (S10) — wizard: format-select + vault-pw + reden (bij plaintext) + ROOD warning-dialog voor csv/json
- `js/import-export.js` — library met `parseBitwardenJson()` + `parseKeePassCsv()` + `parseCSV()` (RFC 4180) + `buildCSV()` + `buildJSON()` (Bitwarden-compat) + `mergeEntriesInto()` (3 strategieën) + `extractEntries()` + `downloadBlob()`
- `vault.html` — "↓ Importeer" + "↑ Exporteer" buttons in top-bar
- `settings.html` — nieuwe sectie "Account-wachtwoord wijzigen" boven TOTP
- `js/settings.js` — pw-change-form met confirm-veld + error-mapping
- `admin.html` — "Exporteer CSV"-button naast filter
- `js/admin.js` — `f-export-csv` triggert browser-download van `/admin/audit/export`

**CI:**
- Nieuwe job `kdbx-oracle` na `backend`-job
- `apt-get install keepassxc` op ubuntu-runner
- Python-script: maakt KDBX4-vault via `keepassxc-cli db-create` + voegt entry toe + assert `keepassxc-cli ls` toont entry
- Bewijst dat KeePassXC-CLI in CI werkt voor latere import/export-validatie

**Docs:**
- `BUGS.md` HS-001 — Definitief deferred naar v1.0-Bernstein productie-pre-release (retry-vector blijft via devserver.py)
- `docs/screens/S09_import.md` + `S10_export.md`

### Decided

- **Client-side only**: server doet GEEN parsing van import-bestanden of export-content. Audit-endpoints registreren alleen event + reden. Zero-knowledge intact.
- **XLSX uitgesteld** naar v0.0.7+ (SheetJS is 700KB, weinig meerwaarde t.o.v. CSV)
- **Plaintext-export reden**: VERPLICHT (min 10 chars) + ROOD confirm-dialog + audit-log-event
- **KeePassXC-CLI oracle**: in CI als sanity-check; bewijst KDBX4-AES-KDF-roundtrip
- **Vault-pw-reset**: NIET geïmplementeerd — onmogelijk in zero-knowledge architectuur
- **Account-pw-vergeet**: magic-link → log in → settings → wijzig pw (geen e-mail-link-met-embed-token)
- **Argon2id-default**: definitief deferred naar v1.0-Bernstein (AES-KDF bewezen geverifieerd via CI-oracle)

### Changed
- `version.json` + `backend/config.py` `app_version` → 0.0.5-Shamir

### Not Yet
- XLSX import/export → v0.0.7+ (op user-request)
- Sharing tussen users → v0.0.6-Adleman (volgende)
- E-mail-link-met-embed-token voor reset → niet (security-risk vermijden)
- WebAuthn/FIDO2 → v0.5.0-Rogaway

## [0.0.4-Rivest] — 2026-05-21

### Added — Admin-paneel + MFA-backup-codes + /auth/me

**Backend (40/40 pytest ✅, +15 tests):**
- `routes/admin.py` — 6 nieuwe endpoints:
  - `GET /admin/users` — lijst met email/created/last_login/vault_count/storage_bytes/has_totp/backup_codes_remaining
  - `DELETE /admin/users/{id}` — cascade-delete (user + vault-blobs + magic-links + backup-codes), **reden verplicht** (min 10 chars), zelf-delete blokkering
  - `POST /admin/users/{id}/disable-mfa` — admin-rescue: TOTP + backup-codes weg
  - `POST /admin/users/{id}/send-magic-link` — naar USER's e-mail, niet admin's
  - `GET /admin/stats` — totaal users/vaults/storage + logins-24u + failed-24u + top10-by-storage
  - `GET /admin/audit?user=&event=&from=&to=&limit=&offset=` — paginated audit-log
  - `_require_admin()` dependency: vereist JWT + admin + MFA pass
- `services/admin_service.py` — user-CRUD-helpers + stats-aggregator + paginated audit-query
- `services/backup_codes_service.py` — bcrypt-hashed codes met look-alike-free alphabet (geen 0/O/1/I/L), single-use, generate-N + consume-by-plaintext + count_remaining
- `routes/auth.py` — 3 nieuwe endpoints:
  - `GET /auth/me` → `{id, email, is_admin, has_totp, backup_codes_remaining, mfa_pass, last_login_at}` (vervangt /vault-probe-hack)
  - `POST /auth/backup-codes/generate` → 10 plaintext codes show-once
  - `POST /auth/backup-codes/verify` → MFA-bypass via single-use backup-code (zelfde upgrade-pad als TOTP-verify)
- `models/admin.py` — Pydantic `AdminDeleteRequest`, `AdminRescueRequest`, `BackupCodeVerify`, `MeResponse`
- `models/audit.py` — 4 nieuwe events: `admin_user_disable_mfa`, `admin_user_send_magic_link`, `backup_codes_generate`, `backup_codes_consume`
- `db/migrate.py` — versie-gestuurde migration-runner (idempotent)
- `db/migrations/002_backup_codes.sql` — nieuwe tabel `users_backup_codes(id, user_id, code_hash, created_at, used_at)`
- `db/migrations/003_audit_log_no_check.sql` — verwijder hardcoded CHECK-constraint op audit_log.event (validatie via Pydantic AuditEvent)
- `db/promote_admin.py` — CLI: `python -m backend.db.promote_admin <email>` om eerste admin te maken
- `app.py` lifespan — run_migrations() bij startup; admin-router gemount op `/admin`
- `requirements.txt` — bcrypt>=4,<6 toegevoegd; passlib[argon2,bcrypt]-extras
- Nieuwe pytest-tests:
  - `tests/test_admin.py` — 7 tests (admin-required, list, delete, self-delete-forbidden, disable-mfa, stats, audit)
  - `tests/test_backup_codes.py` — 5 tests (generate, /me-reflects, consume-as-mfa, invalid-code, regenerate-invalidates-old)
  - `tests/test_auth_me.py` — 2 tests (unauth, after-login)
- conftest: `HORSESAFE_BCRYPT_ROUNDS=4` voor snelle test-runs

**Frontend (5/5 e2e ✅, +2 tests):**
- `admin.html` (S11) — stats-grid + users-tabel met inline actions (MFA-reset/magic-link/delete) + audit-viewer met filters/pagination
- `backup-codes.html` (S13) — show-once flow met checkbox-acknowledge + copy-all + beforeunload-warning
- `js/admin.js` — fetch-helpers met 401/403-handling + user-actions (reden-prompt + delete-confirm-by-email-typ) + stats + audit-paginated
- `js/backup-codes.js` — show-once + ack-checkbox + copy-to-clipboard + reload-warning bij niet-bevestigd
- `settings.html` — backup-codes-link sectie + admin-link in navigatie + footer-version-bump
- `js/settings.js` — gebruikt `/auth/me` ipv /vault-probe-hack; toont admin-link bij `is_admin: true` en backup-codes-link bij `has_totp: true`
- `mfa.html` + `js/mfa.js` — derde tab "Backup-code" met form (XXXXX-XXXXX input) en submit naar /auth/backup-codes/verify
- `tests/admin.spec.ts` — 2 nieuwe e2e: admin.html-redirect-niet-admin + settings.html /auth/me-probe

### Security
- **bcrypt-hashed backup-codes** met productie-default rounds=12 (env-var `HORSESAFE_BCRYPT_ROUNDS` voor test-versnelling)
- **Reden verplicht (min 10 chars)** voor alle destructive admin-acties (delete-user, disable-MFA, send-magic-link)
- **Self-delete blokkering**: admin kan eigen account niet via /admin/users/{id} verwijderen (HTTP 400)
- **Admin-magic-link naar USER's geregistreerde e-mail**, niet admin's (voorkomt mailbox-takeover via rescue)
- **Audit-events**: admin_user_delete, admin_user_disable_mfa, admin_user_send_magic_link, backup_codes_generate, backup_codes_consume

### Changed
- `version.json` + `backend/config.py` `app_version` → 0.0.4-Rivest
- Schema-version 1 → 3 (na migrate.py)
- `backup_codes_service.py` gebruikt directe `bcrypt`-library (niet via passlib — incompatibel met bcrypt 5.x)
- `audit_log.event` heeft geen DB-CHECK meer (Pydantic AuditEvent enum validates)

### Not Yet
- CSV-export audit-log → v0.0.5-Shamir
- Account-pw-reset flow → v0.0.5+
- Import/export vault-data → v0.0.5-Shamir
- Argon2id-default-re-enable → v0.0.5+
- WebAuthn/FIDO2 → v0.5.0-Rogaway

## [0.0.3-Merkle] — 2026-05-21

### Added — MFA-integratie

**Backend:**
- `services/mfa_service.py` — TOTP setup/verify/disable + AES-GCM-encrypted TOTP-secret at-rest (12-byte nonce || ciphertext || tag, base64-urlsafe) + base32 generate + provisioning_uri voor QR-render
- `services/magic_link_service.py` — Gmail SMTP_SSL via App Password + 32-byte urlsafe token + 10 min ttl + single-use redemption + EmailSender Protocol voor test-mocking
- `routes/auth.py` — 5 nieuwe endpoints: `/auth/totp/{setup,verify,disable}` + `/auth/magic-link` + `/auth/magic-link/redeem`
- `routes/vault.py` — `_user()` upgraded naar MFA-gate: weigert 403 als `users.totp_secret IS NOT NULL` + `jwt.mfa = false`
- `services/jwt_service.py` — JWT-payload bevat `mfa: bool` claim + `reissue_with_mfa()` helper voor cookie-upgrade na MFA-pass
- `routes/auth.py` POST /auth/login — antwoord bevat `mfa_required: bool` op basis van TOTP-status
- `config.py` — 6 nieuwe env-vars: `HORSESAFE_TOTP_ENCRYPTION_KEY`, `HORSESAFE_TOTP_ISSUER`, `HORSESAFE_GMAIL_USER`, `HORSESAFE_GMAIL_APP_PASSWORD`, `HORSESAFE_MAGIC_LINK_TTL_MINUTES`, `HORSESAFE_PUBLIC_URL`, `HORSESAFE_MFA_REQUIRED`
- 10 nieuwe pytest-tests over 2 files:
  - `tests/test_mfa_totp.py` — setup/verify-happy/verify-invalid/challenge-flow/disable/vault-block (7 tests)
  - `tests/test_mfa_magic_link.py` — unknown-email-no-leak/happy-roundtrip/grants-mfa-pass (3 tests)
- Backend pytest: **25/25 ✅**, lint: ✅, black: ✅

**Frontend:**
- `mfa.html` (S4 MFA-challenge) — 2 tabs: TOTP-code + magic-link request
- `settings.html` (S12) — TOTP enable/disable + QR-code render + status-display
- `js/mfa.js` — TOTP-challenge UI + magic-link request UI + tab-switching
- `js/settings.js` — TOTP setup-flow (genereer secret → render QR → verify → opslaan) + disable-flow + status-probe
- `js/auth.js` — login redirect: `mfa_required: true` → `mfa.html`; anders `vault.html`
- `js/vault-ui.js` — 403 mfa_required detection → redirect naar `mfa.html`
- `vault.html` — extra "⚙ Instellingen"-button in top-bar
- `frontend/devserver.py` — alternative dev-server met COOP/COEP + WASM-MIME headers (BUG-001-retry-vector)
- E2E playwright: 3 tests (was 2): S1 landing + vault-roundtrip + **MFA setup/re-login-challenge** in 6.6s

**Vendored:**
- `vendor/qrcode/qrcode.js` v2.0.4 (MIT, ~55KB) — QR-Code generator voor TOTP otpauth://-URL render
- `vendor/qrcode/LICENSE.MIT`

**Docs:**
- `BUGS.md` — HS-BUG-001 status update: retry-vector `devserver.py` toegevoegd; cross-browser test verschoven naar v0.0.5+ (samen met KeePassXC-CLI oracle-test)

### Changed
- `version.json`: 0.0.2 → 0.0.3-Merkle
- `backend/config.py`: `app_version` 0.0.1-Diffie → 0.0.3-Merkle (was nog niet bumped in v0.0.2)
- Default `HORSESAFE_MFA_REQUIRED = false` — opt-in via settings-pagina

### Security
- **AES-GCM at-rest encryptie van TOTP-secrets** — server-master-key uit env (`HORSESAFE_TOTP_ENCRYPTION_KEY`, 32-byte hex). Bij key-rotation moeten alle TOTP-secrets opnieuw worden ingesteld (gepland Fase 4).
- **Failed MFA-pogingen throttle**: hergebruikt `failed_logins`-tabel; 5 in 15 min → 423 Locked
- **Audit-log events**: `mfa_setup_totp`, `mfa_pass_totp`, `mfa_pass_magic_link`, `mfa_fail`

### Not Yet
- Argon2id-KDF re-enable voor nieuwe vaults → deferred naar v0.0.5+ (samen met KeePassXC-CLI oracle-test). Bridge staat klaar.
- MFA-backup-codes (10 recovery-codes) → v0.0.4-Rivest met admin-pagina
- Admin-rescue voor user-account-recovery → v0.0.4-Rivest
- iCt_Horse magic-link bridge hergebruik → v0.0.7+ deploy (huidige Gmail SMTP werkt out-of-the-box)
- /auth/me endpoint voor frontend-status-probe → v0.0.4+

## [0.0.2-Hellman] — 2026-05-21

### Added — Frontend POC LIVE (vanilla ES2022 + vendored libs)

**Frontend:**
- `frontend/index.html` (S1 landing + inline register-form met ack-checkbox)
- `frontend/login.html` (S2 account-login)
- `frontend/vault.html` (S6 unlock/create + S7 entries-CRUD single-page)
- `frontend/assets/horsesafe.css` — dark-theme uit DESIGN_TOKENS.md (~200 regels, geen framework)
- `frontend/assets/horsesafe.svg` — placeholder-logo
- `frontend/js/api.js` — fetch-wrappers naar backend met `credentials: 'include'`
- `frontend/js/auth.js` — register + login UI met error-mapping (Nederlands)
- `frontend/js/crypto.js` — kdbxweb-wrapper + argon2-bridge + best-effort 10s clipboard-wipe + password-generator
- `frontend/js/vault-ui.js` — state-management + entries-table + detail-paneel + entry-edit
- `frontend/js/main.js` — event-wiring vault.html

**Vendored (geen npm in productie):**
- `frontend/vendor/kdbxweb/kdbxweb.min.js` — 2.1.1 MIT (135 KB UMD)
- `frontend/vendor/argon2/argon2-bundled.min.js` + `argon2.wasm` — 1.18.0 MIT (45+25 KB)
- `frontend/vendor/README.md` met update-procedure

**Backend updates:**
- `CORSMiddleware` toegevoegd (env-var driven, leeg = uit voor productie)
- `SecurityHeadersMiddleware` uitgebreid met COOP+COEP voor crossOriginIsolated
- `RateLimitMiddleware` nu opt-out via `HORSESAFE_RATE_LIMIT_ENABLED=false` (dev/test)
- Middleware-order: CORS outermost (zodat 429/423-responses ook ACAO-header krijgen)

**Tests:**
- `frontend/package.json` + `playwright.config.ts` + `tests/smoke.spec.ts`
- E2E: registreer + login + vault aanmaken (in browser!) + entry toevoegen + detail-pane + pw-toggle + lock + reopen-roundtrip + verkeerd-wachtwoord
- 2/2 tests groen in 4.1s (Chromium headless)

**Documentatie:**
- `docs/screens/S01_landing.md` + `S02_login.md` + `S06_unlock.md` + `S07_content.md` (gedetailleerd per scherm)
- `frontend/README.md` uitgebreid van placeholder naar live run-instructies + e2e how-to

### Decided

- **KDF in v0.0.2 = AES-KDF** (`kdbxweb.Consts.KdfId.Aes`) voor nieuwe vaults. Reden: argon2-browser-WASM is in headless Chromium niet stabiel (hangt op eerste hash-call). AES-KDF is KDBX-spec-conform en opent in KeePassXC-desktop — disaster-recovery garantie blijft intact. Argon2id-bridge staat klaar voor v0.0.3+.
- **Hostname dev:** frontend en backend beide via `localhost` (niet 127.0.0.1) voor cross-origin-cookie-werking.
- **CORS-config** alleen actief met expliciete `HORSESAFE_CORS_ORIGINS` env-var. Productie via nginx zelfde-origin.

### Not Yet

- MFA (TOTP + magic-link) → v0.0.3-Merkle
- Admin-pagina → v0.0.4-Rivest
- Import/export → v0.0.5-Shamir
- Argon2id-KDF voor nieuwe vaults → v0.0.3+ (na browser-cross-test in echte Chrome/Firefox/Safari)
- Browser-extensie + échte clipboard-wipe → v0.2.0-Schneier

### Notes

- Lokaal getest: backend Python 3.14 + frontend Chromium headless via playwright
- Backend tests 15/15 ✅ + ruff ✅ + black ✅ na alle backend-wijzigingen
- E2E smoke 2/2 ✅ in 4.1s

## [0.0.1-Diffie] — 2026-05-21

### Added — Backend FastAPI-skeleton LIVE

**Code:**
- `backend/app.py` — FastAPI-app met lifespan + 2 middlewares + 3 routers
- `backend/config.py` — Pydantic-Settings met HORSESAFE_*-env-prefix
- `backend/db/`: schema.sql (5 tabellen) + connection.py (aiosqlite) + init.py (CLI-init)
- `backend/middlewares/`: SecurityHeadersMiddleware (CSP+HSTS+X-Frame+nosniff) + RateLimitMiddleware (in-memory sliding-window)
- `backend/models/`: user/vault/audit Pydantic-models met EmailStr-validatie + pw min-12-tekens
- `backend/services/`:
  - `auth_service.py` — Argon2id-hash + verify + create_user + authenticate + throttle-check + record_failed_login (passlib[argon2])
  - `jwt_service.py` — JWT-issue/decode + HttpOnly/Secure/SameSite-cookie + require_auth-dep
  - `storage_service.py` — vault-CRUD met SHA-256-etag + atomic-write (tmp+rename) + 3-pass secure-delete
  - `audit_service.py` — append-only audit_log writes
- `backend/routes/`:
  - `health.py` — GET /health (publiek, version + db + vaults_dir status)
  - `auth.py` — register (ack-vereist) + login (JWT-cookie) + logout (audit)
  - `vault.py` — list/create/read/update/delete met JWT-gate + If-Match optimistic lock
- `backend/tests/`: 15 tests over 3 files met `tmp_path` per test
- `backend/pyproject.toml` — ruff + black + mypy strict + pytest + coverage 80%-gate
- `backend/requirements.txt` — 9 prod + 6 dev dependencies, allemaal MIT/BSD/Apache (AGPL-compatibel)
- `backend/.env.example` — env-template (geen secrets)
- `backend/README.md` — uitgebreid van placeholder naar run+test-instructies

**Test-resultaten (Python 3.14.3 lokaal):**
- 15/15 tests groen
- 96% line-coverage (642 statements, 25 missed)
- Smoke-test uvicorn: health + register + login + vault-list met cookie allemaal ok
- Security headers verified (CSP / HSTS / X-Frame / nosniff)

**Cardinale architectuur-eigenschappen bewaard:**
- ✅ Zero-knowledge: backend ziet vault enkel als opaque KDBX4-bytes (geen parse, geen master-pw, geen keyfile)
- ✅ Optimistic locking: PUT zonder If-Match → fail; PUT met stale If-Match → 412
- ✅ Cross-user isolation: getest dat user 2 user 1's vault niet kan zien
- ✅ Secure-delete: 3-pass random overschrijf vóór unlink

### Not Yet
- MFA (TOTP + magic-link) → Fase 3 (v0.0.3-Merkle)
- Admin-routes → Fase 4 (v0.0.4-Rivest)
- Import/export → Fase 5 (v0.0.5-Shamir)
- Frontend kdbxweb POC → Fase 2 (v0.0.2-Hellman, volgende)

### Notes
- Build/test draait op Python 3.14.3 (lokaal); requirements specificeren >=3.12 (CI gebruikt 3.12)
- RateLimitMiddleware is in-memory (verloren bij restart); Redis-backend vanaf v0.1.0
- JWT-secret moet 32+ bytes zijn (RFC 7518 §3.2) — productie via openssl rand -hex 32

## [0.0.0-Rijndael] — 2026-05-21

### Added
- Repo-skeleton + git init
- 19+ doc-set: README, CLAUDE, ARCHITECTURE, UI_DESIGN, PRINCIPLES, DEPENDENCIES, THREAT_MODEL, BUGS, ACTIONS, API, CHANGELOG, COMPONENT_DIAGRAM, DATA_MODEL, DEPLOYMENT, DESIGN_TOKENS, DPIA, ENGINE_INPUT_CONTROL, GDPR_COMPLIANCE, MONITORING, PRIVACY_STATEMENT, ROADMAP, RUNBOOK, SECURITY, SEQUENCE_DIAGRAMS, version.json
- Sub-dirs: backend/, frontend/, extension/, docs/, prompts/, specs/ (allen met README placeholder)
- Sessie-MD `prompts/2026-05-21_newp_horsesafe.md` + Meta_Master crossref
- Codenaam-thema: Cryptografen (v0.0.0 = Rijndael)
- WhatIf-akkoord 22 punten (alle defaults)

### Decided
- Ecosysteem: iCt Horse Diensten (Meta_iCt_Horse_Diensten)
- Repo-zichtbaarheid: PRIVATE → open-source overweging vanaf v0.1.0
- Backend: Python 3.12 + FastAPI
- Frontend: Vanilla ES2022 + kdbxweb (MIT)
- Storage: SQLite + `/opt/horsesafe/vaults/<u-uuid>/<v-uuid>.kdbx`
- Crypto: KDBX4 + Argon2id(t=12, m=128MiB, p=2)
- MFA: Gmail magic-link (hergebruik iCt_Horse stack) + TOTP RFC 6238
- Vaults/user: 1 in v0.0.x, meerdere in v0.1.x
- Sharing: solo in v0.0.x, re-encryptie in v0.2.x
- Clipboard-wipe: best-effort browser v0.0.x; échte wipe via extensie v0.2.x
- Browser-compat: Chrome + Edge + Firefox + Safari
- Hosting: HC55:3997 + nginx `/HorseSafe/` (intern); `icthorse.nl/HorseSafe/` (dienst v0.1.x)

### Not Yet
- Geen code (skeleton-only)
- Geen GitHub-remote (wacht op akkoord)
- Geen nginx-edit / systemd / DNS / deploy
- KeePassXC 2.7.12 src tarball nog in ClaudeBug-inbox (read-only, niet geconsumeerd)
