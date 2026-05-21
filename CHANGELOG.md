# CHANGELOG — HorseSafe

Alle wijzigingen worden hier gedocumenteerd. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
- Fase 4: admin-pagina + user-CRUD + audit-viewer + MFA-backup-codes

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
