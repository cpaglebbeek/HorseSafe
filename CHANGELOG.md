# CHANGELOG — HorseSafe

Alle wijzigingen worden hier gedocumenteerd. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]
- Fase 2: frontend kdbxweb POC

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
