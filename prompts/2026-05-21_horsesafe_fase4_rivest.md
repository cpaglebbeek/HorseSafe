---
date: 2026-05-21
session: horsesafe_fase4_rivest
status: open
resume: "verder met HorseSafe Fase 5 — import/export KDBX/Bitwarden/CSV/XLSX + KeePassXC-CLI roundtrip-oracle-test + Argon2id-re-enable evaluatie (v0.0.5-Shamir)"
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: [HS-FASE-5-IMPORT-EXPORT]
---

# Sessie 2026-05-21 — HorseSafe Fase 4 v0.0.4-Rivest: Admin-paneel LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 4 ("1, alles akkoord") na presentatie van 6 blokken + 17 punten + impact.

## Wat is gebouwd

**Backend (40/40 pytest ✅, +15 tests):**
| Component | Files |
|---|---|
| Services | `admin_service.py` (user-list/delete/stats/audit) + `backup_codes_service.py` (bcrypt-hashed, look-alike-free alphabet, single-use) |
| Routes | NIEUW `routes/admin.py` met 6 endpoints + uitbreiding `routes/auth.py` met `/auth/me` + `/auth/backup-codes/{generate,verify}` |
| Models | `models/admin.py` (AdminDeleteRequest, AdminRescueRequest, BackupCodeVerify, MeResponse) + `models/audit.py` uitbreiding (4 nieuwe events) |
| DB | `db/migrate.py` (versie-gestuurde runner) + `migrations/002_backup_codes.sql` + `migrations/003_audit_log_no_check.sql` + `db/promote_admin.py` (CLI) |
| Tests | `test_admin.py` (7) + `test_backup_codes.py` (5) + `test_auth_me.py` (2) |

**Frontend (5/5 e2e ✅, +2 tests):**
| Component | Files |
|---|---|
| HTML | `admin.html` (S11 stats + users-tabel + audit-viewer) + `backup-codes.html` (S13 show-once) |
| JS | `admin.js` (fetch-helpers + action-handlers + audit-paginated) + `backup-codes.js` (show-once + ack + copy) |
| Updates | `settings.html` (admin-link + backup-codes-link) + `settings.js` (/auth/me ipv probe-hack) + `mfa.html` (3e tab "Backup-code") + `mfa.js` (backup-form-submit) |
| E2E | `tests/admin.spec.ts` — admin-redirect-niet-admin + /auth/me-probe |

**Docs:**
- `docs/screens/S11_admin.md` + `S13_backup_codes.md`
- `RUNBOOK.md` admin-procedures sectie (eerste-admin, MFA-rescue, lock-out-rescue, user-delete)
- `CHANGELOG.md` [0.0.4-Rivest] sectie compleet
- `version.json` + `backend/config.py` `app_version` → 0.0.4-Rivest

## Verificatie

| Test | Resultaat |
|---|---|
| Backend pytest | **40/40 ✅** (van 25, +15) |
| Ruff lint | ✅ |
| Black format | ✅ |
| Frontend e2e playwright | **5/5 ✅** in 9.7s (van 3, +2) |

## Belangrijkste beslissingen

| Punt | Keuze | Reden |
|---|---|---|
| Backup-code alphabet | `ABCDEFGHJKMNPQRSTUVWXYZ23456789` (geen 0/O, 1/I/L) | User-leesbaarheid + minder fouten bij invoer |
| Hash | bcrypt direct (geen passlib) | passlib 1.7.4 incompatibel met bcrypt 5.x (`__about__` weg) |
| BCRYPT_ROUNDS | env-var, default 12, tests=4 | Productie sterk, tests snel |
| Audit-log CHECK constraint | Verwijderd in migratie 003 | Te rigide; Pydantic-enum AuditEvent validates |
| First-admin bootstrap | CLI script `python -m backend.db.promote_admin <email>` | Geen env-var-bootstrap (te makkelijk te missen) |
| Reden-verplicht | min 10 chars op alle destructive admin-acties | Accountability + audit-trail |
| Self-delete blokkering | HTTP 400 `self_delete_forbidden` | Voorkomt zelf-lockout |
| Magic-link target | USER's geregistreerde e-mail | Voorkomt mailbox-takeover door admin |
| /auth/me | NEW endpoint vervangt /vault-probe-hack | Cleaner UI; één bron-van-waarheid voor frontend |
| pw-reset | NIET geïmplementeerd | Zou zero-knowledge breken (server kent vault-master niet) |

## Wat NIET gebouwd (per WhatIf-scope)

- CSV-export audit-log → v0.0.5-Shamir
- Wachtwoord-reset flow → v0.0.5+
- Import/export vault-data → v0.0.5-Shamir
- Argon2id-default-re-enable → v0.0.5+
- WebAuthn/FIDO2 → v0.5.0-Rogaway

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe Fase 5 — import/export + KeePassXC-CLI roundtrip-oracle (v0.0.5-Shamir)`

**Scope Fase 5:**
1. Import: KDBX3/KDBX4 + Bitwarden JSON + KeePass-CSV + XLSX
2. Export: KDBX4 (encrypted) + CSV/JSON/XLSX (plaintext met audit + reden)
3. KeePassXC-CLI als oracle in CI (write via kdbxweb → read via keepassxc-cli → entries-count match)
4. Argon2id-default-re-enable evaluatie (cross-browser test met devserver.py + COOP/COEP)
5. CSV-export audit-log (admin)
6. Account-pw-reset flow (alleen account-laag, niet vault)
7. Versie-bump → v0.0.5-Shamir

## Acties vastgelegd

- `HorseSafe/ACTIONS.md` — Fase 4 afgevinkt, Fase 5 omhoog
- `HorseSafe/CHANGELOG.md` — [0.0.4-Rivest] sectie
- `HorseSafe/version.json` + `backend/config.py` — v0.0.4-Rivest
- `HorseSafe/docs/screens/` — S11 + S13 toegevoegd
- `HorseSafe/RUNBOOK.md` — admin-procedures
- Meta_Master `STATUS.md` + `RESUME.md` regenereren — volgt in commit-stap
- `claude_memory/project_horsesafe.md` + `MEMORY.md` — bijwerken
