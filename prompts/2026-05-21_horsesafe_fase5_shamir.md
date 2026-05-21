---
date: 2026-05-21
session: horsesafe_fase5_shamir
status: open
resume: "verder met HorseSafe Fase 6 — Vault-sharing tussen users met re-encryptie + asymmetrische key-pair per user (v0.0.6-Adleman)"
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: [HS-FASE-6-SHARING]
---

# Sessie 2026-05-21 — HorseSafe Fase 5 v0.0.5-Shamir: Import/export + KeePassXC-CLI oracle LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 5 ("1, alles akkoord") na 6 blokken / 16 punten.

## Wat is gebouwd

**Backend (+14 tests, 54/54 ✅):**
| Component | Files |
|---|---|
| Routes | `vault.py` 2 nieuwe endpoints (audit-import + audit-export met reden-validatie) + `admin.py` (`/admin/audit/export` streaming CSV) + `auth.py` (`POST /auth/password`) |
| Services | `pw_service.py` (account-pw-change met argon2id-verify + rehash) |
| Models | `audit.py` +2 events (`account_password_changed`, `admin_audit_csv_export`) |
| Tests | `test_password_change.py` (5) + `test_import_export_audit.py` (6) + `test_audit_csv.py` (3) |

**Frontend:**
| Component | Files |
|---|---|
| HTML | `import.html` (S9) + `export.html` (S10) |
| JS | `js/import-export.js` (library) + inline JS in S9/S10 |
| Updates | `vault.html` (Importeer/Exporteer buttons) + `settings.html` (pw-change sectie) + `js/settings.js` (pw-form) + `admin.html` (export-CSV button) + `js/admin.js` (download-trigger) |
| Docs | `docs/screens/S09_import.md` + `S10_export.md` |

**CI:**
- Nieuwe job `kdbx-oracle` na `backend`: install keepassxc + roundtrip-test (create KDBX → add entry → ls assert entry-found)

**Bug-resolutie:**
- HS-BUG-001 (argon2-headless-hang): **definitief deferred naar v1.0-Bernstein productie-pre-release**. AES-KDF werkt + KeePassXC-CLI oracle bewijst KDBX-roundtrip. Argon2id re-evaluatie samen met PQC-overweging in v1.0.

## Verificatie

| Test | Resultaat |
|---|---|
| Backend pytest | **54/54 ✅** (van 40, +14 Fase 5-tests) |
| Ruff lint | ✅ |
| Black format | ✅ |
| Frontend e2e | **5/5 ✅** in 9.8s (oude 5 blijven werken; import/export-flow zelf is interactief en niet automatisch in e2e — toegevoegd in Fase 6 als sharing-tests komen) |
| Uvicorn smoke | health → `0.0.5-Shamir` |

## Belangrijke beslissingen

| Punt | Keuze | Reden |
|---|---|---|
| Server-rol bij import/export | NIETS — audit-stamp only | Zero-knowledge intact |
| XLSX | Uitgesteld naar v0.0.7+ | SheetJS 700KB, weinig meerwaarde t.o.v. CSV |
| Plaintext-export reden | VERPLICHT min 10 chars + ROOD warning-dialog | Accountability + audit-trail |
| Vault-pw-reset | NIET geïmplementeerd | Zou zero-knowledge breken |
| Account-pw-vergeet | Via magic-link → settings | Geen e-mail-link-met-embed-token (security) |
| Argon2id-default | DEFINITIEF deferred v1.0 | AES-KDF + oracle-test voldoende voor disaster-recovery |
| KeePassXC-CLI oracle | apt install + Python-script in CI | Bewijst KDBX-roundtrip per build |

## Wat NIET gebouwd (per WhatIf-scope)

- XLSX import/export → v0.0.7+
- Sharing tussen users → v0.0.6-Adleman (volgende)
- E-mail-link-met-embed-token voor reset → niet (security)
- WebAuthn → v0.5.0-Rogaway

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe Fase 6 — Vault-sharing met re-encryptie (v0.0.6-Adleman)`

**Scope Fase 6:**
1. Asymmetrische key-pair per user (Curve25519 voor sharing) — public key opslaan, private in browser
2. Sharing-flow: vault-content re-encrypted met ontvanger's public key
3. /vault/{id}/share endpoint
4. UI in vault.html: "Deel met user X"
5. Test-coverage voor cross-user re-encryptie

## Acties vastgelegd

- `HorseSafe/ACTIONS.md` — Fase 5 afgevinkt, Fase 6 omhoog
- `HorseSafe/CHANGELOG.md` — [0.0.5-Shamir] sectie compleet
- `HorseSafe/version.json` + `backend/config.py` — v0.0.5-Shamir
- `HorseSafe/BUGS.md` — HS-001 deferred v1.0
- `HorseSafe/docs/screens/` — S09 + S10 toegevoegd
- Meta_Master `STATUS.md` + `RESUME.md` — volgt in commit-stap
- `claude_memory/project_horsesafe.md` + `MEMORY.md` — bijwerken
