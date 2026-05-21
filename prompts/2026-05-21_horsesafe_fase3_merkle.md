---
date: 2026-05-21
session: horsesafe_fase3_merkle
status: done
resume: ""
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: []
---

# Sessie 2026-05-21 — HorseSafe Fase 3 v0.0.3-Merkle: MFA-integratie LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 3 ("1, alles akkoord") na presentatie van plan + 5 opties + 6 blokken + impact + risico's.

## Wat is gebouwd

**Backend:**
| Component | Files |
|---|---|
| Services | `mfa_service.py` (TOTP RFC 6238 + AES-GCM-encrypt-at-rest secret) + `magic_link_service.py` (Gmail SMTP + token + EmailSender Protocol voor test-mocking) |
| Routes | Uitgebreid `auth.py` met 5 endpoints: `/auth/totp/{setup,verify,disable}` + `/auth/magic-link` + `/auth/magic-link/redeem` |
| Models | `models/auth.py` met Pydantic-modellen |
| Vault-gate | `vault.py` `_user()` → vereist `jwt.mfa = true` voor accounts met TOTP |
| JWT-uitbreiding | `mfa` claim toegevoegd + `reissue_with_mfa()` helper |
| Config | 6 nieuwe env-vars (TOTP_ENCRYPTION_KEY, GMAIL_USER/APP_PASSWORD, MAGIC_LINK_TTL_MINUTES, PUBLIC_URL, MFA_REQUIRED, TOTP_ISSUER) |
| Tests | `test_mfa_totp.py` (7 tests) + `test_mfa_magic_link.py` (3 tests) |

**Frontend:**
| Component | Files |
|---|---|
| HTML | `mfa.html` (S4 challenge met 2 tabs) + `settings.html` (S12 TOTP management) |
| JS | `mfa.js` (challenge UI + tab-switch) + `settings.js` (setup-flow + QR-render + disable) |
| Vendored | `vendor/qrcode/qrcode.js` v2.0.4 MIT (~55KB) — voor TOTP-otpauth-URL QR-code render |
| Updates | `auth.js` (mfa_required → redirect mfa.html) + `vault-ui.js` (403 mfa_required handling) + `vault.html` (+ Instellingen-knop) |
| Dev-tooling | `frontend/devserver.py` — COOP/COEP+WASM-MIME headers (BUG-001-retry-vector) |
| E2E | `tests/mfa.spec.ts` — TOTP setup + re-login MFA-challenge flow (in-browser HMAC-SHA1 TOTP-impl) |

**Docs:**
- `docs/screens/S04_mfa.md` + `S12_settings.md`
- `BUGS.md` HS-001-status update: retry-vector documented, deferred naar v0.0.5+
- `CHANGELOG.md` [0.0.3-Merkle] sectie compleet

## Verificatie

| Test | Resultaat |
|---|---|
| Backend pytest | **25/25 ✅** (was 15, +10 MFA-tests) |
| Ruff lint | ✅ |
| Black format | ✅ |
| Frontend e2e playwright | **3/3 ✅** in 6.6s (S1 + vault-roundtrip + MFA-flow) |

## Belangrijkste beslissingen tijdens implementatie

| Punt | Keuze | Reden |
|---|---|---|
| TOTP-secret at-rest | AES-GCM met server-master-key uit env-var | Niet plaintext; standard pattern |
| TOTP-secret fallback (no key) | `plain:` prefix in DB | Dev-mode flexibility; productie eist key |
| Email-sender architectuur | `EmailSender` Protocol + `GmailSMTPSender` default | Mockbaar in tests via `set_sender(stub)` |
| Magic-link in e-mail | Volledige URL met `HORSESAFE_PUBLIC_URL` + `?t=<token>` | Werkt cross-host (dev: localhost:8000) |
| Magic-link respons (onbekend e-mail) | Altijd 200 — geen onthulling | Info-leak-resistant |
| MFA-failed-throttle | Hergebruik `failed_logins`-tabel via event=`mfa_fail` | Geen apart schema nodig |
| JWT-claim "mfa" | `mfa: bool` toegevoegd aan payload | Eén cookie, twee staten (pre/post MFA) |
| Vault-gate | 403 `mfa_required` als `users.totp_secret IS NOT NULL` + `jwt.mfa = false` | Backward-compat: no-TOTP-user krijgt direct mfa=true bij login |
| QR-render | Vendored `qrcode-generator` 2.0.4 (SVG-output) | Geen build-step + scalable |
| TOTP-disable verificatie | Vereist huidige TOTP-code | Voorkomt accidenteel disable bij gestolen cookie |
| Argon2id-retry | Niet uitgevoerd in v0.0.3 — devserver.py retry-vector aangemaakt voor latere cross-browser test | Conservatief: AES-KDF blijft default; bridge staat klaar |

## Bekende bugs

- **HS-BUG-001** (🟡 geel, deferred v0.0.5+) — argon2-browser WASM hangt in headless Chromium. Retry-vector `frontend/devserver.py` aangemaakt (COOP/COEP + WASM-MIME). Cross-browser test verschoven naar Fase 5 (KeePassXC-CLI oracle-test).

## Wat NIET gebouwd (per WhatIf-scope)

- MFA-backup-codes → v0.0.4-Rivest (samen met admin-pagina + admin-rescue)
- Admin-pagina → v0.0.4-Rivest
- Import/export → v0.0.5-Shamir
- Argon2id-default-re-enable → v0.0.5+
- iCt_Horse-magic-link-bridge hergebruik → v0.0.7+ deploy

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe Fase 4 — admin-pagina (v0.0.4-Rivest)`

**Scope Fase 4:**
1. Admin-pagina S11: user-CRUD + storage-stats + audit-log-viewer
2. Admin-routes `/admin/{users,stats,audit}`
3. `is_admin` JWT-claim check + admin-rescue flow
4. MFA-backup-codes (10 codes per user, gehashed in DB)
5. `/auth/me` endpoint voor frontend-status-probe
6. Versie-bump → v0.0.4-Rivest

## Acties vastgelegd

- `HorseSafe/ACTIONS.md` — Fase 3 afgevinkt, Fase 4 omhoog
- `HorseSafe/CHANGELOG.md` — [0.0.3-Merkle] sectie compleet
- `HorseSafe/version.json` — 0.0.2 → 0.0.3-Merkle
- `HorseSafe/backend/config.py` `app_version` — bumped
- `HorseSafe/BUGS.md` — HS-BUG-001 status update
- `HorseSafe/docs/screens/` — S04 + S12 toegevoegd
- `Meta_Master/STATUS.md` — volgt in commit-stap
- `Meta_Master/RESUME.md` — regenereren via update_resume.py
- `claude_memory/project_horsesafe.md` + MEMORY.md — bijwerken Fase 3-status
