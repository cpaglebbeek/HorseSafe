---
date: 2026-05-21
session: horsesafe_fase2_hellman
status: done
resume: ""
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: []
---

# Sessie 2026-05-21 — HorseSafe Fase 2 v0.0.2-Hellman: frontend kdbxweb POC LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 2 ("1, alles akkoord") na presentatie van plan + 4 opties + impact + risico's.

## Wat is gebouwd

**Frontend (vanilla ES2022, geen build-step):**
| Type | Files |
|---|---|
| HTML | `index.html` (S1 + register) · `login.html` (S2) · `vault.html` (S6 + S7) |
| CSS | `assets/horsesafe.css` (dark-theme uit DESIGN_TOKENS) |
| Asset | `assets/horsesafe.svg` (placeholder-logo) |
| JS | `js/api.js` · `js/auth.js` · `js/crypto.js` · `js/vault-ui.js` · `js/main.js` |
| Vendored | `vendor/kdbxweb/kdbxweb.min.js` (MIT 2.1.1, 135KB) + `vendor/argon2/argon2-bundled.min.js` (MIT 1.18.0, 45KB) + `argon2.wasm` (25KB) |
| Tests | `package.json` + `playwright.config.ts` + `tests/smoke.spec.ts` |

**Backend updates:**
- `CORSMiddleware` toegevoegd (env-var-gestuurd; productie: leeg → uit)
- `SecurityHeadersMiddleware`: COOP+COEP toegevoegd
- `RateLimitMiddleware` nu opt-out via `HORSESAFE_RATE_LIMIT_ENABLED=false`
- Middleware-order: CORS outermost (zorgt voor ACAO ook bij 429/423-responses)

**Docs:**
- `docs/screens/S01_landing.md` + `S02_login.md` + `S06_unlock.md` + `S07_content.md`
- `frontend/README.md` van placeholder → live (run-instructies, e2e how-to, vendor-update-procedure)
- `frontend/vendor/README.md` met update-procedure

**CI:**
- Nieuwe job `frontend-e2e` na `backend`. Start backend in achtergrond + draait playwright tegen frontend (npm install + chromium-only).

## Verificatie

**Backend pytest:** 15/15 groen ✅ (na CORS+COEP toevoeging)
**Ruff:** ✅ All checks passed
**Black:** ✅ 26 files unchanged
**Playwright e2e (Chromium headless):** 2/2 ✅ in 4.1s
  - test 1: S1 landing rendert
  - test 2: register + login + vault aanmaken (in browser!) + entry add + pw-toggle + lock + reopen-roundtrip + verkeerd-pw-error

**Smoke-test handmatig:**
- `http://localhost:8000` → S1 toont
- Register → 201, redirect S2
- Login → cookie gezet, redirect vault.html
- Vault-pw invoer → eerste keer: nieuwe KDBX in browser, upload naar `/vault` (1223 bytes)
- Entry toevoegen + pw-toggle + clipboard-copy met 10s aftelling

## Belangrijke beslissingen tijdens implementatie

| Punt | Keuze | Reden |
|---|---|---|
| KDF voor nieuwe vaults | **AES-KDF** (`KdfId.Aes`) ipv default Argon2d | argon2-browser-WASM hangt in headless Chromium (BUG-001) — AES-KDF is KDBX-spec-conform en opent in KeePassXC-desktop |
| Cross-origin frontend↔backend | `localhost:8000 ↔ localhost:3997` (zelfde hostname, niet 127.0.0.1) | Browsers behandelen `localhost` en `127.0.0.1` als verschillende sites voor cookies |
| Middleware-order | CORS outermost (laatste add) | RateLimit kan vroege 429 returnen; CORS-wrap zorgt voor ACAO-header |
| RateLimit-bypass voor e2e | `HORSESAFE_RATE_LIMIT_ENABLED=false` env-var | In-memory rate-limit accumuleert tussen test-runs |
| argon2-bridge | Blijft staan (geen schade) | Klaar voor v0.0.3+ wanneer browser-cross-test argon2-stabiliteit bevestigt |
| Geen Node.js build-step | Vendor UMD-bundles in `frontend/vendor/` | Conform PRINCIPLES.md P-DEV-02 |
| Wachtwoord-genereren | `crypto.getRandomValues(Uint32Array)` % charset-length | KeePassXC-equivalent, cryptografisch random |

## Bekende bugs

- **HS-BUG-001** (🟡 geel, open) — argon2-browser WASM hangt in headless Chromium. Gemitigeerd via AES-KDF-switch voor nieuwe vaults. Target-fix v0.0.3.

## Wat NIET gebouwd (per WhatIf-scope)

- MFA-UI (TOTP + magic-link) → Fase 3 (v0.0.3-Merkle)
- Admin-pagina → Fase 4 (v0.0.4-Rivest)
- Import/export (KDBX/Bitwarden/CSV/XLSX) → Fase 5 (v0.0.5-Shamir)
- Browser-extensie → v0.2.0-Schneier
- KeePassXC-desktop-roundtrip e2e met `keepassxc-cli` → v0.0.5+

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe Fase 3 — MFA-integratie (TOTP + magic-link)`

**Scope Fase 3 (v0.0.3-Merkle):**
1. Backend MFA-endpoints (`/auth/totp/setup`, `/auth/totp/verify`, `/auth/magic-link`, `/auth/magic-link/redeem`)
2. MFA-bridge naar iCt_Horse-magic-link-stack (hergebruik bestaande SMTP/Gmail)
3. Frontend S4 MFA-challenge-scherm + S12 settings-pagina
4. TOTP-QR-code-render in browser (otpauth://-URL)
5. Argon2id-KDF voor nieuwe vaults — alleen na browser-cross-test (Chrome/Firefox/Safari echte browser) BUG-001-resolve
6. Versie-bump → v0.0.3-Merkle

## Acties vastgelegd

- `HorseSafe/ACTIONS.md` — Fase 2 afgevinkt, Fase 3 omhoog met Argon2id-re-enable als sub-task
- `HorseSafe/CHANGELOG.md` — [0.0.2-Hellman] sectie compleet
- `HorseSafe/version.json` — 0.0.1 → 0.0.2-Hellman
- `HorseSafe/BUGS.md` — HS-BUG-001 toegevoegd (argon2-headless-hang)
- `HorseSafe/docs/screens/` — 4 schermen S01/S02/S06/S07 ingevuld
- `HorseSafe/.github/workflows/ci.yml` — frontend-e2e job toegevoegd
- `Meta_Master/STATUS.md` — volgt in commit-stap
- `Meta_Master/RESUME.md` — regenereren via update_resume.py
- `claude_memory/project_horsesafe.md` + MEMORY.md — bijwerken Fase 2-status
