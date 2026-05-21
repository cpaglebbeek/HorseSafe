# frontend/ — HorseSafe browser-client

> **v0.0.2-Hellman** — POC kdbxweb-frontend LIVE (single-vault per user, geen MFA-UI nog, geen import/export, geen extensie).

## Stack

- **Vanilla ES2022** — geen build-step. Direct serveerbaar via nginx-static of `python -m http.server`.
- **Vendored libs** in `vendor/` (zie `vendor/README.md`):
  - `kdbxweb` 2.1.1 (MIT) — KDBX3/4 read/write in browser
  - `argon2-browser` 1.18.0 (MIT) — Argon2id KDF via WASM (bundled)
- **Tests:** Playwright e2e (Chromium-only POC).

## Structuur

```
frontend/
├── index.html          # S1 landing + register-form
├── login.html          # S2 login (geen MFA in v0.0.2)
├── vault.html          # S6 unlock + S7 entries (single-page)
├── assets/
│   ├── horsesafe.css   # dark-theme uit DESIGN_TOKENS.md
│   └── horsesafe.svg   # placeholder-logo
├── js/
│   ├── api.js          # fetch-wrappers naar backend
│   ├── auth.js         # register/login UI
│   ├── crypto.js       # kdbxweb-wrapper + Argon2id-bridge + clipboard-wipe
│   ├── vault-ui.js     # entries-tabel + detail-paneel + entry-edit
│   └── main.js         # vault.html event-wiring
├── vendor/
│   ├── kdbxweb/        # kdbxweb.min.js + LICENSE.MIT
│   ├── argon2/         # argon2-bundled.min.js + argon2.wasm + LICENSE.MIT
│   └── README.md       # update-procedure
├── tests/
│   └── smoke.spec.ts   # e2e: register + login + vault-roundtrip + verkeerd-pw
├── package.json        # @playwright/test (dev-only)
├── playwright.config.ts
└── README.md           # dit bestand
```

## Lokaal draaien

```bash
# 1. Start backend (terminal 1) met CORS voor dev:
cd /Users/christian/Documents/Gemini_Projects/HorseSafe
source backend/venv/bin/activate
HORSESAFE_JWT_SECRET="$(openssl rand -hex 32)" \
HORSESAFE_COOKIE_SECURE=false \
HORSESAFE_CORS_ORIGINS=http://localhost:8000 \
HORSESAFE_DB_PATH=./backend/.dev-db/horsesafe.db \
HORSESAFE_VAULTS_DIR=./backend/.dev-vaults \
uvicorn backend.app:app --reload --port 3997

# 2. Start frontend (terminal 2):
cd /Users/christian/Documents/Gemini_Projects/HorseSafe/frontend
python3 -m http.server 8000

# 3. Open http://localhost:8000/index.html
```

## E2E tests draaien

```bash
cd frontend
npm install   # eenmalig (installeert @playwright/test)
npx playwright install chromium   # eenmalig (browser binary)

# Backend moet draaien (zie boven). Frontend wordt door playwright zelf gestart.
npm test
```

## Wat doet de POC?

1. **S1 — Landing** met register-form (account-pw + ack-checkbox)
2. **S2 — Login** (account-pw → JWT-cookie)
3. **S6 — Vault unlock**: bij eerste keer leeg → maak nieuwe vault aan met master-pw → upload encrypted KDBX-blob naar backend
4. **S7 — Vault content**: entries-tabel + detail-paneel + entry-toevoegen + pw-toggle + 10s-clipboard-wipe + entry-delete + lock-and-reopen-roundtrip

## Wat doet de POC NIET (toekomstige fasen)

- MFA-UI (TOTP + magic-link) → v0.0.3-Merkle
- Admin-pagina → v0.0.4-Rivest
- Import/export (KDBX/Bitwarden/CSV/XLSX) → v0.0.5-Shamir
- Browser-extensie + échte clipboard-wipe → v0.2.0-Schneier
- Meerdere vaults per user → v0.2.1-Daemen

## Argon2id

`crypto.js` koppelt `argon2-browser` aan `kdbxweb` via `kdbxweb.CryptoEngine.setArgon2Impl(...)`.
v0.0.2 maakt vaults aan met **AES-KDF** (kdbxweb-default voor `Kdbx.create()` — snel voor POC).
Argon2id-KDF voor nieuwe vaults wordt expliciet ingeschakeld vanaf **v0.0.5-Shamir** via `db.upgrade()`.

Bestaande KDBX-bestanden mét Argon2id-KDF (geïmporteerd via Fase 5) zullen volledig werken — de Argon2id-impl staat klaar.
