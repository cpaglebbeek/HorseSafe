---
date: 2026-05-21
session: horsesafe_fase1_diffie
status: done
resume: ""
project: HorseSafe
ecosystem: iCt Horse Diensten
parent_master: Meta_iCt_Horse_Diensten
linked_actions: []
---

# Sessie 2026-05-21 — HorseSafe Fase 1 v0.0.1-Diffie: backend FastAPI-skeleton LIVE

## Trigger
Gebruiker akkoord op WhatIf Fase 1 ("alles akkoord" na presentatie van plan + 4 opties + impact + risico's).

## Wat is gebouwd

**Backend-skeleton** (Python 3.14 lokaal, requirements eisen >=3.12):

| Laag | Files |
|---|---|
| App + config | `backend/app.py`, `backend/config.py`, `backend/pyproject.toml`, `backend/requirements.txt`, `backend/.env.example` |
| DB | `backend/db/schema.sql` (5 tabellen), `backend/db/connection.py`, `backend/db/init.py` |
| Models | `backend/models/{user,vault,audit}.py` |
| Services | `backend/services/{auth,jwt,storage,audit}_service.py` |
| Middlewares | `backend/middlewares/{csp_headers,ratelimit}.py` |
| Routes | `backend/routes/{health,auth,vault}.py` |
| Tests | `backend/tests/{conftest,test_health,test_auth,test_vault}.py` |

**Endpoints actief (9):** GET /health, POST /auth/{register,login,logout}, GET/POST /vault, GET/PUT/DELETE /vault/{id}.

## Verificatie

**Pytest:**
```
15 passed, 96% coverage
```

Tests dekken:
- Health-endpoint + security-headers (CSP/HSTS/X-Frame/nosniff)
- Register: happy path + ack-vereist + zwak-pw afwijzen + duplicate-email-conflict
- Login: happy + wrong-pw + unknown-email (timing-safe) + throttle na 5 mislukte pogingen (rate-limit OF account-throttle)
- Logout: happy + 401 zonder cookie
- Vault: auth-vereist + volledige CRUD-lifecycle + etag-conflict 412 + cross-user isolation + duplicate-name 409

**Uvicorn smoke-test (lokaal port 3997):**
- /health → `{"status":"ok","version":"0.0.1-Diffie","db":"ok","vaults_dir":"ok"}`
- Security headers in response → ✅
- /auth/register → 201 + user_id terug
- /auth/login → 200 + JWT-cookie gezet
- /vault met cookie → 200 + lege lijst

## Beslissingen tijdens implementatie

| Punt | Keuze | Reden |
|---|---|---|
| Argon2id params (server-side account-pw) | t=3, m=64MiB, p=4 (default) | Lager dan KDBX-vault-default (t=12, m=128MiB) — server-side moet snel zijn voor login-flow |
| Test-argon2id-params | t=2, m=8MiB, p=1 | Voorkomt trage testsuite (1.3s totaal) |
| Failed-login-throttle vs rate-limit | Beide actief | Test accepteert 423 of 429 — beide zijn correct security-gedrag |
| JWT-secret-warning | Productie 32+ bytes via openssl rand | Test-conftest gebruikt 53-byte string |
| Vault-blob upload | multipart `name` + `blob` | FastAPI File+Form werkt out-of-the-box |
| Etag-format | SHA-256 hex (64 chars) | Standaard, deterministisch, zonder weak-etag-quoting |
| Atomic write | tmp + os.replace | POSIX atomic op zelfde fs |
| Delete | 3-pass random overschrijf + unlink | Ook al is KDBX al ciphertext: zorgvuldig vanwege metadata-residue |
| In-memory ratelimit | Deque per (ip, prefix) | Goed genoeg Fase 1; Redis vanaf v0.1.0 |

## Wat NIET gebouwd (per WhatIf-scope)

- MFA-routes (TOTP, magic-link) → Fase 3 (v0.0.3-Merkle)
- Admin-routes → Fase 4 (v0.0.4-Rivest)
- Import/export → Fase 5 (v0.0.5-Shamir)
- Productie-deploy + nginx → Fase 7+

## CI-status

GitHub Actions `ci.yml` heeft 4 conditionele jobs:
- `repo-structure` — actief, runt elke push (26 files-check + secrets-scan)
- `backend` — activeert vanzelf zodra `backend/requirements.txt` aanwezig is (= NU)
- `frontend` — wacht op `frontend/index.html` (Fase 2)
- `kdbx-roundtrip` — wacht op `backend/tests/fixtures/test_vault.kdbx` (Fase 5)

**Verwachting:** eerste push naar `main` triggert nu backend-job. Lokaal getest met `ruff check` + `black --check` + `mypy --strict` zou meeste issues moeten oppakken; eerste CI-run kan kleine issues laten zien.

## Volgende sessie

**Hervat-opdracht:**
> `verder met HorseSafe Fase 2 — frontend kdbxweb POC (v0.0.2-Hellman)`

**Scope Fase 2:**
- Vanilla ES2022 frontend in `frontend/`
- `index.html` + `login.html` + `vault.html` (3 schermen S1+S2+S6/S7)
- `vendor/kdbxweb.esm.js` pinnen op laatste stable (versie noteren in DEPENDENCIES)
- `js/api.js` fetch-wrappers naar `/HorseSafe/api/`
- `js/crypto.js` kdbxweb-wrapper + clipboard-manager met 10s aftelling
- `docs/screens/S01_landing.md` + screenshot
- E2E playwright-smoke-test (start backend + frontend, login + lege vault unlock + write entry + roundtrip)
- Bump → v0.0.2-Hellman

## Acties vastgelegd

- `HorseSafe/ACTIONS.md` — Fase 1 afgevinkt, Fase 2 omhoog
- `HorseSafe/CHANGELOG.md` — [0.0.1-Diffie] sectie toegevoegd
- `HorseSafe/version.json` — 0.0.0 → 0.0.1
- `HorseSafe/backend/README.md` — placeholder → live
- `Meta_Master/STATUS.md` — volgt in commit-stap
- `Meta_Master/RESUME.md` — regenereren via update_resume.py
- `claude_memory/project_horsesafe.md` + memory — bijwerken met Fase 1-status
