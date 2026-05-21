# backend/ — HorseSafe FastAPI

> **v0.0.1-Diffie** — backend-skeleton LIVE (geen MFA, geen admin, geen import/export).
> Volgende fasen voegen toe: MFA (v0.0.3), admin (v0.0.4), import/export (v0.0.5).

## Structuur

```
backend/
├── pyproject.toml           # ruff + black + mypy + pytest config
├── requirements.txt         # FastAPI, Pydantic, passlib[argon2], pyjwt, aiosqlite, ...
├── .env.example             # template voor lokale .env
├── config.py                # Settings via Pydantic-Settings (HORSESAFE_* env)
├── app.py                   # FastAPI-instance + lifespan + middlewares + routers
├── routes/
│   ├── health.py            # GET /health (publiek)
│   ├── auth.py              # POST /register, POST /login, POST /logout
│   └── vault.py             # GET, POST, PUT (If-Match), DELETE op /vault
├── models/                  # Pydantic-models user/vault/audit
├── services/
│   ├── auth_service.py      # Argon2id-hash + verify + throttle
│   ├── jwt_service.py       # JWT + HttpOnly cookie
│   ├── storage_service.py   # blob CRUD + sha256-etag + atomic-write + secure-delete
│   └── audit_service.py     # append-only audit_log
├── middlewares/
│   ├── csp_headers.py       # CSP + HSTS + X-Frame-Options + nosniff
│   └── ratelimit.py         # in-memory sliding-window (Redis vanaf v0.1.0)
├── db/
│   ├── schema.sql           # 5 tabellen (users/vaults/audit_log/magic_links/failed_logins)
│   ├── connection.py        # aiosqlite-context-manager
│   └── init.py              # `python -m backend.db.init`
└── tests/
    ├── conftest.py          # AsyncClient + per-test tmp DB/vaults + lichte argon2
    ├── test_health.py
    ├── test_auth.py         # register / login / throttle / logout
    └── test_vault.py        # CRUD / etag-conflict / cross-user isolation
```

## Run lokaal

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # pas HORSESAFE_JWT_SECRET aan!
python -m backend.db.init  # DB-schema laden (idempotent)
uvicorn backend.app:app --reload --port 3997
# Probeer: curl http://127.0.0.1:3997/health
```

> NB: vanaf project-root draaien (`cd /Users/christian/Documents/Gemini_Projects/HorseSafe`)
> zodat `backend.*` als package werkt.

## Tests draaien

```bash
cd /Users/christian/Documents/Gemini_Projects/HorseSafe
source backend/venv/bin/activate
pytest backend/tests -v
```

Tests gebruiken `tmp_path` per test → geen state-pollution. Argon2id staat op
lichte parameters (t=2, m=8MiB) voor snelle testruns.

## API-endpoints (Fase 1)

| Methode | Pad | Auth | Doel |
|---|---|---|---|
| GET | `/health` | — | Health-check + version |
| POST | `/auth/register` | — | Account aanmaken (vereist `ack_data_loss`) |
| POST | `/auth/login` | — | Pw-login → JWT-cookie (geen MFA in Fase 1) |
| POST | `/auth/logout` | JWT | Sessie wissen |
| GET | `/vault` | JWT | Eigen vault-list |
| POST | `/vault` | JWT | Vault aanmaken (multipart: `name` + `blob`) |
| GET | `/vault/{id}` | JWT | KDBX4-blob downloaden (+ ETag) |
| PUT | `/vault/{id}` | JWT + If-Match | Blob updaten (optimistic lock) |
| DELETE | `/vault/{id}` | JWT | Vault verwijderen (3-pass secure delete) |

Volledige spec: zie `../API.md`. NB: API.md beschrijft MFA-gated endpoints — die
zijn in Fase 1 niet actief; vault-routes vereisen nu enkel JWT.

## Versie

- Huidig: **v0.0.1-Diffie**
- Volgende: v0.0.2-Hellman (frontend POC met kdbxweb)
