# backend/ — HorseSafe FastAPI

> Phase 0 — placeholder. Backend-skeleton volgt in Fase 1.

## Geplande structuur

```
backend/
├── pyproject.toml         # ruff + black + pytest config
├── requirements.txt       # FastAPI, Pydantic, passlib[argon2], pyotp, pyjwt, aiosqlite
├── app.py                 # FastAPI-instance + main()
├── routes/
│   ├── auth.py            # /auth/register, /auth/login, /auth/magic-link, /auth/totp/*
│   ├── vault.py           # /vault GET, POST, PUT, DELETE
│   └── admin.py           # /admin/users, /admin/stats, /admin/audit
├── models/
│   ├── user.py            # Pydantic + SQLite-row mapping
│   ├── vault.py
│   └── audit.py
├── services/
│   ├── auth_service.py    # JWT + Argon2id
│   ├── mfa_service.py     # TOTP + magic-link bridge
│   ├── storage_service.py # blob read/write + etag-locking
│   └── audit_service.py
├── db/
│   └── schema.sql         # SQLite-tables
└── tests/
    ├── test_auth.py
    ├── test_vault.py
    ├── test_admin.py
    └── fixtures/
        └── test_vault.kdbx
```

## Run lokaal (geplant)

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 3997
```
