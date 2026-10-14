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
│   ├── schema.sql           # fresh-install-blob = alle migraties (schema-versie 5)
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

## Hardware-sleutels (v0.2.0-Koblitz)

Bindend contract: `../docs/HARDWARE_KEYS.md` §12. Backend-onderdelen:

| Onderdeel | Bestand |
|---|---|
| `POST /webauthn/options` (register/unlock/stepup) | `routes/webauthn.py` |
| `GET/POST /vault/{vid}/keys`, `POST …/{kid}/unlock`, `PUT …/keys/sealed`, `PUT /vault/{vid}/rekey`, `POST/DELETE …/release`, `POST/DELETE …/block`, `DELETE …/{kid}` | `routes/vault_keys.py` |
| `POST /auth/stepup` (bio of TOTP) | `routes/auth.py` |
| WebAuthn-verificatie (py_webauthn + eigen vlag-, AAGUID- en signCount-controles) | `services/webauthn_service.py` |
| Seal_v2-vormcontrole, recovery-state, meldingen | `services/vault_key_service.py` |
| Step-up-claims in het JWT | `services/stepup_service.py`, `services/jwt_service.py` |
| Generieke SMTP-mailer (587 STARTTLS; ook magic-link) | `services/mail_service.py` |
| Yubico-roots + AAGUID-allowlist (publiek, gevendord) | `data/`, gebouwd met `tools/build_*.py` |
| Migratie (herschreven 005) | `db/migrations/005_vault_keys.sql` + `db/schema.sql` |

Nieuwe dependency: `webauthn` (py_webauthn, trekt `cbor2`, `pyOpenSSL`, `pyasn1` mee).
Tests gebruiken een in-test softwareauthenticator (`tests/softauth.py`) met een eigen test-root;
de testvlag `HORSESAFE_TEST_ATTESTATION` staat alleen aan waar een test dat nodig heeft.

De data in `data/` vernieuwen (publiek materiaal, geen secrets):

```bash
python -I backend/tools/build_yubico_roots.py /tmp/ykpki       # zie docstring voor downloads
python -I backend/tools/build_aaguids.py /tmp/mds/blob.jwt --root /tmp/mds/root-r3.crt
```

## Telefoon koppelen (v0.3.4-Miller deel 2)

Bindend contract: `../docs/HARDWARE_KEYS.md` §13.

| Onderdeel | Bestand |
|---|---|
| `POST/GET/DELETE /devices/pairings…`, `…/claim`, `…/confirm`, `GET /devices`, `DELETE /devices/{id}` | `routes/devices.py` |
| `GET /device/v1/status`, `GET /device/v1/keys/{kid}/sealed` (getekend met K_dev) | `routes/device_api.py` |
| Afleidingen (§13.1), pairings/devices in de DB, device-handtekening + nonces | `services/device_service.py` |
| Android key attestation: keten, Google-roots, revocatielijst (24 u cache), key-description (`pyasn1`) | `services/android_attestation.py` |
| Google hardware-attestation-roots (publiek, gevendord) | `data/android_attestation_roots.pem`, gebouwd met `tools/build_android_roots.py` |
| Migratie | `db/migrations/006_devices_pairings.sql` (via `migrate.py`; `schema.sql` blijft op 5) |
| Tests + nep-app (ook CLI voor Playwright) | `tests/test_devices.py`, `tests/test_pair_vectors.py`, `tests/fake_device.py` |

Nieuwe dependency: `pyasn1==0.6.4` (kwam al mee met `webauthn`; nu direct gebruikt).
Testvlag `HORSESAFE_TEST_DEVICE_ATTESTATION` (alleen tests; `create_app()` weigert hem met rpId
`icthorsecloud.nl`): software-attestation, package `….debug`, willekeurige signer, de vaste test-root
`tests/fake_device_root.pem`, en een onbereikbare revocatielijst telt als leeg.

```bash
python -I backend/tools/build_android_roots.py /tmp/androidroots/page.html --json /tmp/androidroots/roots.json
```

## Versie

- Huidig: **v0.2.0-Koblitz** (zie `config.py::app_version`)
