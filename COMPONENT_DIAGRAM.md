# COMPONENT_DIAGRAM.md — HorseSafe

> Visualisaties + componenten-overzicht. Cross-ref: `ARCHITECTURE.md §2.1`.

## C4-Level 1 — Context

```
                ┌──────────────────────────────────────────────┐
                │             Eindgebruiker (browser)          │
                └──────────────┬───────────────────────────────┘
                               │ HTTPS
                ┌──────────────▼───────────────────────────────┐
                │                HorseSafe SaaS                │
                │   (zero-knowledge wachtwoord-vault)           │
                └──────┬──────────────┬──────────────┬──────────┘
                       │              │              │
                       ▼              ▼              ▼
              ┌────────────┐  ┌──────────────┐  ┌────────────────┐
              │ Gmail (MFA │  │ Hetzner-     │  │ iCt_Horse      │
              │ magic-link)│  │ Storagebox   │  │ magic-link     │
              │            │  │ (backup)     │  │ bridge         │
              └────────────┘  └──────────────┘  └────────────────┘
```

## C4-Level 2 — Containers

```
┌──────────────────────── BROWSER ────────────────────────┐
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Auth-UI  │  │ Vault-UI │  │ Crypto   │  │ Clipboard│  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       └─────────────┴─────────────┴─────────────┘        │
│                          │                                │
└──────────────────────────┼────────────────────────────────┘
                           │ HTTPS
┌──────────────────────────┼────────────── HORSECLOUD55 ─┐
│                          ▼                              │
│              ┌────────────────────────┐                 │
│              │ nginx :443             │                 │
│              │ /HorseSafe/ + /HorseSafe/api/             │
│              └────────────┬───────────┘                 │
│                           │ HTTP localhost              │
│                           ▼                             │
│              ┌────────────────────────┐                 │
│              │ FastAPI :3997          │                 │
│              │  - /auth/*             │                 │
│              │  - /vault/*            │                 │
│              │  - /admin/*            │                 │
│              └─┬──────────────────┬──┘                 │
│                │                  │                     │
│                ▼                  ▼                     │
│       ┌──────────────┐  ┌─────────────────┐            │
│       │ SQLite       │  │ /opt/horsesafe/ │            │
│       │ (users,      │  │ vaults/         │            │
│       │  audit,      │  │  <u>/           │            │
│       │  vaults-meta)│  │   <v>.kdbx      │            │
│       └──────────────┘  └─────────────────┘            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## C4-Level 3 — Componenten backend

```
FastAPI app
├── routes/
│   ├── auth.py        ───► AuthService ──► PasslibArgon2
│   │                  ───► JWTService
│   │                  ───► MFAService ──► PyOTP (TOTP)
│   │                                   └► HTTP (magic-link bridge)
│   ├── vault.py       ───► VaultService ──► StorageService (filesystem)
│   │                                     └► DBService (vaults-tabel)
│   └── admin.py       ───► AdminService
└── middlewares/
    ├── audit.py       ───► AuditService (writes audit_log)
    ├── ratelimit.py
    └── csp_headers.py
```

## Sequence-overzicht

Zie `SEQUENCE_DIAGRAMS.md` voor flows.

## Dependency-graph

Zie `DEPENDENCIES.md` voor libs.

## Deployment-topologie

Zie `DEPLOYMENT.md` § "Doel-omgeving" + § "Systemd".
