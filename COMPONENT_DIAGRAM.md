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
┌──────────────────────────── BROWSER ────────────────────────────┐
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │
│  │ Auth-UI  │ │ Vault-UI │ │ Crypto   │ │ Clipboard│ │ TOTP   │  │
│  │          │ │ + keyfile│ │ + keyfile│ │          │ │ render │  │
│  │          │ │ input    │ │ arg      │ │          │ │ (RFC   │  │
│  │          │ │          │ │          │ │          │ │ 6238)  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘  │
│       └────────────┴────────────┴────────────┴───────────┘       │
│                              │                                    │
└──────────────────────────────┼────────────────────────────────────┘
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

## C4-Level 3 — Componenten frontend (v0.0.9-Bellare+)

```
frontend/
├── vault.html              ───► detail-pane: TOTP-rij (d-totp-{label,cell,code,countdown,copy})
│                                unlock-form: vault-keyfile <input type="file">
├── js/
│   ├── crypto.js          ───► HorseSafeCrypto.openDatabase(blob, pw, keyFileBuffer)
│   │                      ───► HorseSafeCrypto.listEntries() → entries[].otp (parsed otpauth)
│   ├── totp.js  (NEW)     ───► HorseSafeTotp.generateTotp(uri) → {code, secondsLeft, period}
│   │                      ───► HorseSafeTotp.parseOtpauth(uri) → {secret, digits, period, algo}
│   │                      uses crypto.subtle.sign('HMAC') + base32-decoder + RFC 4226 truncation
│   ├── vault-ui.js        ───► state.totpTimer + startTotpLoop/stopTotpLoop/renderTotpOnce/copyTotp
│   │                      ───► auto-start in selectEntry, auto-stop in lockVault
│   └── main.js            ───► binding #d-totp-copy → UI.copyTotp()
└── vendor/
    └── kdbxweb v2.1.1     (keyfile: 64-hex default; XML werkt sinds 2026-07-21 ook browser-side → HS-BUG-005-update)
```

## Sequence-overzicht

Zie `SEQUENCE_DIAGRAMS.md` voor flows.

## Dependency-graph

Zie `DEPENDENCIES.md` voor libs.

## Deployment-topologie

Zie `DEPLOYMENT.md` § "Doel-omgeving" + § "Systemd".
