# COMPONENT_DIAGRAM.md — HorseSafe

> Visualisaties + componenten-overzicht. Cross-ref: `ARCHITECTURE.md §2.1`.

## C4-Level 1 — Context

```
   ┌──────────────────┐   USB   ┌──────────────────────────────────────────────┐
   │ YubiKey Bio /    │◄───────►│             Eindgebruiker (browser)          │
   │ noodsleutel      │ WebAuthn└──────────────┬───────────────────────────────┘
   │ (v0.2.0-Koblitz) │  + PRF                 │
                               │ HTTPS
                ┌──────────────▼───────────────────────────────┐
                │                HorseSafe SaaS                │
                │   (zero-knowledge wachtwoord-vault)           │
                └──────┬──────────────┬──────────────┬──────────┘
                       │              │              │
                       ▼              ▼              ▼
              ┌────────────┐  ┌──────────────┐  ┌────────────────┐
              │ SMTP 587   │  │ Hetzner-     │  │ Gmail SMTP     │
              │ STARTTLS   │  │ Storagebox   │  │ (alleen        │
              │ magic-link │  │ (backup)     │  │ fallback,      │
              │ + meldingen│  │              │  │ 465 dicht HC55)│
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
│              │  - /webauthn/* (v0.2)  │                 │
│              │  - /vault/*/keys (v0.2)│                 │
│              └─┬──────────────────┬──┘                 │
│                │                  │                     │
│                ▼                  ▼                     │
│       ┌──────────────┐  ┌─────────────────┐            │
│       │ SQLite       │  │ /opt/horsesafe/ │            │
│       │ (users,      │  │ vaults/         │            │
│       │  audit,      │  │  <u>/           │            │
│       │  vaults-meta,│  │   <v>.kdbx      │            │
│       │  vault_keys, │  │                 │            │
│       │  webauthn_   │  │                 │            │
│       │  challenges) │  │                 │            │
│       └──────────────┘  └─────────────────┘            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## C4-Level 3 — Componenten backend

```
FastAPI app
├── routes/
│   ├── auth.py        ───► AuthService ──► PasslibArgon2
│   │                  ───► JWTService (+ claims stepup_until/stepup_method, v0.2)
│   │                  ───► MFAService ──► PyOTP (TOTP)
│   │                                   └► MagicLinkService ──► MailService
│   │                  ───► POST /auth/stepup ──► StepupService ──► WebAuthnService | PyOTP
│   ├── vault.py       ───► VaultService ──► StorageService (filesystem)
│   │                                     └► DBService (vaults-tabel)
│   ├── webauthn.py    ───► WebAuthnService (opties + challenges)          (v0.2)
│   ├── vault_keys.py  ───► WebAuthnService ──► py_webauthn
│   │                  │                     ├► data/yubico_fido_roots.pem
│   │                  │                     └► data/aaguids.json
│   │                  ───► VaultKeyService (validate_sealed, recovery_state, notify_user)
│   │                  ───► StorageService (rekey: blob atomair)            (v0.2)
│   │                  ───► MailService (send_async via asyncio.to_thread)
│   └── admin.py       ───► AdminService
├── services/
│   └── mail_service.py ──► SMTPSender (587 STARTTLS) | GmailSMTPSender (fallback)  (v0.2)
└── middlewares/
    ├── audit.py       ───► AuditService (writes audit_log)
    ├── ratelimit.py
    └── csp_headers.py
```

## C4-Level 3 — Componenten frontend (v0.0.9-Bellare+, aangevuld v0.2.0-Koblitz)

```
frontend/
├── vault.html              ───► detail-pane: TOTP-rij (d-totp-{label,cell,code,countdown,copy})
│                                unlock-form: vault-keyfile <input type="file">
│                                v0.2: keuze YubiKey / Keyfile + sleutelbeheer + wijzig pw/keyfile
├── js/
│   ├── crypto.js          ───► HorseSafeCrypto.openDatabase(blob, pw, keyFileBuffer)
│   │                      ───► variant met kant-en-klaar Credentials-object (hardware-route, v0.2)
│   │                      ───► HorseSafeCrypto.listEntries() → entries[].otp (parsed otpauth)
│   ├── totp.js  (NEW)     ───► HorseSafeTotp.generateTotp(uri) → {code, secondsLeft, period}
│   │                      ───► HorseSafeTotp.parseOtpauth(uri) → {secret, digits, period, algo}
│   │                      uses crypto.subtle.sign('HMAC') + base32-decoder + RFC 4226 truncation
│   ├── vault-ui.js        ───► state.totpTimer + startTotpLoop/stopTotpLoop/renderTotpOnce/copyTotp
│   │                      ───► auto-start in selectEntry, auto-stop in lockVault
│   ├── main.js            ───► binding #d-totp-copy → UI.copyTotp()
│   ├── hwkeys.js  (v0.2)  ───► window.HorseSafeHwKeys: checkSupport, listKeys, enroll, unlock,
│   │                           resealAll, rekey, requestRelease/cancelRelease/block/unblock/deleteKey,
│   │                           stepUp, secretFromCredentials, credentialsFromHashes, _crypto (Seal_v2)
│   ├── hwkeys-ui.js (v0.2)───► sleutelbeheer-paneel; statussen in gewone taal; banner notify_available=false
│   └── stepup.js  (v0.2)  ───► step-up-dialoog (Bio of TOTP), herhaalt de actie één keer
└── vendor/
    └── kdbxweb v2.1.1     (keyfile: 64-hex default; XML werkt sinds 2026-07-21 ook browser-side → HS-BUG-005-update)
```

## Sequence-overzicht

Zie `SEQUENCE_DIAGRAMS.md` voor flows (SQ-9 t/m SQ-12: hardware-sleutels).

## Dependency-graph

Zie `DEPENDENCIES.md` voor libs.

## Deployment-topologie

Zie `DEPLOYMENT.md` § "Doel-omgeving" + § "Systemd".
