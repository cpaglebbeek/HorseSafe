# HorseSafe

> SaaS password-safe op HorseCloud55 met KeePassXC-equivalente functionaliteit en strict zero-knowledge server-architectuur.

**Productnaam:** HorseSafe
**Versie:** 0.0.0-Rijndael-skeleton
**Status:** Phase 0 — repo-skeleton (newp-protocol fase 2)
**Ecosysteem:** iCt Horse Diensten (sub-master: `Meta_iCt_Horse_Diensten`)
**Repo-zichtbaarheid:** PRIVATE (open-source overweging vanaf v0.1.0)
**Codenaam-thema:** Cryptografen — v0.0.x = Rijndael (Daemen + Rijmen, AES-ontwerpers)

## Een-zin-beschrijving

Browser-based wachtwoordkluis met client-side KDBX4-encryptie (KeePass-compat), MFA via Gmail magic-link of TOTP, optionele browser-extensie voor autocomplete, en clipboard-wipe na 10s. Server houdt enkel encrypted blobs vast — pw en keyfile verlaten nooit de browser.

## Belangrijkste kenmerken

- **Zero-knowledge:** server ziet enkel ciphertext; master-pw + keyfile alleen client-side
- **KDBX4-compat:** export = native KDBX4 → user kan vault openen in KeePassXC-desktop (disaster-recovery garantie)
- **Encryptie-keuze:** alleen pw / alleen keyfile / beide
- **MFA op account-laag:** Gmail magic-link (hergebruik bestaande iCt_Horse stack) + TOTP RFC 6238
- **Twee onafhankelijke auth-lagen:** account-login (server kent) ≠ vault-decryptie (alleen client kent)
- **Multi-device:** optimistic locking met etag; v0.0.x = single-device lock; v0.1.x = conflict-merge UI
- **Clipboard-wipe:** best-effort overschrijf met `[HorseSafe wiped]` na 10s in browser; extensie kan échte clipboard-wipe (v0.2.0)
- **Import:** KDBX3/KDBX4 + Bitwarden JSON + KeePass-CSV + XLSX
- **Export:** alle bovenstaande + KDBX4 (plaintext-formaten unprotected, audit-log + reden-veld verplicht)
- **Per-entry live TOTP** (v0.0.9-Bellare+): KeePassXC-compatibele `otp`-veld → browser-side RFC 6238 via WebCrypto → 6-cijferige code + 30s countdown in detail-pane, geen externe lib. Seeds blijven in encrypted vault.
- **Keyfile vault-open** (v0.0.9-Bellare+): `vault.html` accepteert KeePass `.keyx`/`.key`-bestanden naast pw. Default-format = 64-hex-char ASCII (KeePass 1.x-spec); XML 2.0 import via lokale Node-resave (zie HS-BUG-005).
- **Admin-pagina:** user CRUD + storage-stats + login-pogingen; GEEN vault-toegang

## Tech-stack

| Laag | Keuze | Reden |
|---|---|---|
| Backend | Python 3.12 + FastAPI | Consistent met SMSRelay/iCt_Horse-stack op HC55; backend doet alleen blob-storage + auth |
| Storage | `/opt/horsesafe/vaults/<user-uuid>/<vault-uuid>.kdbx` + SQLite user-metadata | Zero-knowledge: vault-content = encrypted blob op disk |
| Frontend | Vanilla JS + `kdbxweb` (MIT) | De-facto webclient voor KDBX4; gebruikt libargon2-wasm voor Argon2id KDF |
| Crypto | KDBX4 standaard (AES-256-CBC + HMAC-SHA-256, of ChaCha20 + Poly1305-impliciet via KDBX-AEAD) + Argon2id | KeePassXC-compat; toekomstbestendig |
| Auth | JWT cookie (HttpOnly + Secure + SameSite=Strict) | Standaard FastAPI pattern |
| MFA | Magic-link (iCt_Horse stack) + TOTP RFC 6238 | Hergebruik bestaande infra |
| Hosting | HorseCloud55 :3997 + nginx-location `/HorseSafe/` | Naast SMSRelay 3995, ClaudeBug 3996 |

## URL-pad

- **v0.0.x intern:** `https://horsecloud55.ddns.net/HorseSafe/`
- **v0.1.x dienst:** `https://icthorse.nl/HorseSafe/`

## Documenten

- `ARCHITECTURE.md` — conceptueel/logisch/fysiek
- `DESIGN.md` — UI/UX flows, schermen, componenten
- `PRINCIPLES.md` — ontwerpbeginselen + dwingende constraints
- `DEPENDENCIES.md` — externe libs, services, integraties
- `THREAT_MODEL.md` — dreigingsmodel + zero-knowledge bewijs
- `BUGLIST.md` — open bugs met kleurcode (groen/geel/rood/loop)
- `ACTIONS.md` — openstaande acties + WhatIf-vervolgvragen
- `CLAUDE.md` — repo-specifieke regels voor AI-agenten
- `version.json` — actuele versie + codenaam + thema

## Status

Phase 0 = repo-skeleton + ontwerp-documentatie. **Geen code, geen deploy, geen nginx-edit.**
Volgende fase (1) na akkoord = backend-skeleton (FastAPI), frontend-skeleton (kdbxweb POC), zonder publieke endpoint.
