# HorseSafe

> SaaS password-safe op HorseCloud55 met KeePassXC-equivalente functionaliteit en strict zero-knowledge server-architectuur.

**Productnaam:** HorseSafe
**Versie:** 0.2.0-Koblitz (in bouw; LIVE draait 0.1.0-Massey)
**Status:** Koblitz — hardware-sleutels (YubiKey Bio + noodsleutel) in het web, server-geverifieerd. Ontwerp: `docs/HARDWARE_KEYS.md`.
**Ecosysteem:** iCt Horse Diensten (sub-master: `Meta_iCt_Horse_Diensten`)
**Repo-zichtbaarheid:** PUBLIC, AGPL-3.0 (sinds v0.1.0-Massey)
**Codenaam-thema:** Cryptografen — v0.0.x = Rijndael; v0.1.0 Massey; v0.2.0 Koblitz, v0.3.0 Miller, v0.4.0 Montgomery, v0.5.0 Lange (zie `ROADMAP.md`)

## Een-zin-beschrijving

Browser-based wachtwoordkluis met client-side KDBX4-encryptie (KeePass-compat), MFA via magic-link of TOTP, ontgrendelen met een YubiKey Bio (v0.2.0), optionele browser-extensie voor autocomplete, en clipboard-wipe na 10s. Server houdt enkel encrypted blobs vast — pw en keyfile verlaten nooit de browser.

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
- **Hardware-sleutels** (v0.2.0-Koblitz): vault ontgrendelen met één vinger op een YubiKey Bio in Chrome/Edge (WebAuthn PRF). De server verifieert attestation, gebruikersverificatie en device-binding (geen gesynchroniseerde passkeys) en bewaart per sleutel alleen een kopie `{ph,kh}` die verzegeld is naar de YubiKey en die hij zelf niet kan openen (P-CRYPT-09). Wachtwoord + keyfile blijven de basis en de KeePassXC-noodroute.
- **Noodsleutel** (v0.2.0-Koblitz): reserve-YubiKey met PIN van 63 tekens, bruikbaar na 24 uur wachttijd met mail en audit; blokkeren kan altijd, opheffen alleen met YubiKey Bio.
- **Step-up + rekey** (v0.2.0-Koblitz): uitbreidende sleutelacties vragen een verse bevestiging; wachtwoord/keyfile wijzigen vernieuwt blob en alle verzegelde kopieën in één stap.
- **Meldingen** (v0.2.0-Koblitz): generieke SMTP-mailer (587 STARTTLS, `HORSESAFE_SMTP_*`) voor magic-links en beveiligingsmeldingen.

## Tech-stack

| Laag | Keuze | Reden |
|---|---|---|
| Backend | Python 3.12 + FastAPI | Consistent met SMSRelay/iCt_Horse-stack op HC55; backend doet alleen blob-storage + auth |
| Storage | `/opt/horsesafe/vaults/<user-uuid>/<vault-uuid>.kdbx` + SQLite user-metadata | Zero-knowledge: vault-content = encrypted blob op disk |
| Frontend | Vanilla JS + `kdbxweb` (MIT) | De-facto webclient voor KDBX4; gebruikt libargon2-wasm voor Argon2id KDF |
| Crypto | KDBX4 standaard (AES-256-CBC + HMAC-SHA-256, of ChaCha20 + Poly1305-impliciet via KDBX-AEAD) + Argon2id | KeePassXC-compat; toekomstbestendig |
| Auth | JWT cookie (HttpOnly + Secure + SameSite=Strict) | Standaard FastAPI pattern |
| MFA | Magic-link (SMTP-mailer) + TOTP RFC 6238 | Hergebruik bestaande infra |
| Hardware-sleutels | WebAuthn PRF + py_webauthn (server) + Seal_v2 (X25519/HKDF/AES-GCM via WebCrypto) | Device-bound YubiKey, server kan kopie niet openen |
| Hosting | HorseCloud55 :3997 + nginx-location `/HorseSafe/` | Naast SMSRelay 3995, ClaudeBug 3996 |

## URL-pad

- **LIVE:** `https://icthorsecloud.nl/HorseSafe/` (hardware-sleutels werken alleen hier, WebAuthn-rpId)
- **Publiek:** `https://icthorse.nl/HorseSafe/` (302 → icthorsecloud.nl)

## Documenten

- `ARCHITECTURE.md` — conceptueel/logisch/fysiek
- `UI_DESIGN.md` — UI/UX flows, schermen, componenten
- `PRINCIPLES.md` — ontwerpbeginselen + dwingende constraints
- `DEPENDENCIES.md` — externe libs, services, integraties
- `THREAT_MODEL.md` — dreigingsmodel + zero-knowledge bewijs
- `docs/HARDWARE_KEYS.md` — hardware-sleutels, noodsleutel, telefoon-app; bindend Koblitz API-contract (§12)
- `API.md`, `DATA_MODEL.md`, `SECURITY.md`, `DPIA.md`, `SEQUENCE_DIAGRAMS.md`, `COMPONENT_DIAGRAM.md`, `ROADMAP.md`, `CHANGELOG.md`
- `BUGS.md` — open bugs met kleurcode (groen/geel/rood/loop)
- `ACTIONS.md` — openstaande acties + WhatIf-vervolgvragen
- `CLAUDE.md` — repo-specifieke regels voor AI-agenten
- `version.json` — actuele versie + codenaam + thema

## Status

v0.1.0-Massey is LIVE en publiek (AGPL-3.0). v0.2.0-Koblitz (web + backend) is in bouw en nog niet gedeployed; acceptatiecriteria in `docs/HARDWARE_KEYS.md` §10. Daarna: v0.3.0-Miller (Android-app) en v0.4.0-Montgomery (laptop ontgrendelen via telefoon-QR + vinger). v0.5.0-Lange (native kluis in de app) is gepland maar wordt pas na de veldtest van v0.4 gebouwd.
