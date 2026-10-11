# SECURITY.md — HorseSafe

> Security-policy en disclosure-protocol. Cross-ref: `THREAT_MODEL.md`, `PRINCIPLES.md`, `GDPR_COMPLIANCE.md`.

## Disclosure-procedure

**E-mail:** security@icthorse.nl (PGP-key in `docs/security-pgp.asc` na live).

**Response-SLA:**
- Acknowledgment binnen 48u
- Triage binnen 7 dagen
- Fix-target afhankelijk van kleurcode:
  - 🔴 Rood (rce, auth-bypass, vault-leak): 7 dagen
  - 🟡 Geel (privilege-escalation, info-leak metadata): 30 dagen
  - 🟢 Groen (UI-bugs, low-impact): next release

## Scope

In scope:
- HorseSafe backend (`/opt/horsesafe/backend/`)
- HorseSafe frontend (`/opt/horsesafe/web/`)
- Hardware-sleutels, step-up en noodsleutel (v0.2.0-Koblitz+; contract `docs/HARDWARE_KEYS.md`)
- Android-app `android/` (vanaf v0.3.0-Miller)
- HorseSafe browser-extensie (Schneier, gepland)

Buiten scope:
- HC55-server-config zelf (zie `cloudinfra`)
- iCt_Horse magic-link bridge (apart project)
- Externe dependencies (kdbxweb, FastAPI etc.) → upstream

## Bekende beperkingen (geen "bug")

Zie `THREAT_MODEL.md` § "Bekende beperkingen v0.0.x" en § "Dreigingen waar HorseSafe NIET tegen beschermt".

## Veilige defaults

| Item | Default |
|---|---|
| TLS | 1.3 minimum |
| HSTS | `max-age=31536000; includeSubDomains` |
| CSP | strict, geen unsafe-inline behalve style |
| Cookies | HttpOnly + Secure + SameSite=Strict |
| JWT TTL | 12u sliding |
| Failed-login throttle | 5/15min per IP+email |
| Argon2id KDF | t=12 m=128MiB p=2 |
| KDBX-format | 4 |
| Random | `secrets.token_urlsafe(32)` voor tokens; `os.urandom` server-side; `crypto.getRandomValues` browser |
| Session-binding | UA+IP optioneel (v0.1) |
| Logging | nooit body-content, alleen metadata |
| WebAuthn (v0.2.0) | rpId `icthorsecloud.nl`, origin `https://icthorsecloud.nl`, `userVerification: required`, `authenticatorAttachment: cross-platform`, `hints: ["security-key"]`, `attestation: direct` |
| Toegestane authenticators | Alleen YubiKey Bio (dagelijks) en YubiKey 5/Bio (noodsleutel): `packed`-attestation tot de gevendorde Yubico-roots + AAGUID-allowlist uit FIDO MDS3; BE=0/BS=0 (geen gesynchroniseerde passkeys) |
| WebAuthn-challenge | 32 random bytes, 300 s, eenmalig, alleen SHA-256-hash opgeslagen |
| Step-up | 300 s (`HORSESAFE_STEPUP_TTL_SECONDS`); Bio, of TOTP zolang er geen actieve Bio is |
| Noodsleutel | 24 u wachttijd + 24 u venster, één keer bruikbaar; blokkade alleen op te heffen met Bio-step-up |
| Testvlag | `HORSESAFE_TEST_ATTESTATION=false`; de app weigert te starten met de vlag aan en de productie-rpId |
| Mail | SMTP 587 + STARTTLS (`ssl.create_default_context()`), From = SMTP-gebruiker |

## Crypto-keuzes (samenvatting)

Zie `ARCHITECTURE.md`, `PRINCIPLES.md`, `CLAUDE.md`.

| Doel | Algoritme |
|---|---|
| KDF account-pw | argon2id (passlib defaults) |
| KDF vault-master-key | argon2id (KDBX4-header: t=12 m=128MiB p=2) |
| Vault buiten-cipher | AES-256-CBC + HMAC-SHA-256 (KDBX4 standaard) |
| Vault inner-cipher | ChaCha20 |
| JWT | HS256 (server-secret in env, 32 bytes) |
| Magic-link | 32-byte urlsafe-random |
| TOTP | RFC 6238 SHA-1 30s/6digits (Google Authenticator-compat) |
| TOTP-secret at-rest | AES-GCM-encrypted met `HORSESAFE_TOTP_ENCRYPTION_KEY` in env |
| Cookie-signature | server-secret 32 bytes |
| ETag | SHA-256 van blob |
| Verzegelde ontgrendelkopie (v0.2.0, P-CRYPT-09) | Seal_v2: X25519 (ECDH, eenmalige sleutel) + HKDF-SHA256 + AES-256-GCM; AAD = `HSv2`‖purpose‖vault_id‖key_id |
| Sleutel uit YubiKey | WebAuthn PRF (hmac-secret) → HKDF-SHA256 (`info="HorseSafe v2 X25519"`) → X25519-privésleutel, alleen in browser-RAM |
| WebAuthn-handtekeningen | EdDSA (-8) of ES256 (-7), geverifieerd met py_webauthn |

## Secrets-management

`/opt/horsesafe/.env` (mode 600, eigenaar `horsesafe`):
- `HORSESAFE_JWT_SECRET` — 32 hex bytes
- `HORSESAFE_TOTP_ENCRYPTION_KEY` — 32 hex bytes
- `HORSESAFE_MAGIC_LINK_BRIDGE_URL` — endpoint iCt_Horse magic-link bridge
- `HORSESAFE_SMTP_HOST`, `HORSESAFE_SMTP_PORT` (587), `HORSESAFE_SMTP_USER`, `HORSESAFE_SMTP_PASSWORD`, `HORSESAFE_SMTP_FROM` — generieke mailer (v0.2.0-Koblitz); From = SMTP-gebruiker
- `HORSESAFE_GMAIL_USER`, `HORSESAFE_GMAIL_APP_PASSWORD` — alleen fallback (SMTP_SSL 465 werkt niet op HC55)

De waarden komen uit ClaudeSecrets en staan alleen in `/opt/horsesafe/.env`; in deze repo staan uitsluitend variabelenamen (`backend/.env.example`). Nooit in code, docs, tests, logs of audit.

**Geen secrets, wel vertrouwensanker:** `backend/data/yubico_fido_roots.pem` (Yubico FIDO-attestation-roots) en `backend/data/aaguids.json` (allowlist uit FIDO MDS3) zijn publiek materiaal, gevendord en reproduceerbaar via `backend/tools/build_yubico_roots.py` en `build_aaguids.py`. Een wijziging daarin is een beveiligingswijziging en hoort in review.

**Rotatie:**
- JWT-secret: bij compromittering rotate → alle sessies invalid
- TOTP-key: bij compromittering rotate → users moeten TOTP opnieuw inrichten
- Magic-link: alleen secret bij bridge, niet hier
- SMTP-wachtwoord: bij compromittering roteren bij de mailprovider en `.env` bijwerken; zolang de mailer niet werkt is noodsleutel-vrijgave uitgeschakeld

## CSP-policy (productie)

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
connect-src 'self';
img-src 'self' data:;
frame-ancestors 'none';
form-action 'self';
base-uri 'self';
object-src 'none';
```

## Pen-test plan (pre-v0.1.0)

Voor open-source-go-live (v0.1.0): externe pen-test op:
1. Auth-bypass attempts
2. Vault-blob-tampering (HMAC-bypass)
3. Optimistic-lock race
4. TOTP-replay
5. CSRF + XSS in admin-pagina
6. Path-traversal in `/vault/{id}`
7. SQL-injection (alle input)
8. Side-channel timing op login

Resultaat → SECURITY-POSTURE.md (na pen-test).

## Pen-test-checklist v0.1.0-Massey — uitgevoerd 2026-07-20 (interne LIVE-probe)

Interne go-live-checklist tegen de LIVE-omgeving (`icthorsecloud.nl/HorseSafe/`). Externe partij-pen-test blijft aanbevolen bij eerste zakelijke klant (zie DPIA).

| # | Test | Resultaat | Bewijs |
|---|---|---|---|
| 1 | Security-headers | ✅ compleet | HSTS `max-age=31536000; includeSubDomains`, CSP `default-src 'self'` + `object-src 'none'` + `frame-ancestors 'none'`, X-Frame DENY, X-Content-Type nosniff, Referrer no-referrer |
| 2 | Auth-bypass `/api/vault` zonder cookie | ✅ geblokt | HTTP 401 |
| 3 | Path-traversal `/vault/{id}` (`..%2f`, `../`) | ✅ geblokt | HTTP 401 (auth-gate vóór resolve) |
| 4 | SQL-injection login-email `' OR 1=1--` | ✅ geweigerd | HTTP 422 Pydantic email-validatie; ORM parametriseert queries |
| 5 | Rate-limit login (8× snel) | ✅ actief | 401×4 → 429×4 |
| 6 | CORS cross-origin preflight (`Origin: evil`) | ✅ geen ACAO | lege `cors_origins` in productie → geen cross-origin |
| 7 | OpenAPI/docs-exposure | ⚠️→✅ **fix** | was `/docs`+`/openapi.json`+`/redoc` = 200; `docs_enabled=false` (default) sluit ze in productie |
| 8 | Set-Cookie op mislukte/gerate-limite login | ✅ geen | geen sessie-cookie bij fail |

**Openstaand (server-side niet los te probren, client-side by-design):**
- Vault-blob-HMAC-tampering + TOTP-replay: zero-knowledge → server ziet plaintext niet; integriteit is client-side (kdbxweb HMAC-SHA-256). Getest via cross-runtime roundtrip in v0.0.9.
- Side-channel timing login: Argon2id constante-tijd-verificatie via passlib; niet gemeten, laag risico.

## Te testen vóór deploy v0.2.0-Koblitz

Acceptatiecriteria: `docs/HARDWARE_KEYS.md` §10 en de minimale tests in §12.14. Beveiligingsrelevant in het bijzonder:

- Gesynchroniseerde passkey (BE=1), UV=0, `fmt=none`, verkeerde origin en niet-Bio-AAGUID als `bio` worden geweigerd.
- Hergebruikte of verlopen challenge → 400 `invalid_challenge`; signCount-daling → 409.
- Noodsleutel: vóór 24 u 423 `recovery_waiting`; daarna één keer bruikbaar; geblokkeerd → 423; opheffen met TOTP → 403 `stepup_bio_required`.
- Release zonder mailer → 503 `notify_unavailable`; mailer faalt → 503 `notify_failed` en state blijft `idle`.
- Een verzegelde kopie met afwijkende vault_id, key_id of purpose opent niet.
- Live: `/api/health` geeft `test_attestation:false`; een Windows Hello-passkey wordt geweigerd.
