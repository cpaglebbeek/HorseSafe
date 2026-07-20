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
- HorseSafe browser-extensie (v0.2.0+)

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

## Secrets-management

`/opt/horsesafe/.env` (mode 600, eigenaar `horsesafe`):
- `HORSESAFE_JWT_SECRET` — 32 hex bytes
- `HORSESAFE_TOTP_ENCRYPTION_KEY` — 32 hex bytes
- `HORSESAFE_MAGIC_LINK_BRIDGE_URL` — endpoint iCt_Horse magic-link bridge
- `HORSESAFE_GMAIL_APP_PASSWORD` — fallback bij directe Gmail SMTP

**Rotatie:**
- JWT-secret: bij compromittering rotate → alle sessies invalid
- TOTP-key: bij compromittering rotate → users moeten TOTP opnieuw inrichten
- Magic-link: alleen secret bij bridge, niet hier

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

Interne go-live-checklist tegen de LIVE-omgeving (`horsecloud55.ddns.net/HorseSafe/`). Externe partij-pen-test blijft aanbevolen bij eerste zakelijke klant (zie DPIA).

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
