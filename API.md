# API.md — HorseSafe REST-API

> Versie: v0.0.0-Rijndael (skeleton — endpoints nog niet geïmplementeerd).
> Conform `ARCHITECTURE.md §2.3` en `PRINCIPLES.md`.

## Basis-URL

- **v0.0.x intern:** `https://horsecloud55.ddns.net/HorseSafe/api/`
- **v0.1.x dienst:** `https://icthorse.nl/HorseSafe/api/`

## Authenticatie

- **JWT cookie** (HttpOnly, Secure, SameSite=Strict)
- Cookie-naam: `horsesafe_session`
- TTL: 12u sliding window
- Header voor write-acties: `If-Match: <etag>` (optimistic lock)

## Foutmodel

```json
{ "error": "<machine-code>", "message": "<menselijke uitleg>", "details": {} }
```

| HTTP | Betekenis |
|---|---|
| 200 | OK |
| 201 | Created |
| 204 | No content (delete) |
| 400 | Validation error (Pydantic) |
| 401 | Niet geauthenticeerd |
| 403 | Wel geauthenticeerd maar geen rechten |
| 409 | Conflict (bv. e-mail al in gebruik) |
| 412 | Precondition Failed (etag-mismatch) |
| 423 | Locked (failed-login throttle) |
| 429 | Rate-limit |

## Endpoints

### Auth

#### `POST /auth/register`
**Body:**
```json
{
  "email": "user@example.com",
  "password": "<account-pw, niet vault-pw>",
  "ack_data_loss": true
}
```
**Response 201:**
```json
{ "user_id": "<uuid>", "email": "user@example.com" }
```
**Errors:** 400 (zwak pw / ontbrekende ack), 409 (e-mail bestaat).

#### `POST /auth/login`
**Body:**
```json
{ "email": "user@example.com", "password": "..." }
```
**Response 200:** zet `horsesafe_session` cookie. Body:
```json
{ "mfa_required": true, "mfa_methods": ["totp", "magic_link"] }
```
**Errors:** 401, 423.

#### `POST /auth/magic-link`
**Body:** `{ "email": "user@example.com" }`
**Response 202:** "Als deze e-mail bestaat, is een link verzonden." (info-leak-resistant)

#### `GET /auth/magic-link/redeem?t=<token>`
**Response 302:** redirect naar `/HorseSafe/vault/` met JWT-cookie set, of 401.

#### `POST /auth/totp/setup`
**Auth:** JWT (geen MFA vereist nog).
**Response 200:**
```json
{ "secret_base32": "...", "qr_code_url": "otpauth://totp/HorseSafe:user@example.com?secret=...&issuer=HorseSafe" }
```

#### `POST /auth/totp/verify`
**Body:** `{ "code": "123456" }`
**Response 200:** activeert TOTP voor account.

#### `POST /auth/logout`
Wist cookie. 204.

### Vault

Alle endpoints: vereisen JWT + voltooide MFA in deze sessie.

#### `GET /vault`
**Response 200:**
```json
[ { "id": "<vault-uuid>", "name": "default", "size_bytes": 4096, "etag": "<sha-256>", "updated_at": 1734820000 } ]
```

#### `POST /vault`
**Body:** multipart upload van lege of bestaande KDBX4-blob + `name` field.
**Response 201:** zoals GET-row.

#### `GET /vault/{id}`
**Response 200:** body = pure KDBX4-bytes. Header `ETag: <sha-256>`. Content-Type: `application/octet-stream`.

#### `PUT /vault/{id}`
**Header:** `If-Match: <oude-etag>` verplicht.
**Body:** nieuwe KDBX4-blob.
**Response 200:** nieuwe etag in header.
**Error 412:** `{"error":"etag_mismatch","current_etag":"<server-etag>"}`.

#### `DELETE /vault/{id}`
**Response 204.** Blob wordt veilig overgeschreven (3-pass random) vóór unlink.

#### `POST /vault/{id}/audit-export`
**Body:** `{ "format": "csv|json|xlsx|kdbx", "reason": "<verplicht voor plaintext>" }`
**Response 200:** `{ "audit_id": "<uuid>", "allowed": true }`. Frontend voert daarna de export client-side uit.

### Admin

Alle endpoints: vereisen JWT met claim `is_admin: true` + voltooide MFA.

#### `GET /admin/users`
Lijst van alle users met counts.

#### `POST /admin/users`
Body: `{ email, is_admin, magic_link_only }`. Server stuurt invite-magic-link.

#### `DELETE /admin/users/{id}`
Cascading delete: vaults + audit-log-anonimisatie. Hard-delete na 30 dagen.

#### `GET /admin/stats`
```json
{
  "users_total": 12,
  "vaults_total": 12,
  "storage_bytes": 524288,
  "logins_24h": 45,
  "failed_logins_24h": 3
}
```

#### `GET /admin/audit?user=&event=&from=&to=`
Audit-log met filters.

## Rate-limits

| Endpoint | Limiet |
|---|---|
| `/auth/login` | 5/15min per IP+email |
| `/auth/magic-link` | 3/uur per email, 10/uur per IP |
| `/auth/totp/verify` | 5/15min per account |
| `/vault/{id}` PUT | 60/min per user |
| `/admin/*` | 100/min per admin |

## OpenAPI

FastAPI exposeert automatisch `/HorseSafe/api/openapi.json` (alleen accessable als admin in productie; in dev altijd).
