# ENGINE_INPUT_CONTROL.md — HorseSafe

> Input-validatie + sanitization-policy. In tegenstelling tot iCt_Horse_Assist (waar "engine" = remote-keyboard/mouse) is HorseSafe-input puur HTTP-bodies + file-uploads + KDBX-content.

## Input-bronnen

| Bron | Sanitization-eis |
|---|---|
| **HTTP request-body (JSON)** | Pydantic v2 strict-mode + custom validators |
| **HTTP query-strings** | Pydantic + URL-escape voor logging |
| **HTTP headers (Authorization, If-Match, ...)** | Format-check; ETag regex `^[a-f0-9]{64}$` |
| **Cookies** | JWT-signature-verify; afwijzing op tamper |
| **File-uploads (KDBX)** | Size-cap 50MB, header-magic-check (KDBX4 = `0x03D9A29A 0x67FB4BB5`), HMAC-verify door kdbxweb in browser; server doet GEEN parse |
| **File-uploads (CSV/JSON/XLSX import)** | Frontend-only — server ziet alleen merged KDBX-blob |
| **TOTP-codes** | Regex `^\d{6}$` |
| **E-mails** | Pydantic EmailStr + DNS-MX-check (optioneel) |
| **Wachtwoorden (account)** | Min lengte 12; zxcvbn-score ≥ 3; max lengte 256 |
| **Vault-naam** | Regex `^[\w \-]{1,64}$`; geen path-separators |

## Geblokkeerde patronen

| Patroon | Reden |
|---|---|
| Path-traversal `../` in vault-ID | UUID-validatie |
| SQL-injection | Parameterized queries (aiosqlite) verplicht |
| HTML/JS in user-input | Frontend rendert via `textContent`, niet `innerHTML` |
| Header-injection (CR/LF) | FastAPI strips automatisch |
| Argon2id-DoS (extreem hoge KDF-params) | KDBX-header-check op KDF-params; max t=64, m=512MiB |
| Bytes-omitting (UTF-8 invalid) | Pydantic str-validation rejects |

## Rate-limits per input-type

Zie `API.md § Rate-limits`.

## Failure-mode

- **400 Bad Request** met machine-leesbare error-code
- **422 Unprocessable Entity** voor Pydantic-validation-failures
- **413 Payload Too Large** voor blobs > 50MB
- **415 Unsupported Media Type** voor non-octet-stream KDBX-uploads
- Server logt validation-failures naar audit_log met event `input_rejected`

## CSP-laag

Frontend CSP (zie `SECURITY.md`) verbiedt:
- `script-src 'unsafe-inline'` (geen XSS-pivot via injected HTML)
- `connect-src` buiten `'self'` (geen exfiltratie via injected fetch)
- `frame-ancestors 'none'` (geen clickjack)

## Test-coverage

Per `BUGS.md` HS-BUG-PRE-008: import-CSV met UTF-8-BOM, UTF-16, Windows-1252-fixtures verplicht in pytest.
