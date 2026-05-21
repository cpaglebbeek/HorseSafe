# SEQUENCE_DIAGRAMS.md — HorseSafe

> Mermaid-flows voor belangrijke operaties. Cross-ref: `ARCHITECTURE.md §2.4-2.6`.

## SQ-1 — Account-registratie

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API as FastAPI :3997
    participant DB as SQLite

    User->>Browser: vul email, pw, vink "data-loss ack"
    Browser->>API: POST /auth/register {email, pw, ack}
    API->>API: validate (Pydantic + ack-check)
    API->>API: argon2id-hash(pw)
    API->>DB: INSERT users (id, email, pw_hash, ...)
    DB-->>API: ok
    API-->>Browser: 201 {user_id, email}
    Browser-->>User: redirect /login
```

## SQ-2 — Login + TOTP

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant DB

    User->>Browser: email + account-pw
    Browser->>API: POST /auth/login
    API->>DB: SELECT users WHERE email
    DB-->>API: user-row
    API->>API: argon2.verify(pw, pw_hash)
    API->>API: set JWT-cookie (pre-MFA)
    API-->>Browser: 200 {mfa_required: true, methods: [totp, magic_link]}
    Browser->>User: kies MFA-methode
    User->>Browser: voer TOTP-code in
    Browser->>API: POST /auth/totp/verify {code}
    API->>DB: SELECT totp_secret WHERE id=jwt.user
    DB-->>API: secret (decrypted from at-rest)
    API->>API: pyotp.verify(code, secret, window=1)
    API->>API: upgrade JWT-cookie (mfa_passed=true)
    API->>DB: INSERT audit_log (mfa_pass_totp)
    API-->>Browser: 200 {ok}
    Browser->>Browser: redirect /vault
```

## SQ-3 — Magic-link login

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant DB
    participant Bridge as iCt_Horse magic-link bridge
    participant Mail as Gmail SMTP

    User->>Browser: email
    Browser->>API: POST /auth/magic-link {email}
    API->>DB: SELECT users WHERE email
    DB-->>API: user (of NULL)
    API->>DB: INSERT magic_links (token, user_id, exp=10min)
    API->>Bridge: POST /send {to: email, link: ".../redeem?t=<token>"}
    Bridge->>Mail: SMTP
    Mail-->>User: e-mail met link
    API-->>Browser: 202 "indien email bestaat, link verzonden"

    User->>Browser: klik link
    Browser->>API: GET /auth/magic-link/redeem?t=<token>
    API->>DB: SELECT magic_links WHERE token, exp>now, redeemed_at IS NULL
    DB-->>API: row
    API->>DB: UPDATE magic_links SET redeemed_at=now
    API->>API: set JWT-cookie (mfa_passed=true)
    API-->>Browser: 302 /vault
```

## SQ-4 — Vault-openen (decryptie volledig in browser)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant FS as Filesystem
    participant DB

    Note over Browser: JWT-cookie + mfa_passed
    Browser->>API: GET /vault/{id}
    API->>DB: SELECT vault WHERE id, user_id=jwt.user
    DB-->>API: blob_path + etag
    API->>FS: read blob_path
    FS-->>API: KDBX4-bytes
    API->>DB: INSERT audit_log (vault_read)
    API-->>Browser: 200 + body=KDBX4 + ETag header

    User->>Browser: voer master-pw + optioneel keyfile
    Browser->>Browser: kdbxweb.Kdbx.load(blob, credentials)
    Note over Browser: Argon2id KDF (zware berekening, ~1s)
    Browser->>Browser: AES-256-CBC + HMAC verify
    Browser-->>User: render entries
```

## SQ-5 — Vault-update met optimistic lock

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant FS

    User->>Browser: bewerk entry, klik save
    Browser->>Browser: kdbxweb.save() → nieuwe KDBX4-blob
    Browser->>API: PUT /vault/{id}, If-Match: <oude-etag>, body=blob
    API->>API: bereken huidige server-etag (sha256 van disk-blob)
    alt etag matcht
        API->>FS: write blob (atomic: tmp + rename)
        API->>API: nieuwe etag = sha256(new blob)
        API->>DB: UPDATE vaults SET etag=..., size_bytes=..., updated_at=now
        API->>DB: INSERT audit_log (vault_update)
        API-->>Browser: 200 + nieuwe ETag header
    else etag mismatch
        API-->>Browser: 412 {error: etag_mismatch, current_etag: ...}
        Browser->>User: dialog "vault elders gewijzigd; herlaad of force overwrite"
    end
```

## SQ-6 — Plaintext export (CSV/JSON/XLSX)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant DB

    User->>Browser: klik "Exporteer als CSV"
    Browser->>User: dialog: vul reden in
    User->>Browser: reden = "backup voor migratie naar 1Password"
    Browser->>API: POST /vault/{id}/audit-export {format: csv, reason: ...}
    API->>DB: INSERT audit_log (export_csv, reason=...)
    API-->>Browser: 200 {audit_id, allowed}
    Browser->>User: ROOD-confirm-dialog "ALLE wachtwoorden ONVERSLEUTELD downloaden?"
    User->>Browser: bevestig
    Browser->>Browser: kdbxweb.toJson() → csv-formatter
    Browser->>Browser: trigger download (Blob + URL.createObjectURL)
    Browser-->>User: bestand wordt gedownload
    Note over Browser: server ziet plaintext NIET
```

## SQ-7 — Clipboard-copy met 10s wipe

```mermaid
sequenceDiagram
    actor User
    participant Browser

    User->>Browser: klik "📋 kopieer pw"
    Browser->>Browser: navigator.clipboard.writeText(pw)
    Browser->>User: visuele 10s aftelling
    Note over Browser: timer pauzeert bij tab-blur
    Browser->>Browser: na 10s: navigator.clipboard.writeText("[HorseSafe wiped]")
    Browser->>User: aftelling klaar
    Note over Browser: best-effort; v0.2 extensie = echte wipe
```
