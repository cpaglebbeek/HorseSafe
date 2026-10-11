# SEQUENCE_DIAGRAMS.md — HorseSafe

> Mermaid-flows voor belangrijke operaties. Cross-ref: `ARCHITECTURE.md §2.4-2.7`. SQ-9 t/m SQ-12 (v0.2.0-Koblitz) volgen het bindende contract `docs/HARDWARE_KEYS.md` §12.

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

> v0.2.0-Koblitz: de link gaat via de generieke SMTP-mailer (`mail_service`, 587 STARTTLS, From = SMTP-gebruiker). Gmail SMTP_SSL 465 is alleen fallback (werkt niet op HC55).

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant DB
    participant Mailer as mail_service (to_thread)
    participant Mail as SMTP 587 STARTTLS

    User->>Browser: email
    Browser->>API: POST /auth/magic-link {email}
    API->>DB: SELECT users WHERE email
    DB-->>API: user (of NULL)
    API->>DB: INSERT magic_links (token, user_id, exp=10min)
    API->>Mailer: send_async(to, onderwerp, link ".../mfa.html#ml=<token>")
    Mailer->>Mail: EHLO, STARTTLS, LOGIN, SEND
    Mail-->>User: e-mail met link
    API-->>Browser: 202 "indien email bestaat, link verzonden"

    User->>Browser: klik link (webmail = cross-site: Strict-cookie gaat niet mee)
    Browser->>Browser: laad mfa.html#ml=<token>, haal token uit adresbalk
    Browser->>API: POST /auth/magic-link/redeem {t} (same-site fetch, mét sessie-cookie)
    API->>API: sessie-cookie van dezelfde gebruiker? (anders 403 magic_link_login_first, niet verbruikt)
    API->>DB: SELECT magic_links WHERE token, exp>now, redeemed_at IS NULL
    DB-->>API: row
    API->>DB: UPDATE magic_links SET redeemed_at=now
    API->>API: set JWT-cookie (mfa_passed=true)
    API-->>Browser: 200 {ok}
    Browser->>Browser: naar vault.html
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

## SQ-8 — Per-entry TOTP-render-loop (v0.0.9-Bellare+)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant WebCrypto as crypto.subtle (browser-native)

    User->>Browser: klik entry-rij in vault-content
    Browser->>Browser: selectEntry(entry)
    Browser->>Browser: entry.otp = fields.get('otp') — check op otpauth:// URI
    alt entry.otp aanwezig
        Browser->>Browser: stopTotpLoop() (oude interval clearen)
        Browser->>Browser: show d-totp-label + d-totp-cell
        Browser->>Browser: startTotpLoop(uri) — setInterval(renderTotpOnce, 1000)
        loop elke 1s
            Browser->>Browser: HorseSafeTotp.generateTotp(uri)
            Browser->>Browser: parseOtpauth(uri) → {secret, digits, period, algo}
            Browser->>Browser: base32Decode(secret) → keyBytes
            Browser->>Browser: counter = floor(now/period) → 8-byte BE buffer
            Browser->>WebCrypto: importKey('raw', keyBytes, {HMAC, SHA-1/256/512})
            WebCrypto-->>Browser: HMAC-key
            Browser->>WebCrypto: sign('HMAC', key, counter)
            WebCrypto-->>Browser: sig (Uint8Array 20/32/64 bytes)
            Browser->>Browser: dynamic truncation (RFC 4226) + mod 10^digits
            Browser->>Browser: render #d-totp-code (XXX XXX) + #d-totp-countdown (Ns)
        end
    else entry.otp ontbreekt
        Browser->>Browser: hide d-totp-label + d-totp-cell
        Browser->>Browser: stopTotpLoop()
    end

    User->>Browser: klik 📋 d-totp-copy
    Browser->>Browser: copyTotp() → generateTotp(uri) → navigator.clipboard.writeText(code)
    Browser->>User: button-feedback "✓" (1.5s) → terug naar "📋"

    User->>Browser: klik "Vergrendel vault" of selecteer andere entry
    Browser->>Browser: stopTotpLoop() (interval clearen, geen geheugen-lek)

    Note over Browser,WebCrypto: TOTP-secret + code blijven in browser-RAM. Server zag seed nooit (zat encrypted in KDBX4-blob). Zero-knowledge intact.
```

## SQ-9 — YubiKey koppelen (v0.2.0-Koblitz)

Voorwaarde: vault is open met wachtwoord/keyfile, dus `CK = {ph,kh}` staat in browser-RAM.

```mermaid
sequenceDiagram
    actor User
    participant Browser as Browser (hwkeys.js)
    participant YK as YubiKey Bio
    participant API
    participant DB

    Browser->>API: POST /webauthn/options {purpose:"register", vault_id, kind}
    API->>DB: vault + aantal sleutels + step-up-eis (al een sleutel? dan SU)
    API->>DB: INSERT 2 challenges (register + register_assert), key_id, prf_salt
    API-->>Browser: rp, user, create/assert-challenges, key_id, prf_salt
    Browser->>YK: credentials.create (cross-platform, UV required, attestation direct, prf)
    User->>YK: vinger
    YK-->>Browser: attestation (packed), credential_id
    Browser->>YK: credentials.get (assert-challenge, PRF eval = prf_salt)
    User->>YK: vinger
    YK-->>Browser: assertion + PRF-resultaat
    Browser->>Browser: PRF → HKDF → sk_c/pk_c, sealed = Seal_v2(pk_c, CK, "store", vault_id, key_id)
    Browser->>Browser: zelf openen ter controle, PRF/seed/CK-tussenbuffers fill(0)
    Browser->>API: POST /vault/{vid}/keys {key_id, kind, label, create, assert, public_key, sealed}
    API->>DB: challenges atomair verbruiken
    API->>API: attestation (Yubico-root), AAGUID-allowlist, origin, rpId, UP/UV, BE=0/BS=0, alg
    API->>API: assertion met nieuwe publieke sleutel, validate_sealed (alleen vorm)
    API->>DB: INSERT vault_keys (één transactie)
    API->>DB: audit vault_key_add (pas na verificatie)
    API-)User: mail "nieuwe sleutel gekoppeld" (to_thread, niet-blokkerend)
    API-->>Browser: 201 sleutelobject
    Note over API: Afwijzing in stap 2-6 → audit vault_key_add_rejected, geen INSERT
```

## SQ-10 — Ontgrendelen met YubiKey Bio (v0.2.0-Koblitz)

```mermaid
sequenceDiagram
    actor User
    participant Browser as Browser (hwkeys.js)
    participant YK as YubiKey Bio
    participant API
    participant DB

    Browser->>API: GET /vault/{id} → KDBX4-blob + ETag
    Browser->>API: POST /webauthn/options {purpose:"unlock", vault_id}
    API-->>Browser: challenge + allow_credentials [{key_id, credential_id, prf_salt}]
    Browser->>YK: credentials.get (UV required, PRF evalByCredential)
    User->>YK: vinger
    YK-->>Browser: assertion + PRF-resultaat
    Browser->>Browser: fail-closed: UV=1, BE=0, getAuthenticatorData, prf.results.first
    Browser->>API: POST /vault/{vid}/keys/{kid}/unlock {challenge_id, assertion}
    API->>DB: challenge verbruiken
    API->>API: origin/rpId/UP/UV/BE + handtekening + signCount
    alt signCount gedaald
        API->>DB: audit vault_key_clone_suspect
        API-)User: mail "verdachte sleutel-teller"
        API-->>Browser: 409 sign_count_regression
    else geldig
        API->>DB: last_used_at, sign_count, audit vault_key_unlock
        API-->>Browser: 200 {id, sealed}
        Browser->>Browser: PRF → sk_c, pk_c == public_key?, Seal_v2 openen met eigen AAD → {ph,kh}
        Browser->>Browser: credentialsFromHashes → Kdbx.load(blob)
        alt InvalidKey
            Browser-->>User: "Kopie verouderd. Ontgrendel één keer met wachtwoord/keyfile en klik Bijwerken."
        else ok
            Browser-->>User: entries
        end
    end
```

## SQ-11 — Noodsleutel: vrijgave, gebruik en blokkade (v0.2.0-Koblitz)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant API
    participant DB
    participant Mailer as mail_service

    User->>Browser: "Vrijgave noodsleutel aanvragen"
    Browser->>API: POST /vault/{vid}/keys/{kid}/release
    alt geblokkeerd
        API-->>Browser: 409 recovery_blocked
    else geen mailer geconfigureerd
        API-->>Browser: 503 notify_unavailable
    else
        API->>DB: release_requested_at=nu, release_at=nu+24u (commit, verbinding dicht)
        API->>Mailer: "vrijgave noodsleutel aangevraagd" (resultaat afwachten)
        alt mail mislukt
            API->>DB: vrijgave terugdraaien, audit notify_failed
            API-->>Browser: 503 notify_failed
        else mail verstuurd
            API->>DB: audit recovery_release_request
            API-->>Browser: 200 (state waiting)
        end
    end
    Note over User,API: Binnen 24 u: annuleren (DELETE …/release) of blokkeren (POST …/block, zonder step-up)
    Note over Browser,API: Na 24 u, binnen 24 u venster: SQ-10 met de noodsleutel + PIN van 63 tekens
    API->>DB: release_consumed_at=nu, audit recovery_key_used
    API-)User: mail "noodsleutel gebruikt"

    User->>Browser: "Blokkade opheffen"
    Browser->>API: DELETE /vault/{vid}/keys/{kid}/block
    alt geen step-up
        API-->>Browser: 403 stepup_required → SQ-12
    else step-up met TOTP
        API-->>Browser: 403 stepup_bio_required
    else Bio-step-up geldig
        API->>DB: status=active, blocked_at=NULL, audit recovery_unblock
        API-)User: mail "blokkade noodsleutel opgeheven"
        API-->>Browser: 200 (state idle)
    end
```

## SQ-12 — Step-up en rekey (v0.2.0-Koblitz)

```mermaid
sequenceDiagram
    actor User
    participant Browser as Browser (stepup.js + hwkeys.js)
    participant YK as YubiKey Bio
    participant API
    participant DB

    Browser->>API: actie die SU vraagt (bv. PUT /vault/{vid}/rekey)
    API-->>Browser: 403 stepup_required
    Browser->>API: POST /webauthn/options {purpose:"stepup"}
    alt geen actieve Bio-sleutel
        API-->>Browser: 409 no_bio_keys
        User->>Browser: TOTP-code
        Browser->>API: POST /auth/stepup {method:"totp", code}
    else
        API-->>Browser: challenge + allow_credentials
        Browser->>YK: credentials.get (UV)
        User->>YK: vinger
        Browser->>API: POST /auth/stepup {method:"bio", assertion}
    end
    API->>API: verifiëren, JWT opnieuw met stepup_until=nu+300, stepup_method
    API->>DB: audit stepup
    API-->>Browser: 200 + nieuw cookie

    Note over Browser: Rekey: nieuwe KDBX4 met nieuw pw/keyfile, per sleutel Seal_v2(pk_c, CK_nieuw) — YubiKeys niet nodig
    Browser->>API: PUT /vault/{vid}/rekey (multipart blob + sealed-items, If-Match)
    API->>API: SU, If-Match (428), grootte (413), ids == actuele sleutels (409 keys_mismatch), validate_sealed, etag (412)
    API->>DB: BEGIN IMMEDIATE, UPDATE alle sealed, UPDATE vaults, blob atomair schrijven, COMMIT
    API->>DB: audit vault_rekey
    API-)User: mail "wachtwoord of keyfile van je kluis gewijzigd"
    API-->>Browser: 200 {vault, resealed} + ETag
```
