# PRINCIPLES.md — HorseSafe

> Ontwerpbeginselen + dwingende constraints. Genummerd voor verwijzing in commits + sessie-MD's.

## P-CRYPT — Cryptografie

| ID | Principe | Constraint |
|---|---|---|
| P-CRYPT-01 | **Zero-knowledge server** | Server ziet master-pw, keyfile of derived-key NOOIT. |
| P-CRYPT-02 | **KDBX4-compat** | Vault-format = KeePass KDBX4. Export = native KDBX4. Disaster-recovery = open in KeePassXC-desktop. |
| P-CRYPT-03 | **Argon2id KDF** | Memory-hard KDF, t=12, m=128 MiB, p=2 (KeePassXC-default). Lager = blocker. |
| P-CRYPT-04 | **AEAD voor blobs** | KDBX4 AEAD-mode (AES-256-CBC+HMAC of ChaCha20+Poly1305-impliciet). Geen CBC zonder MAC. |
| P-CRYPT-05 | **Crypto in browser** | Alle vault-encryptie/-decryptie in browser via `kdbxweb` + libargon2-wasm. Geen server-fallback. |
| P-CRYPT-06 | **Geen key-escrow** | Geen "master-key herstel" via server, e-mail of secondary account. Verlies = data weg. |
| P-CRYPT-07 | **Keyfile-format-default = 64-hex-char ASCII** (v0.0.9-Bellare+) | HorseSafe genereert keyfiles in KeePass 1.x-spec-pad (64 hex chars ASCII, decodeert naar 32 bytes interne hash). **Reden**: kdbxweb 2.1.1 browser-side faalt op KeePassXC 2.x XML keyfiles + op 32-byte raw keyfiles met `InvalidKey`, terwijl Node-side en pykeepass beide werken (zie HS-BUG-005 RCA). 64-hex-ASCII gebruikt `hexToBytes` in alle runtimes → consistent. Import van XML 2.0 en 32-byte raw via lokale Node-resave vóór upload is **toegestaan**, niet als generate-default. KeePassXC-desktop accepteert 64-hex-ASCII zonder issue → P-CRYPT-02 disaster-recovery garantie intact. |
| P-CRYPT-08 | **Per-entry TOTP client-side** (v0.0.9-Bellare+) | TOTP-seeds in vault-entries (custom-field `otp` met `otpauth://`-URI, KeePassXC-compat) blijven binnen encrypted KDBX4-blob. RFC 6238-codes worden client-side berekend via `crypto.subtle.sign('HMAC')` in `frontend/js/totp.js`. Server ziet seed NOOIT — niet bij vault-storage (encrypted blob) en niet bij code-generatie (browser-only). Fundamenteel anders dan account-laag TOTP-MFA (server-side `users.totp_secret` voor login). |

## P-AUTH — Authenticatie

| ID | Principe | Constraint |
|---|---|---|
| P-AUTH-01 | **Twee onafhankelijke lagen** | Account-laag (server kent) ≠ vault-laag (alleen client kent). Hack van laag 1 ≠ toegang tot laag 2. |
| P-AUTH-02 | **MFA verplicht voor vault-toegang** | Geen vault-access zonder MFA-pass (magic-link OF TOTP). |
| P-AUTH-03 | **Argon2id voor account-pw** | Account-pw-hashing met argon2id. |
| P-AUTH-04 | **JWT in HttpOnly cookie** | JWT nooit in localStorage of JS-bereik. SameSite=Strict + Secure. |
| P-AUTH-05 | **Failed-login throttle** | Max 5 / 15 min per IP en per account. |
| P-AUTH-06 | **Magic-link single-use 10 min** | Tokens 256-bit URL-safe, eenmalig verzilverbaar, max 10 min geldig. |

## P-DATA — Dataopslag

| ID | Principe | Constraint |
|---|---|---|
| P-DATA-01 | **Geen plaintext credentials op server** | Disk, RAM-dump, DB-dump: nooit master-pw, vault-content of keyfile. |
| P-DATA-02 | **Filesystem isolation** | Vault-blobs op disk: `chmod 600`, eigenaar `horsesafe`. Backend draait als `horsesafe`, niet root. |
| P-DATA-03 | **Optimistic locking** | PUT /vault/{id} vereist If-Match. Geen blind overschrijven. |
| P-DATA-04 | **Append-only audit** | Audit-log nooit muteren, alleen toevoegen. Apart bestand + DB-tabel. |
| P-DATA-05 | **Backup encrypted** | Nightly rsync naar Hetzner-storagebox. Vault-blobs zijn al ciphertext. |
| P-DATA-06 | **GDPR-conform delete** | Verwijder account = delete users-row + cascading vault-blob-unlinks + audit-anonimisering binnen 30 dagen. |

## P-UX — Gebruikerservaring

| ID | Principe | Constraint |
|---|---|---|
| P-UX-01 | **Wachtwoord nooit zichtbaar zonder klik** | Default-display = bullets. Eye-icon = expliciete actie. |
| P-UX-02 | **Clipboard-wipe expliciet** | 10s aftellen visueel + best-effort overschrijf. v0.2.0 = échte wipe via extensie. |
| P-UX-03 | **Plaintext-export vereist reden** | CSV/JSON/XLSX-export = reden-veld verplicht + confirm-dialog + audit-log. |
| P-UX-04 | **Disaster-recovery in UI** | "Download mijn vault als KDBX4" = altijd één-klik. Werkt zelfs als HorseSafe offline gaat. |
| P-UX-05 | **Keyboard-shortcuts KeePassXC-compat** | Ctrl+B/C/U conform KeePassXC. |
| P-UX-06 | **Dark-theme default** | Less light-leakage; user kan switchen. |

## P-OPS — Operationeel

| ID | Principe | Constraint |
|---|---|---|
| P-OPS-01 | **Shared-infra check vóór nginx-edit** | Bij élke wijziging aan HC55 nginx: eerst `Meta_Master/SHARED_INFRASTRUCTURE.md`. |
| P-OPS-02 | **Versie-bump verplicht** | Elke functionele commit = +0.0.1 minimaal. Geen build zonder version-update. |
| P-OPS-03 | **Codenaam Cryptografen** | v0.0.x = Rijndael. Daarna: Diffie, Hellman, Rivest, Shamir, Adleman, Bellare, Rogaway, Bernstein, ... |
| P-OPS-04 | **Auto git commit + push** | Conform Gemini_Projects/CLAUDE.md. |
| P-OPS-05 | **Session-MD per sessie** | `prompts/YYYY-MM-DD_<slug>.md` met RESUME-frontmatter. |
| P-OPS-06 | **WhatIf vóór actie** | Plan + impact + akkoord vóór destructieve of architecturele wijziging. |

## P-DEV — Ontwikkeling

| ID | Principe | Constraint |
|---|---|---|
| P-DEV-01 | **Type-hints verplicht backend** | Python 3.12 type-hints + Pydantic v2 voor alle FastAPI-routes. |
| P-DEV-02 | **Geen build-step frontend** | Vanilla ES2022 modules. kdbxweb via ESM-import. |
| P-DEV-03 | **CI round-trip test** | Elke build: KDBX4-blob na server-round-trip identiek + opent in KeePassXC. |
| P-DEV-04 | **Coverage 80% backend / 60% frontend** | pytest + playwright. |
| P-DEV-05 | **Lint groen** | ruff + black backend, eslint + prettier frontend. Commit-block bij rode lint. |
| P-DEV-06 | **Geen secrets in repo** | .env in .gitignore. Test-secrets in `tests/fixtures/` met `test_` prefix. |

## Niet-onderhandelbare grenzen

- ❌ Server-side decryptie van vault-content
- ❌ Server-side opslag master-pw of keyfile (zelfs encrypted)
- ❌ Crypto "outsourcen" naar third-party API
- ❌ Telemetrie die vault-content of metadata-content lekt (entry-titels, URLs)
- ❌ Plaintext-export zonder reden + confirm + audit
- ❌ Productie-deploy zonder /sanitycheck groen
