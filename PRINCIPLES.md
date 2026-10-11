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
| P-CRYPT-09 | **Verzegelde ontgrendelkopie naar gebruikershardware** (v0.2.0-Koblitz+, besluit 10-10-2026) | De server mag een kopie van het ontgrendelmateriaal alleen bewaren als die verzegeld is naar een publieke sleutel per credential. Het privédeel bestaat alleen in hardware van de gebruiker: YubiKey-PRF of een biometrie-gebonden Android Keystore-sleutel. De server kan zo'n kopie aantoonbaar niet openen. De inhoud is `{ph,kh}` en nooit het leesbare wachtwoord of de keyfile. **Uitwerking:** Seal_v2 (X25519 + HKDF-SHA256 + AES-256-GCM, AAD gebonden aan versie, purpose, vault_id en key_id); de server controleert alleen de vorm (`validate_sealed`) en geeft een kopie pas vrij na een server-geverifieerde WebAuthn-assertion met UV=1 en BE=0. P-CRYPT-01 en P-CRYPT-06 blijven gelden: de kopie is bezit van de gebruiker, de server bewaart hem alleen. De KDBX4-basis (pw + keyfile, KeePassXC-noodroute) blijft ongewijzigd. Zie `docs/HARDWARE_KEYS.md` §1, §2 en §12.5. |

## P-AUTH — Authenticatie

| ID | Principe | Constraint |
|---|---|---|
| P-AUTH-01 | **Twee onafhankelijke lagen** | Account-laag (server kent) ≠ vault-laag (alleen client kent). Hack van laag 1 ≠ toegang tot laag 2. |
| P-AUTH-02 | **MFA verplicht voor vault-toegang** | Geen vault-access zonder MFA-pass (magic-link OF TOTP). |
| P-AUTH-03 | **Argon2id voor account-pw** | Account-pw-hashing met argon2id. |
| P-AUTH-04 | **JWT in HttpOnly cookie** | JWT nooit in localStorage of JS-bereik. SameSite=Strict + Secure. |
| P-AUTH-05 | **Failed-login throttle** | Max 5 / 15 min per IP en per account. |
| P-AUTH-06 | **Magic-link single-use 10 min** | Tokens 256-bit URL-safe, eenmalig verzilverbaar, max 10 min geldig. |
| P-AUTH-07 | **Step-up voor uitbreidende sleutelacties** (v0.2.0-Koblitz+) | Een tweede of volgende sleutel koppelen, opnieuw verzegelen en rekey vragen een verse step-up (YubiKey Bio; TOTP alleen zolang er geen actieve Bio-sleutel is), 300 s geldig. Defensieve acties (blokkeren, verwijderen, vrijgave annuleren) vragen geen step-up maar worden gemeld en gelogd. Een noodsleutel-blokkade opheffen kan alleen met Bio-step-up, met een Bio die al gekoppeld was vóór de blokkade. TOTP-step-up heeft 24 u afkoeltijd na het verwijderen van een Bio of het instellen van TOTP met bestaande sleutels; een TOTP-secret vervangen kan alleen na uitschakelen met de huidige code. Zie `docs/HARDWARE_KEYS.md` §12.8. |
| P-AUTH-08 | **Alleen device-bound hardware-sleutels** (v0.2.0-Koblitz+) | WebAuthn-sleutels alleen met UV=1, BE=0/BS=0, `packed`-attestation tot een Yubico-root en een AAGUID uit de allowlist. Gesynchroniseerde passkeys, Windows Hello en Touch ID worden door de server geweigerd. |

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
| P-UX-02 | **Clipboard-wipe expliciet** | 10s aftellen visueel + best-effort overschrijf. Échte wipe via de browserextensie (Schneier, na de Koblitz-Lange-reeks). |
| P-UX-03 | **Plaintext-export vereist reden** | CSV/JSON/XLSX-export = reden-veld verplicht + confirm-dialog + audit-log. |
| P-UX-04 | **Disaster-recovery in UI** | "Download mijn vault als KDBX4" = altijd één-klik. Werkt zelfs als HorseSafe offline gaat. |
| P-UX-05 | **Keyboard-shortcuts KeePassXC-compat** | Ctrl+B/C/U conform KeePassXC. |
| P-UX-06 | **Dark-theme default** | Less light-leakage; user kan switchen. |

## P-OPS — Operationeel

| ID | Principe | Constraint |
|---|---|---|
| P-OPS-01 | **Shared-infra check vóór nginx-edit** | Bij élke wijziging aan HC55 nginx: eerst `Meta_Master/SHARED_INFRASTRUCTURE.md`. |
| P-OPS-02 | **Versie-bump verplicht** | Elke functionele commit = +0.0.1 minimaal. Geen build zonder version-update. |
| P-OPS-03 | **Codenaam Cryptografen** | v0.0.x = Rijndael. Daarna: Diffie, Hellman, Rivest, Shamir, Adleman, Bellare, Rogaway, Massey (v0.1.0). Vastgesteld 10-10-2026: v0.2.0 Koblitz, v0.3.0 Miller, v0.4.0 Montgomery, v0.5.0 Lange; daarna Schneier e.v. (zie `ROADMAP.md`). |
| P-OPS-04 | **Auto git commit + push** | Conform Gemini_Projects/CLAUDE.md. |
| P-OPS-05 | **Session-MD per sessie** | `prompts/YYYY-MM-DD_<slug>.md` met RESUME-frontmatter. |
| P-OPS-06 | **WhatIf vóór actie** | Plan + impact + akkoord vóór destructieve of architecturele wijziging. |
| P-OPS-07 | **Geen noodsleutel zonder meldkanaal** (v0.2.0-Koblitz+) | Mail loopt via de generieke SMTP-mailer (`HORSESAFE_SMTP_*`, poort 587 STARTTLS, From = SMTP-gebruiker). Is er geen mailer geconfigureerd, dan weigert de server een noodsleutel-vrijgave (503 `notify_unavailable`); mislukt de melding, dan wordt de vrijgave teruggedraaid (503 `notify_failed`). SMTP-gegevens staan alleen in `/opt/horsesafe/.env`, nooit in code, docs of logs. |

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
- ❌ Server-side opslag van master-pw of keyfile in een vorm die de server kan openen (ook niet versleuteld met een serversleutel). Enige uitzondering: P-CRYPT-09 (verzegeld naar gebruikershardware; inhoud `{ph,kh}`, nooit leesbaar pw/keyfile)
- ❌ Opheffen van een noodsleutel-blokkade met alleen wachtwoord of TOTP (alleen step-up met YubiKey Bio, vanaf Miller ook telefoonvinger)
- ❌ Crypto "outsourcen" naar third-party API
- ❌ Telemetrie die vault-content of metadata-content lekt (entry-titels, URLs)
- ❌ Plaintext-export zonder reden + confirm + audit
- ❌ Productie-deploy zonder /sanitycheck groen
