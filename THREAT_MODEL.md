# THREAT_MODEL.md — HorseSafe

> STRIDE-analyse + zero-knowledge bewijslast + bekende beperkingen.

## Aannames

- Gebruiker draait HorseSafe in een moderne browser (Chrome/Edge/Firefox/Safari recent)
- Gebruiker heeft controle over zijn eigen device (geen evil-maid / keylogger)
- Gebruiker kent zijn master-pw en bewaart keyfile veilig (USB/printout/separate device)
- HC55-server kan gecompromitteerd raken (worst case in dit model)
- TLS staat aan en valide cert (LE auto-renew)

## STRIDE-matrix

| Categorie | Dreiging | HorseSafe mitigatie |
|---|---|---|
| **S** Spoofing | Aanvaller logt in als user | MFA (magic-link OF TOTP). Failed-login throttle. JWT-binding aan IP+UA optioneel (v0.1). |
| **S** Spoofing | Phishing-site doet zich voor als HorseSafe | HSTS + CSP + browser-extensie URL-check (v0.2). User-education in onboarding. |
| **T** Tampering | Server vervangt vault-blob met malicious content | KDBX4 heeft HMAC-integriteit ingebouwd. Mismatch → kdbxweb weigert decryptie. |
| **T** Tampering | MitM tussen browser en server | TLS 1.3 + HSTS + cert-pinning (v0.2 via extensie). |
| **T** Tampering | Server muteert audit-log | Append-only file naast SQLite-tabel; nightly hash-chain naar storagebox. |
| **R** Repudiation | User ontkent export-actie | Audit-log + reden-veld + IP + UA. |
| **I** Information disclosure | Server-disk-dump lekt vault | **Vault = KDBX4-ciphertext**. Zonder master-key niet ontsleutelbaar. |
| **I** Information disclosure | Server-RAM-dump lekt sessie-data | Server kent nooit master-key. RAM kan JWT-cookies bevatten → session-hijack mogelijk → mitigatie: korte JWT-TTL + sliding window + cookie-rotation. |
| **I** Information disclosure | Browser-RAM-dump lekt master-key | Threat-actor heeft device-toegang → outside scope. Mitigatie: vault-auto-lock na 5 min inactiviteit. |
| **I** Information disclosure | Clipboard lekt pw naar andere app | 10s wipe (best-effort). v0.2 = extensie wipe (échte). |
| **I** Information disclosure | Telemetrie lekt entry-titels | Geen telemetrie naar third-party. Eigen audit-log enkel server-side. |
| **D** Denial of service | Aanvaller spamt magic-link aanvragen | Rate-limit per e-mail (3/uur) + per IP (10/uur). |
| **D** Denial of service | Aanvaller uploadt gigantische blobs | `client_max_body_size 50M` in nginx + backend-check op KDBX4-header. |
| **E** Elevation of privilege | Normale user wordt admin | `is_admin` is server-DB-flag, alleen gezet via directe DB-actie (geen UI). Admin-route check op JWT-claim. |
| **E** Elevation of privilege | User leest andermans vault | `/vault/{id}` check: `vaults.user_id == jwt.user_id`. Test in CI. |

## Zero-knowledge bewijs (formeel)

**Stelling:** een aanvaller met **volledige server-toegang** (root, alle disk, alle DB-content, alle code, ongelimiteerd CPU) kan **geen** vault-inhoud reconstrueren.

**Bewijs:**

1. Vault-content wordt **uitsluitend in browser** geserialiseerd naar KDBX4 + geëncrypteerd.
2. De master-key (= composiet van master-pw + keyfile via KeePassXC-formule) wordt **uitsluitend in browser-RAM** geconstrueerd.
3. De master-key wordt **nooit** naar de server gestuurd (audit: alleen `/vault/{id}`-uploads van pure KDBX4-bytes; geen apart key-veld in request-body of header).
4. De server slaat enkel de KDBX4-blob op (= ciphertext + KDF-parameters + HMAC).
5. KDBX4 gebruikt AES-256 of ChaCha20 met sleutel = Argon2id(master-key, salt, t, m, p) waar t=12, m=128 MiB, p=2.
6. **Argon2id is memory-hard**: brute force op random 64-bit-equivalente master-key kost ~2^64 × 128 MiB-passes ≈ 10^25 J ≈ 3.16 × 10^17 jaar bij Landauer-limiet voor de hele wereld-energieproductie.
7. **Conclusie:** zonder client-side master-key is decryptie computationeel onhaalbaar. QED.

**Caveats:**

- Bewijs faalt als master-pw zwak is (bv. < 60 bits entropie) → user-education verplicht in S3.
- Bewijs faalt bij client-side compromise (malware op browser-host) → outside scope.
- Bewijs faalt als kdbxweb-implementatie buggy is → mitigatie: CI round-trip test met KeePassXC-desktop als oracle.

## Vault-content vs. metadata

| Type data | Server-zichtbaarheid |
|---|---|
| Entry-titel | ❌ ciphertext binnen KDBX4 |
| Username | ❌ ciphertext |
| Password | ❌ ciphertext |
| URL | ❌ ciphertext |
| Notes | ❌ ciphertext |
| Attachments | ❌ ciphertext |
| Entry-aantal | ❌ ciphertext (zit in KDBX-body) |
| **Vault-bestandsnaam** | ✅ (vaults.name = "default" of user-gekozen — **let op**, gebruiker mag gevoelige string kiezen) |
| **Vault-grootte (bytes)** | ✅ (size_bytes) — indirect verklikt entry-aantal |
| **Update-tijdstip** | ✅ (updated_at) — verklikt activiteit |
| Account-e-mail | ✅ (users.email — onvermijdelijk voor magic-link) |
| Account-pw | ❌ (argon2id-hash op server) |
| TOTP-secret | ⚠️ plaintext base32 op server (RFC 6238 noodzaak) — beschermt alleen account-laag |
| Magic-link token | ⚠️ tijdelijk plaintext server-RAM/DB tot redemption |

**Risico-acceptatie:** metadata-lekage (vault-grootte, update-tijdstip) is bewust geaccepteerd. Gebruiker wordt geïnformeerd in onboarding.

## Bekende beperkingen v0.0.x

1. **Browser clipboard-wipe = best-effort.** Werkt alleen bij tab-focus. Extensie (v0.2) lost dit op.
2. **MFA-secret server-side plaintext.** Onvermijdelijk voor TOTP-verificatie. Mitigatie: PBKDF2-encrypted-at-rest met server-master-key (uit env-var, niet in repo).
3. **Geen sharing tussen users.** v0.0.x = solo. v0.2.x = re-encryptie per ontvanger met diens publieke key.
4. **Geen offline-modus.** Vault-toegang vereist server-bereikbaarheid. v0.1.x = ServiceWorker-cache van laatste blob voor read-only offline.
5. **Geen hardware-token (FIDO2/WebAuthn).** v0.3.x. FIDO2 zou MFA-flow versterken.
6. **Magic-link via Gmail = single-vendor risk.** Bij Gmail-storing: TOTP-fallback verplicht.
7. **Single-device locking in v0.0.x.** Gelijktijdige edits op twee devices → conflict-merge in v0.1.x.

## Dreigingen waar HorseSafe NIET tegen beschermt

- Malware op user-device (keylogger, screen-grabber)
- Side-channel attacks op WebCrypto in browser
- Quantum-computer attacks op AES-256 (post-2040+ overweging)
- Coercion ("rubber-hose cryptanalysis")
- Lekken via Argon2-cache-timing in shared-hosting scenario (n/a voor HC55 dedicated)

## Compliance-implicaties

- **GDPR** Artikel 32: pseudonimiserings- en versleutelings-eis = ruim voldaan (zero-knowledge gaat verder dan GDPR-minimum)
- **NIS2** voor latere dienst-aanbieding: documentatie voldoet aan Artikel 21 lid 2(h) "encryption policies"
- **DPA-template** voor zakelijke klanten: leverbaar (zero-knowledge = beperkte verwerkersrol)
