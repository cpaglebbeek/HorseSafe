# ROADMAP.md — HorseSafe

> Versie-volgorde + planning. Cross-ref: `ACTIONS.md`, `CHANGELOG.md`.

## Codenamen-thema: Cryptografen

Beschikbare namen (in chronologische volgorde van bijdrage):
Rijndael (Daemen+Rijmen), Diffie, Hellman, Merkle, Rivest, Shamir, Adleman, Lai, Massey, Koblitz, Miller, Montgomery, Lange, Schneier, Daemen, Rijmen, Bellare, Rogaway, Krawczyk, Bernstein, Aumasson, Kelsey, Hutchison, ...

**Herschikking 10-10-2026 (besluit 2, Christian):** v0.2.0 tot en met v0.5.0 worden de hardware-sleutelreeks uit `docs/HARDWARE_KEYS.md` (Koblitz, Miller, Montgomery, Lange; elliptische-krommen-cryptografen, passend bij X25519). Schneier (browserextensie) en de verdere items (Daemen, Rijmen, Bellare, Rogaway, Bernstein) schuiven door. Rogaway (FIDO2/WebAuthn) gaat grotendeels op in Koblitz. Zie §11 van `docs/HARDWARE_KEYS.md`.

> Let op: de 0.0.x-reeks heeft in de praktijk andere namen gekregen dan oorspronkelijk gepland (o.a. 0.0.7 en 0.0.9 Bellare, 0.0.8 Rogaway, 0.0.10 Goldwasser). Die versies staan hieronder zoals ze uitgebracht zijn; de namen Bellare en Rogaway blijven voor de toekomst beschikbaar als volgnaam bij een nieuwe minor.

## Releases

### Uitgebracht

| Versie | Datum | Inhoud |
|---|---|---|
| v0.0.0-Rijndael | 2026-05-21 | Skeleton + ontwerp-documenten |
| v0.0.1-Diffie | 2026-05-21 | Backend FastAPI-skeleton |
| v0.0.2-Hellman | 2026-05-21 | Frontend POC met kdbxweb |
| v0.0.3-Merkle | 2026-05-21 | MFA (TOTP + magic-link) |
| v0.0.4-Rivest | 2026-05-21 | Admin-pagina + backup-codes |
| v0.0.5-Shamir | 2026-05-21 | Import/export + KDBX-roundtrip-oracle |
| v0.0.6-Adleman | 2026-05-21 | Vault-sharing (ECDH-P256) |
| v0.0.7-Bellare | 2026-05-22 | Productie-deploy HC55 |
| v0.0.8-Rogaway | 2026-05-18 | XLSX-import/-export |
| v0.0.9-Bellare | 2026-06-05 | Keyfile vault-open + per-entry TOTP |
| v0.0.10-Goldwasser | 2026-07-20 | Test-rerun + HS-BUG-006 |
| v0.1.0-Massey | 2026-07-20 | Publieke launch, AGPL-3.0 ✅ |

### v0.2.0-Koblitz — hardware-sleutels in het web, server-geverifieerd — IN BOUW
Ontgrendelen met een YubiKey Bio (WebAuthn PRF, UV=1, BE=0) in Chrome/Edge op de laptop. Server verifieert attestation (Yubico-roots + AAGUID-allowlist), UV, BE en signCount (py_webauthn). Verzegelde ontgrendelkopie `{ph,kh}` per sleutel volgens P-CRYPT-09 (Seal_v2). Reserve-YubiKey als noodsleutel met 24 uur wachttijd, blokkeren via het web en opheffen alleen met Bio-step-up. Step-up (`/auth/stepup`), wachtwoord/keyfile wijzigen via `/rekey`, opnieuw verzegelen na een wijziging in KeePassXC. Generieke SMTP-mailer (587 STARTTLS) voor meldingen én magic-link. Migratie 005 (`vault_keys`, `webauthn_challenges`, lege `devices`), schema-versie 5. Contract: `docs/HARDWARE_KEYS.md` §12; acceptatie: §10.

### v0.3.0-Miller — Android-app — gepland
`android/` in deze repo: YubiKey Bio inrichten (PIN van 63 tekens, minimale PIN-lengte, always-uv, vingers inschrijven), telefoon koppelen (QR + SAS), telefoon-credential (`kind='phone'`, Keystore `BIOMETRIC_STRONG`, nooit `DEVICE_CREDENTIAL`), noodsleutel blokkeren/deblokkeren vanaf de telefoon, update in de app via HorseAPK. Meldingen via polling, geen FCM. Migratie 006. Test-emulator `hb-horsesafe`.

### v0.4.0-Montgomery — laptop ontgrendelen via telefoon-QR + vinger — gepland
Goedkeuringsprotocol (laptop toont QR, telefoon keurt goed met vinger, end-to-end verzegeld naar een tijdelijke laptopsleutel; server alleen doorgifte). Ontgrendelen in de app via WebView. Migratie 007 (`approvals`, `revoked_sessions`, JWT-claim `sid`).

### v0.5.0-Lange — native read-only kluis in de app — GEPLAND, NIET BOUWEN
Pas na de veldtest van v0.4 (besluit 7).

### Daarna (doorgeschoven, volgorde en nummering vast te stellen)

- **Schneier** — browserextensie (Chrome + Edge MV3): échte clipboard-wipe, autocomplete, URL-pinning.
- **Daemen** — meerdere vaults per user: vault-naamgeving in UI + vault-switcher.
- **Rijmen** — sharing uitbreiden (re-encryptie per ontvanger; basis staat sinds v0.0.6).
- **Bellare** — offline-modus: ServiceWorker-cache laatste vault-blob, read-only.
- **Rogaway** — FIDO2/WebAuthn als account-MFA (de vault-laag is al gedekt door Koblitz).
- **v1.0.0-Bernstein** — productie-ready: volledig getest, extern gepenetreerd, gedocumenteerd; Argon2id-default; marketing-post `icthorse.nl/diensten`.

## Buiten roadmap (research)

- iOS-app (Android-app staat sinds 10-10-2026 op de roadmap als Miller)
- CLI-tool `horsesafe-cli`
- Yubico OTP / OnlyKey integration
- TOTP-codes binnen vault-entries (KeePassXC-feature)
- Vault-templates (Email, Banking, Social, Work bootstrap)
- Audit-log export voor user
- LDAP/OIDC integratie voor enterprise tenants
- Post-quantum KDF migratie (Argon2id → Kyber-derived)

## Niet op roadmap

- Server-side decryption — schendt zero-knowledge ❌
- "Wachtwoord herstel" via server — schendt zero-knowledge ❌
- Cloud-sync naar Dropbox/iCloud — out of scope ❌
- Web-only zonder offline — offline staat gepland (Bellare) ❌

## Beslis-momenten

| Moment | Beslissing |
|---|---|
| Bij v0.0.7 | Pen-test passed → ja/nee voor v0.1.0 |
| Bij v0.1.0 | Open-source ja/nee + licentie |
| Bij v0.2.0-Koblitz | Veldtest Bio in Chrome op de laptop geslaagd + mail vanaf HC55 aantoonbaar afgeleverd → go voor deploy |
| Bij v0.3.0-Miller | Debug-keystore-ondertekening blijft acceptabel (E8)? |
| Na v0.4.0-Montgomery | Veldtest geslaagd → go/no-go voor v0.5.0-Lange |
| Bij Schneier | Chrome Web Store dev-account vereist (€5) |
| Later | Pricing-model dienst (gratis tier? betaald?) |
| Bij v1.0.0 | DPA-template gereed; eerste B2B-pilot? |
