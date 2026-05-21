# ROADMAP.md — HorseSafe

> Versie-volgorde + planning. Cross-ref: `ACTIONS.md`, `CHANGELOG.md`.

## Codenamen-thema: Cryptografen

Beschikbare namen (in chronologische volgorde van bijdrage):
Rijndael (Daemen+Rijmen), Diffie, Hellman, Merkle, Rivest, Shamir, Adleman, Lai, Massey, Schneier, Daemen, Rijmen, Bellare, Rogaway, Krawczyk, Bernstein, Lange, Aumasson, Kelsey, Hutchison, ...

## Releases

### v0.0.0-Rijndael — 2026-05-21 ✅
Skeleton + ontwerp-documenten. Geen code.

### v0.0.1-Diffie — gepland Fase 1
Backend FastAPI-skeleton met `/auth/register`, `/auth/login`, `/vault` GET/POST/PUT/DELETE (geen MFA). SQLite-init. Geen deploy, alleen lokaal `uvicorn`. Tests: pytest + httpx.

### v0.0.2-Hellman — gepland Fase 2
Frontend POC met kdbxweb. Login + lege vault aanmaken + 1 entry tonen. Vanilla ES2022. Lokaal serveerbaar via `python -m http.server`.

### v0.0.3-Merkle — gepland Fase 3
MFA-integratie. TOTP-setup-flow + magic-link bridge naar iCt_Horse. End-to-end auth-laag werkend.

### v0.0.4-Rivest — gepland Fase 4
Admin-pagina. User-CRUD + stats + audit-viewer. Pas activeerbaar voor `is_admin=true`.

### v0.0.5-Shamir — gepland Fase 5
Import KDBX3/4 + Bitwarden JSON. Export KDBX + CSV + JSON + XLSX. Audit-log + reden-veld voor plaintext.

### v0.0.6-Adleman — gepland Fase 6
CI-pipeline. GitHub Actions: ruff + black + mypy + pytest + playwright. KDBX-roundtrip-oracle-test (kdbxweb-write → keepassxc-cli-read).

### v0.0.7-Lai — gepland Fase 7
Pen-test interne ronde (Christian + Hofstra-team eventueel). Bug-fixes uit pen-test rapport.

### v0.1.0-Massey — gepland milestone
Eerste publieke release. URL switch naar `icthorse.nl/HorseSafe/`. Documentatie public-ready. **Beslis-moment open-source** (default-voorstel: AGPL-3.0).

### v0.2.0-Schneier — gepland uitbreiding
Browser-extensie (Chrome + Edge MV3). Echte clipboard-wipe + autocomplete + URL-pinning.

### v0.2.1-Daemen — meerdere vaults per user
Vault-naamgeving in UI + vault-switcher.

### v0.3.0-Rijmen — sharing
Vault-sharing tussen users via re-encryptie. Vereist asymmetrische key-pair per user.

### v0.4.0-Bellare — offline-modus
ServiceWorker-cache laatste vault-blob. Read-only offline.

### v0.5.0-Rogaway — FIDO2/WebAuthn
Hardware-token MFA-laag.

### v1.0.0-Bernstein — productie-ready
Volledig getest, gepenetreerd, gedocumenteerd, AGPL-3.0 public. Marketing-post `icthorse.nl/diensten`.

## Buiten roadmap (research)

- Mobile-app (iOS/Android) — wrapper of native
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
- Web-only zonder offline — al gepland v0.4 ❌

## Beslis-momenten

| Moment | Beslissing |
|---|---|
| Bij v0.0.7 | Pen-test passed → ja/nee voor v0.1.0 |
| Bij v0.1.0 | Open-source ja/nee + licentie |
| Bij v0.2.0 | Chrome Web Store dev-account vereist (€5) |
| Bij v0.3.0 | Pricing-model dienst (gratis tier? betaald?) |
| Bij v1.0.0 | DPA-template gereed; eerste B2B-pilot? |
