# S6 — Vault unlock (of create)

**Route:** `/HorseSafe/vault.html` (eerste view na login)
**Auth-eis:** JWT (cookie)
**Doel:** ofwel bestaande KDBX-vault openen, ofwel nieuwe vault aanmaken met de eerste keer
**Doelgroep:** ingelogde gebruiker

## Key-messages

- "Voer je **vault-wachtwoord** in. Dit verlaat je browser niet."
- v0.0.2: single-vault per user. Eerste keer → maak aan; latere keer → open.
- v0.0.9-Bellare+: keyfile-input toegevoegd. Wachtwoord óf keyfile is verplicht; beide combineren werkt KeePassXC-compatibel.
- Bij verkeerd wachtwoord/keyfile → "Vault openen mislukt: `<e.code>`. Check pw + keyfile." (vault-ui.js toont nu de exacte kdbxweb-`KdbxError`-code i.p.v. generieke melding sinds v0.0.9-Bellare).

## Componenten

- `<header class="brand">`
- `#unlock-section` (initieel visible) met:
  - `#vault-pw` (type=password, autocomplete=off, minlength=6, **NIET** `required` sinds v0.0.9-Bellare)
  - `#vault-keyfile` (type=file, accept=`.keyx,.key,.keyfile,application/octet-stream`, autocomplete=off) — v0.0.9-Bellare+
  - subtekst muted 0.85em: "Wachtwoord óf keyfile is verplicht. Beide combineren kan ook (KeePassXC-compatibel)."
  - submit + secundair-uitloggen buttons
  - error + status (muted)

## Keyfile-format-restrictie (v0.0.9-Bellare, HS-BUG-005)

| Format | kdbxweb-browser | kdbxweb-Node | pykeepass | KeePassXC-desktop | HorseSafe-advies |
|---|---|---|---|---|---|
| **64-hex-char ASCII** (KeePass 1.x-spec) | ✅ | ✅ | ✅ | ✅ | **DEFAULT — gebruik voor nieuwe vaults** |
| KeePassXC 2.x XML (`<KeyFile><Meta><Version>2.0</Version>...`) | ❌ InvalidKey | ✅ | ✅ | ✅ | Import-only via lokale Node-resave vóór upload |
| 32-byte raw binary | ❌ InvalidKey | ❌ (save/load-inconsistentie) | ✅ | ✅ | Niet gebruiken — kdbxweb-bug |

## Flows

| Stap | Doel | Outcome |
|---|---|---|
| Load page | GET `/vault` (auth-check + list) | 200 lege lijst → "geen vault" pad · 200 met items → "open vault" pad · 401 → redirect S2 |
| Submit (geen vault) | createDatabase(pw) in browser + POST `/vault` | success → S7 onthuld · fail → error-message |
| Submit (vault bestaat) | GET `/vault/{id}` + kdbxweb.load(blob, pw) | success → S7 · fail → "Verkeerd wachtwoord" |
| Klik "Uitloggen" | POST `/auth/logout` | sessie wissen + redirect S1 |

## Crypto-flow (bij CREATE)

1. `kdbxweb.Kdbx.create(credentials, 'default')`
2. `db.header.setKdf(kdbxweb.Consts.KdfId.Aes)` — POC keuze; Argon2id volgt v0.0.3+
3. `db.save()` → ArrayBuffer (KDBX4 ciphertext)
4. `POST /vault` multipart: `name=default` + `blob=<KDBX-bytes>`
5. Bewaar `vault_id` + `etag` in state

## Crypto-flow (bij OPEN)

1. `GET /vault/{id}` → ArrayBuffer
2. `kdbxweb.Kdbx.load(buffer, credentials)` (decryptie volledig client-side)
3. Bewaar `db` + `vault_id` + `etag` in state

## Visuele referentie

`S06_unlock.png` (screenshot volgt).

## Bron

- `UI_DESIGN.md` § S6
- `ARCHITECTURE.md` § 2.4 (vault-open flow)
- `frontend/vault.html`
- `frontend/js/vault-ui.js` `unlockOrCreate()`
- `frontend/js/crypto.js` `createDatabase()` / `openDatabase()`
