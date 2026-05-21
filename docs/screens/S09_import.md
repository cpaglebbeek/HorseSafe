# S9 — Import wizard

**Route:** `/HorseSafe/import.html`
**Auth-eis:** JWT + mfa=true
**Doel:** entries uit externe bron in HorseSafe-vault mergen
**Doelgroep:** user die KeePass/KeePassXC/Bitwarden/CSV-data wil migreren

## Componenten

### Stap 1: Bron + wachtwoorden
- Format-select: KDBX3/4 / Bitwarden JSON / KeePass-CSV (XLSX uitgesteld)
- File-upload (geen size-limit aan client-zijde; backend doet 50MB op upload-PUT)
- KDBX-wachtwoord (alleen bij KDBX-import)
- HorseSafe vault-wachtwoord (vereist)
- Conflict-strategie: **skip** / **overschrijf** / **dupliceer-met-suffix**

### Stap 2: Preview-tabel
- Eerste 100 entries getoond (Title + Username + URL)
- "… en N meer" als overshoot
- Count-indicator
- Bevestig-knop → merge + upload + audit-stamp

## Flow

| Stap | Doel | Outcome |
|---|---|---|
| Submit form | Parse client-side + load vault | preview-section tonen |
| Klik "Bevestig" | mergeEntriesInto(strategie) → kdbxweb.save() → PUT /vault/{id} | upload + audit-stamp + redirect vault.html |

## Zero-knowledge

- **Bestand wordt UITSLUITEND in browser geparseerd**.
- Server ziet alleen de uiteindelijke encrypted KDBX-blob via PUT.
- Audit-stamp via POST `/vault/{id}/audit-import` `{format, count}` registreert event + count zonder content.

## Bron-formaten

| Format | Detector | Vereisten |
|---|---|---|
| KDBX3/4 | kdbxweb.Kdbx.load() | KDBX-wachtwoord vereist |
| Bitwarden JSON | parseBitwardenJson() | `encrypted: false` + `items[]`-array |
| KeePass-CSV | parseKeePassCsv() | Header met "Title" + "Password" verplicht |

## Audit-events

- `import_kdbx`, `import_bitwarden`, `import_csv` (per format)
- `detail`: `{vault_id, count}`

## Niet in v0.0.5

- XLSX → v0.0.7+
- 1Password .1pif → wachten op user-request
- LastPass CSV → bestaande CSV-parser kan dit aan (zelfde kolomnamen)

## Bron

- `UI_DESIGN.md` § S9
- `frontend/import.html` + `frontend/js/import-export.js`
- `API.md` § /vault/{id}/audit-import
