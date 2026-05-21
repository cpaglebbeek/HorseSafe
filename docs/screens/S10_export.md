# S10 — Export wizard

**Route:** `/HorseSafe/export.html`
**Auth-eis:** JWT + mfa=true
**Doel:** vault-content downloaden in KDBX4 (encrypted) of plaintext (CSV/JSON)
**Doelgroep:** user die migratie, backup of disaster-recovery wil

## Componenten

### Format-select
- **KDBX4 (encrypted)** — aanbevolen; opent in KeePassXC-desktop
- **JSON (Bitwarden-compatibel)** — PLAINTEXT
- **CSV (KeePass-kolommen)** — PLAINTEXT

### Vault-pw
- Vereist voor alle exports (om vault te kunnen decrypteren)

### Reden-veld
- **Alleen bij plaintext** (csv/json/xlsx) — VERPLICHT min 10 chars
- Wordt server-side gevalideerd (HTTP 400 `reason_required`)
- Wordt opgenomen in audit-log

### Plaintext-warning-dialog (rood)
- Activeert bij keuze csv/json na "Exporteer"-klik
- Tekst: "Je staat op het punt ALLE wachtwoorden ONVERSLEUTELD te downloaden..."
- "Begrepen, download nu" (rood) + "Annuleer"

## Flow

| Stap | Doel | Outcome |
|---|---|---|
| Submit form | Validate reden indien plaintext | warning-dialog (plaintext) of direct doExport (kdbx) |
| Confirm-plaintext / kdbx-direct | POST `/vault/{id}/audit-export` `{format, reason}` | server logt event + reden |
| Daarna | kdbxweb.save() of buildCSV/buildJSON + downloadBlob() | bestand downloaded |

## Format-builders

| Format | Output |
|---|---|
| KDBX4 | `kdbxweb.Kdbx.save()` → ArrayBuffer (geëncrypteerd) |
| CSV | Header `Title,Username,Password,URL,Notes` + RFC 4180-quoted data-rijen |
| JSON | Bitwarden-compatibel schema: `{encrypted: false, folders: [], items: [{name, type:1, login:{username,password,uris:[]}, notes}]}` |

## Audit-events

- `export_kdbx` (reden=null)
- `export_csv`, `export_json`, `export_xlsx` (reden verplicht)
- `detail`: `{vault_id}`

## Disaster-recovery via export

KDBX4 export = OPEN STANDAARD. Werkt in:
- KeePassXC-desktop (Windows/macOS/Linux)
- KeePass2 (.NET, Windows)
- KeePassDX (Android)
- Strongbox (iOS/macOS)
- AuthPass (cross-platform)

User kan dus altijd uit HorseSafe stappen — geen vendor lock-in.

## Bron

- `UI_DESIGN.md` § S10
- `frontend/export.html` + `frontend/js/import-export.js`
- `API.md` § /vault/{id}/audit-export
