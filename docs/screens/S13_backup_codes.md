# S13 — Backup-codes show-once

**Route:** `/HorseSafe/backup-codes.html`
**Auth-eis:** JWT + (eventueel mfa, niet hard vereist voor /generate)
**Doel:** 10 backup-codes show-once aan user + ack-flow
**Doelgroep:** user met TOTP ingeschakeld die fallback wil

## Flow

### Pane 1: "Genereer"
- Tekst + warning over single-show + vervangt eerdere codes
- Knop "Genereer 10 codes" → POST `/auth/backup-codes/generate`
- Confirm: "Hierdoor worden eerder gegenereerde codes ongeldig. Doorgaan?"

### Pane 2: "Show"
- 10 codes in 2x5 grid, monospace font
- Warning-box: "wordt MAAR ÉÉN KEER getoond"
- Checkbox-acknowledge VERPLICHT: "Ik heb de 10 codes veilig opgeslagen..."
- "📋 Kopieer alle codes" knop
- "Bevestig + verberg permanent" knop (disabled tot ack-checked)
- Reload-warning via `beforeunload` zolang codes onthouden + niet bevestigd

## Constraints

- **Show-once**: na "bevestig" navigeert user naar settings.html; codes zijn weg uit browser-RAM
- **Geen "toon nogmaals"** endpoint
- **Codes bcrypt-hashed at-rest** (server kan ze niet teruglezen)
- **Single-use redemption**: bij gebruik via mfa.html backup-code-tab gemarkeerd als `used_at`

## Errors
| HTTP | UI |
|---|---|
| 401 | Redirect `login.html` |
| 500/anders | Alert met error-detail |

## Bron
- `UI_DESIGN.md` § S13
- `API.md` § /auth/backup-codes/{generate,verify}
- `services/backup_codes_service.py` (bcrypt + lookup-alphabet)
- `frontend/backup-codes.html` + `frontend/js/backup-codes.js`
