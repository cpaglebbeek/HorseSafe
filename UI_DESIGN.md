# DESIGN.md — HorseSafe UI/UX

## Schermen

### S1. Public landing `/HorseSafe/`
- Logo + slogan: "Jouw kluis. Niet de onze."
- Login-knop (→ S2)
- Registreer-knop (→ S3)
- Korte uitleg: zero-knowledge + KDBX-compat + open-source-belofte

### S2. Account-login
- E-mail + accountwachtwoord
- Submit → server stuurt naar S4 (MFA-challenge) of S5 (vault-list)

### S3. Account-registratie
- E-mail + accountwachtwoord + wachtwoord-bevestigen
- **Verplichte checkbox:** "Ik begrijp dat als ik mijn vault-wachtwoord verlies, mijn data permanent weg is. HorseSafe kan dit niet herstellen."
- TOTP-setup-wizard (optioneel, kan later)
- Submit → S2

### S4. MFA-challenge
- Twee tabs: "Magic-link" of "TOTP-code"
- Magic-link: stuur naar mijn e-mail (één klik, e-mail bevat link → terug naar S5 ingelogd)
- TOTP: 6-cijferige code-invoer
- Submit → S5

### S5. Vault-lijst
- v0.0.x: 1 vault per user → automatisch redirect naar S6
- v0.1.x+: lijst van vaults + "+ Nieuwe vault"-knop

### S6. Vault-unlock
- Master-wachtwoord-veld (`#vault-pw`, type=password, minlength 6 als ingevuld, niet `required` sinds v0.0.9-Bellare)
- Keyfile-upload `<input type="file" id="vault-keyfile" accept=".keyx,.key,.keyfile,application/octet-stream">` (v0.0.9-Bellare LIVE; drag-drop nog niet)
- Subtekst onder keyfile (muted, 0.85em): "Wachtwoord óf keyfile is verplicht. Beide combineren kan ook (KeePassXC-compatibel)."
- Encryptie-modus indicator: 🔑 alleen pw / 📄 alleen keyfile / 🔑+📄 beide (concept; visuele indicator nog te bouwen v0.0.10+)
- **Keyfile-format-compatibiliteit** (HS-BUG-005): 64-hex-char ASCII (default, alle runtimes) > KeePassXC 2.x XML (import-only via lokale Node-resave) > 32-byte raw (niet ondersteund, kdbxweb-browser-bug)
- Lock-cleanup: `lockVault()` reset zowel `vault-pw.value=''` als `vault-keyfile.value=''`
- Submit → `unlockOrCreate()` → `openDatabase(blob, pw, keyFileBuffer)` met `await credentials.ready` → S7

### S7. Vault-content (hoofdscherm)
- Linker-zijbalk: groepen-boom (Root → General, Internet, eMail, ...)
- Hoofdpaneel: entry-tabel (Title, Username, URL, Modified)
- Rechter-detailpaneel bij selectie:
  - Title, Username
  - Password (verborgen, "👁 toon" + "📋 kopieer (10s wipe)" knoppen)
  - URL (klikbaar → `target="_blank" rel="noopener noreferrer"`)
  - **TOTP (v0.0.9-Bellare+, alleen zichtbaar als entry een `otp`-custom-field met `otpauth://`-URI heeft):**
    - 6-cijferige code in monospace 1.3em + letter-spacing 0.15em, gegroepeerd "XXX XXX"
    - Countdown rechts (seconden resterend in het 30s-window, `tabular-nums` voor stabiele alignment)
    - 📋 copy-button → kopieert huidige code naar clipboard (geen 10s wipe — TOTP-code is per definitie kortstondig)
    - Render-loop: `setInterval(renderTotpOnce, 1000)`, start in `selectEntry`, stop in `lockVault` en bij entry-wissel
  - Notes (multi-line)
  - Attachments (lijst, download-knop)
  - History (versies van deze entry)
- Toolbar: "+ Entry", "+ Groep", "Importeer", "Exporteer", "Sluit vault"

### S8. Entry bewerken (modal)
- Veld-grid: Title, Username, Password (genereer-knop), URL, Notes, Tags, Expiry
- Attachments toevoegen/verwijderen
- Generator-paneel (KeePassXC-stijl: lengte, classes, exclude-similar)
- Opslaan → frontend save() → upload

### S9. Importeer-flow
- Selecteer formaat: KDBX, Bitwarden JSON, KeePass-CSV, XLSX
- Bestand selecteren
- Preview (kolom-mapping voor CSV/XLSX)
- Conflict-keuze: skip/overschrijf/dupliceer-met-suffix
- Bevestig → entries toegevoegd aan huidige vault

### S10. Exporteer-flow
- Selecteer formaat: KDBX (encrypted) | CSV | JSON | XLSX (plaintext)
- Bij plaintext: **reden verplicht** ("backup", "migratie naar X", "wachtwoord-audit", ...)
- Confirm-dialog rood: "Je gaat ALLE wachtwoorden ONVERSLEUTELD downloaden. Doorgaan?"
- Audit-log entry geschreven → download triggered

### S11. Admin-pagina (alleen `is_admin=true`)
- User-tabel: e-mail, created, last_login, vault-count, storage
- Acties per user: deactiveer, verwijder
- Globale stats: totaal users, storage-gebruik, login-pogingen-laatste-24u
- Audit-log-viewer (filter op user/event/datum)

### S12. Settings
- E-mail wijzigen (vereist re-auth)
- Accountwachtwoord wijzigen (vereist re-auth)
- TOTP toevoegen/verwijderen (vereist re-auth)
- Magic-link only-toggle
- Verwijder mijn account (rood, vereist re-auth + typ "VERWIJDER MIJN DATA")

## UI-principes

- **Donker-thema-default** (security-tools-stijl, minder light-leakage bij schoudersurfing)
- **Geen wachtwoord ooit zichtbaar zonder expliciete `👁`-klik** (eye-icon = "ik weet wat ik doe")
- **10-seconden-aftelvisualisatie** rond clipboard-icoon na kopie
- **Audit-zichtbaarheid:** user kan eigen audit-log inzien in S12
- **Toetsenbord-shortcuts:** `Ctrl+B` username kopiëren, `Ctrl+C` password kopiëren, `Ctrl+U` URL openen (KeePassXC-compat)
- **Responsive:** Z-Fold 6 compatibel (zie globale CLAUDE.md note over Dashboard)

## Schermen-flow

```
S1 landing
  ├─→ S2 login → S4 MFA → S5 vault-list → S6 unlock → S7 content
  └─→ S3 register → S2

S7 content
  ├─→ S8 entry-edit (modal)
  ├─→ S9 import-flow
  ├─→ S10 export-flow
  ├─→ S11 admin (alleen admins)
  └─→ S12 settings
```

## Wachtwoord-generator (S8 paneel)

KeePassXC-compat defaults:

| Optie | Default | Range |
|---|---|---|
| Lengte | 20 | 8–128 |
| Hoofdletters | ✓ | — |
| Kleine letters | ✓ | — |
| Cijfers | ✓ | — |
| Speciale tekens | ✓ | — |
| Look-alikes uitsluiten (0/O, 1/l/I) | optie | — |
| Vergelijkbaar uitsluiten | optie | — |
| Custom characterset | optie | — |
| Diceware-passphrase | optie (5 woorden default) | 3–10 |

## Clipboard-strategie

### Browser (v0.0.x — best-effort)
1. User klikt "📋 kopieer"
2. `navigator.clipboard.writeText(pw)` → tab heeft focus = werkt
3. Visuele 10s-aftelling
4. Na 10s: `navigator.clipboard.writeText("[HorseSafe wiped]")` → **werkt alleen als tab nog focus heeft**
5. Bij tab-blur: timer pauzeert; bij focus-return: hervat
6. Page-unload: best-effort `beforeunload`-handler

### Extensie (v0.2.0)
- Native messaging tussen tab en extensie
- Extensie kan `chrome.clipboard` API gebruiken zonder focus-eis
- Cross-domain autocomplete: extensie injecteert pw in URL-matching form-field

## Notities

- **Geen "remember me"** op vault-unlock (master-key in geheugen = 0 minuten persisted)
- **JWT session-cookie**: max 12u, sliding window
- **MFA-replay:** TOTP-codes worden eenmalig gemarkeerd in 30s-window
- **Magic-link**: 10 minuten geldig, single-use
- **Failed-login lockout**: 5 pogingen / 15 min, per IP + per account
