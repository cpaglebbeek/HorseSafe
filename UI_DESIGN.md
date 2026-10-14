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
- **v0.2.0-Koblitz — YubiKey-route** (`#hwkey-unlock`, alleen zichtbaar als er sleutels gekoppeld zijn): knop "🔑 Ontgrendel met YubiKey" (`#hwkey-unlock-btn`) met de hint "Steek de sleutel in en leg je vinger erop zodra hij knippert". De laatst gebruikte methode (YubiKey of keyfile) staat bovenaan (localStorage, in try/catch). Zonder geschikte browser (`#hwkey-support`): "Gebruik Chrome of Edge op de laptop". Uitklapper "Noodsleutel gebruiken" (`#recovery-details`) met per noodsleutel de status en de knoppen aanvragen / annuleren / blokkeren / ontgrendelen; banner `#recovery-notify` als meldingen niet zijn ingesteld (vrijgave dan uitgeschakeld). Zie S14.
- **Waarschuwing** `#recovery-alert` bovenaan (ook in S7) zodra er een vrijgave loopt: wie, wanneer, "Nu annuleren".
- **Automatisch vergrendelen** na 15 minuten inactiviteit (`AUTO_LOCK_MS`); het wachtwoordveld wordt direct na openen geleegd.

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

### S14. Sleutelbeheer (v0.2.0-Koblitz) — paneel `#keys-section` in S7
- Openen via "🔑 Sleutels" (`#keys-open`) in de werkbalk van S7; alleen met een geopende kluis.
- Tabel `#keys-body` (horizontaal scrollbaar op smalle schermen): naam (bij een telefoon het toestellabel), soort (YubiKey Bio / Noodsleutel / Telefoon, met model eronder), gekoppeld, laatst gebruikt, status in gewone taal (klaar · in de kluis (klaar) · wacht nog 13 u 20 m (tot …) · vrijgegeven tot … · gebruikt · verlopen · geblokkeerd sinds … · "kopie verouderd") en per rij de acties.
- Koppelen: naam (`#key-label`) + "+ YubiKey Bio koppelen" / "+ Noodsleutel koppelen"; uitleg in een bevestiging (Bio: vingerafdruk; noodsleutel: PIN van 63 tekens, PIN niet bij de sleutel, daarna in de fysieke kluis). Vanaf de tweede sleutel eerst S15.
- "↻ Bijwerken" (`#keys-reseal`, S15): alle sleutels opnieuw verzegelen na een wachtwoord/keyfile-wijziging buiten HorseSafe.
- Noodsleutel: blokkeren kan altijd (defensief, zonder S15); opheffen alleen met S15 via de YubiKey Bio.
- Banner `#notify-banner` als meldingen niet zijn ingesteld.
- Fouten (`#keys-error`) in gewone taal volgens `docs/HARDWARE_KEYS.md` §12.13.
- **v0.3.4-Miller:** telefoonsleutels (kind `phone`) staan in dezelfde tabel; actie "Toestel verwijderen" (`data-device`) trekt na bevestiging het hele toestel in (`DELETE /devices/{id}`: het kan geen enkele kluis meer openen, de verzegelde kopieën op de server worden gewist). Onder de tabel het blok "Telefoon" met "📱 Telefoon koppelen" (`#phone-pair`) → S17.

### S15. Bevestig dat jij het bent — step-up-dialoog (v0.2.0-Koblitz) — `#stepup-section`
- Verschijnt bij een 403 `stepup_required` (sleutel koppelen vanaf de tweede, bijwerken, S16, blokkade opheffen); na succes wordt de oorspronkelijke actie één keer herhaald.
- Standaard: "🔑 Bevestig met YubiKey Bio" (`#stepup-bio`). Een authenticator-code (`#stepup-totp-form`) alleen als er nog geen actieve Bio is, of de browser geen hardware-sleutels kan; blokkade opheffen kan alleen met de Bio.
- `role="dialog"`, `aria-modal`, "Annuleren" (`#stepup-cancel`); fouten in `#stepup-error`.

### S16. Wachtwoord of keyfile wijzigen (v0.2.0-Koblitz) — `#rekey-form` in S14
- Nieuw wachtwoord (2×) en/of nieuwe keyfile; een leeg veld behoudt dat onderdeel. Verwijderen alleen via een expliciet vinkje (`#rekey-pw-remove`, `#rekey-kf-remove`) met bevestiging.
- Eerst S15; daarna worden de kluis en álle sleutelkopieën in één keer bijgewerkt (ook de noodsleutel in de kluis). Bij een onduidelijke uitkomst controleert de client of de wijziging is doorgevoerd en meldt hij welk wachtwoord geldt.

### S17. Telefoon koppelen (v0.3.4-Miller deel 2) — paneel `#pair-section` in S14
- Contract: `docs/HARDWARE_KEYS.md` §13 (flow §13.3). Code: `frontend/js/pairing.js` (crypto + API) en `frontend/js/pairing-ui.js` (scherm). Alleen met een geopende kluis.
- "📱 Telefoon koppelen" (`#phone-pair`) → bij 403 `stepup_required` eerst S15 → **QR** (`#pair-qr`, SVG zonder inline script) met de tekst "Open de HorseSafe-app op je telefoon, kies Koppelen en scan deze QR-code" en een aftelling `#pair-countdown` (5:00 → 0:00). De QR bevat het browsergeheim `s`; de server krijgt alleen `k_srv`.
- De browser pollt elke seconde. Zodra de telefoon claimt: QR weg, `mac_web` controleren. Fout → koppeling verwijderd (`DELETE`) en de melding **"Koppeling niet vertrouwd — mogelijk gemanipuleerd"** (`#pair-error`, `role="alert"`). Er wordt dan niets verzegeld.
- Klopt `mac_web`: **SAS** groot en monospace (`#pair-sas`, "267 364"; schermlezer leest de cijfers los) met toestelnaam, model en app-versie, en de vraag "Staat op je telefoon precies dezelfde code?". Knoppen "✓ Klopt" (`#pair-sas-ok`, krijgt focus) en "✗ Klopt niet" (`#pair-sas-bad`), minimaal 44 px hoog; onder 480 px elk over de volle breedte.
- **Klopt** → Seal_v2 naar de telefoonsleutel (`pk_c`) + vormcontrole, ontvanger vastgelegd in de kluis (zoals bij YubiKeys, R15), `POST …/confirm` → melding "✓ Telefoon "…" gekoppeld" en de lijst ververst. **Klopt niet**, **Annuleren**, verlopen, kluis vergrendeld of tab dicht → `DELETE` (bij tab dicht best effort).
- Status in `#pair-status` (`role="status"`, `aria-live="polite"`; de aftelling meldt zich alleen per minuut). Na afloop: QR en SAS uit beeld, `s` en `k_web` gewist; de knop wordt "Sluiten".

### S12. Settings
- E-mail wijzigen (vereist re-auth)
- Accountwachtwoord wijzigen (vereist re-auth)
- TOTP toevoegen/verwijderen (vereist re-auth)
- Magic-link only-toggle
- Verwijder mijn account (rood, vereist re-auth + typ "VERWIJDER MIJN DATA")

## Android-app (v0.3.0-Miller deel 1, M13 sinds v0.3.1) — schermen M0..M13

Eén activity met Compose (`android/`, `ui/Navigation.kt`); per scherm een korte referentie in
`docs/screens/M<NN>_*.md`. Teksten in het Nederlands (`ui/Texts.kt`). Schermen met een geheim
(**M4, M5, M6, M8**) zijn geblokkeerd zolang de omgevingscontrole een overtreding ziet (BlockedPanel,
invoer gewist) en slikken hardwaretoetsen; bij verlaten van het venster wordt de PIN verborgen.

| # | Scherm | Doel | Geheim |
|---|---|---|---|
| M0 | Start | omgevingsoordeel + menu: nieuwe hoofdsleutel, nieuwe noodsleutel, hervatten, keuren zonder/met PIN, PIN wijzigen, vingers beheren, oefenen, rapporten, over (geen reset) | — |
| M1 | Checklist | vliegtuigmodus, geen schermkoppeling, ontwikkelaarsopties uit, Auto Blocker aan, niemand kijkt mee, pen + formulier | — |
| M2 | Sleutel aansluiten | één YubiKey direct in USB-C (YK5 via één OTG-adapter); NFC alleen bij keuren zonder PIN; "altijd openen" niet aanvinken | — |
| M3 | Oordeel | sleuteltype, firmware, per eis groen/oranje/rood; "nog te doen" bij hervatten; melding verschillende PIN's (noodsleutel) | — |
| M4 | PIN tonen | 9 kaarten (4+3 tekens + omkaderd controleteken), alleen zichtbaar zolang ingedrukt; Canvas uit CharArray | ja |
| M5 | Overschrijven | papier controleren; bevestigen dat alle 9 groepen met controleteken op papier staan | ja |
| M6 | Overtypen | eigen toetsenblok (29 tekens + Wis), alle 9 groepen; per groep alleen "klopt"/"groep N wijkt af" | ja |
| M6b | Onomkeerbaar | rood kader, vinkje + "Ik begrijp het, vastzetten" vóór minimum 63 | — |
| M7 | Vingers | inschrijven met voortgang en Nederlandse feedback, naam (R-wijs …), testaanraking; beheren: toevoegen/hernoemen/verwijderen | — |
| M8 | PIN invoeren | PIN van papier per groep met controleteken (fout controleteken kost geen poging); banner PIN-pogingen x/8, geblokkeerd bij ≤ 3; ook voor Oefenen | ja |
| M9 | Keuring | rapport met vergelijking met de vorige basis (verschil = rood; geen basis = oranje) | — |
| M10 | Rapport | whitelist-velden, zelfgekozen codes (zak, papierlocatie), exporteren/importeren, "Afsluiten" (wist PIN, beëindigt app), verwijzing naar S14 | — |
| M11 | Stop | reden, wat je nu doet, wat al op de sleutel staat; knop "Sleutel wissen" bij afwijzings-stops (0.3.1) | — |
| M12 | Over | versie, SHA-256 van de vertrouwensankers, signer-digest, licenties (yubikit Apache-2.0) | — |
| M13 | Sleutel wissen | wat erop staat en verloren gaat, laatste 4 cijfers serienummer overtypen + 3 s vasthouden, opnieuw aansluiten, aanraken, nagelezen; daarna inrichten | — |

Flow nieuwe sleutel: M0 → M1 → M2 → M3 → M4 → M5 → M6 → (bezig: attestation/setPin/tellen) → M6b →
(bezig: minimum, alwaysUv) → [hoofdsleutel: M7] → M10. Hervatten: M0 → M1 → M2 → M3 → M8 → (rest van de
volgorde) → M10. Elke STOP → M11.

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

S6 unlock
  ├─→ (YubiKey Bio) → S7
  └─→ (noodsleutel: aanvragen → 24 u → ontgrendelen) → S7

S7 content
  ├─→ S14 sleutelbeheer ─→ S15 step-up ─→ S16 wachtwoord/keyfile wijzigen
  │                      └─→ S15 step-up ─→ S17 telefoon koppelen (QR → SAS → Klopt/Klopt niet)
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
