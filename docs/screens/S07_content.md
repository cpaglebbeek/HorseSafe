# S7 — Vault content (entries)

**Route:** `/HorseSafe/vault.html` (na unlock)
**Auth-eis:** JWT + vault-decrypted in browser
**Doel:** entries beheren (lijst, detail, toevoegen, verwijderen, copy)
**Doelgroep:** ingelogde + unlocked gebruiker

## Key-messages

- "default" — vault-naam zichtbaar bovenaan
- "zero-knowledge (server ziet alleen ciphertext)" — herinnering aan privacy-belofte
- Aantal entries dynamisch

## Componenten

### Top-bar
- Vault-naam + stats
- Buttons: **+ Nieuwe entry**, **Vergrendel**, **Uitloggen**

### Linker-paneel: categorieën (`nav.group-pane`, v0.3.5-Miller)
- `#group-tree`: "Alle entries" + KDBX-groepen onder de root met submappen (`.group-toggle` ▸/▾, `state.expanded`),
  per groep het aantal entries inclusief subgroepen (`.count`); gekozen groep `aria-current="true"` (accentkleur).
- Prullenbak (`meta.recycleBinUuid`) heet "Prullenbak", cursief, onderaan; telt niet mee in "Alle".
- ≤ 1100 px: `#group-select` (ingesprongen namen met aantallen) i.p.v. de boom, over de volle breedte boven de lijst.
- Bij vergrendelen: boom, keuzelijst, zoekveld en lijst leeg (`resetView()`).

### Middenpaneel: entries-tabel
- Kop: `#list-title` (categoriepad "A › B", "Alle entries" of "Zoekresultaten") + `#entry-count` + `#entry-total` (" van N")
- Zoekveld `#entry-search` (type search, debounce 120 ms) + `#search-in-group` "alleen in deze categorie"
  - zoekt in titel, gebruikersnaam, URL, notities, categorienaam; nooit in Password/beveiligde velden
  - alle woorden moeten voorkomen; hoofdletters en accenten tellen niet (`HorseSafeVaultIndex.normalize`)
  - `/` = focus zoekveld (niet tijdens typen elders), `Esc` = leegmaken
- Kolommen: Titel · Gebruikersnaam · URL · Categorie (`.col-group`, alleen als de lijst meerdere categorieën kan bevatten)
- Gesorteerd op titel (`localeCompare('nl')`); rij is `selectable` — klik = selecteer → toont detail
- Lege state: "Geen entries — klik …", "Geen entries in deze categorie" of "Niets gevonden"

### Rechter-paneel: detail (`#detail-pane`)
- Title, Username (read-only)
- Password — verborgen by default (`••••••••••••`); toggle-knop `👁`
- URL — klikbare link (`target="_blank" rel="noopener noreferrer"`)
- **TOTP** (v0.0.9-Bellare+, alleen zichtbaar als entry een `otp`-custom-field met `otpauth://`-URI heeft):
  - `#d-totp-code` — 6-cijferige code in monospace 1.3em + letter-spacing 0.15em + tussen-spatie `XXX XXX` + bold (`--hs-totp-code-size`, `--hs-totp-letter-spacing`, `--hs-totp-code-weight`)
  - `#d-totp-countdown` — seconden resterend in 30s-window, `tabular-nums` voor stabiele alignment (`--hs-totp-numeric-style`)
  - `#d-totp-copy` — 📋-button kopieert huidige code naar clipboard; visuele "✓" feedback 1.5s
  - Render-loop: `setInterval(renderTotpOnce, 1000)` via `state.totpTimer`, auto-start in `selectEntry`, auto-stop in `lockVault` en bij entry-wissel
  - Berekening: `frontend/js/totp.js` RFC 6238 via `crypto.subtle.sign('HMAC')` + base32-decoder + RFC 4226 dynamic truncation
  - **Zero-knowledge**: TOTP-seed staat in encrypted KDBX4-blob; berekening browser-only; server zag seed NOOIT
- Notes (multi-line)
- Acties: **📋 Kopieer wachtwoord** (met 10s-aftel-progressbar) + **Verwijder** (rood)

### Entry-edit-section (`#edit-section`, hidden tot "+ Nieuwe entry")
- "Komt in: <categorie>" (`#e-group-label`); de entry landt in de gekozen categorie, anders de hoofdmap (nooit de prullenbak)
- Title (required), Username, Password, URL, Notes
- 🎲 Genereer 20-char wachtwoord (cryptografisch random via `crypto.getRandomValues`)
- Opslaan + Annuleren

## Flows

| Stap | Doel | Outcome |
|---|---|---|
| Klik rij | Select entry → toon detail | detail-pane visible |
| Klik `👁` | Toggle pw display | tekst vs `••••••••••••` |
| Klik "📋 Kopieer wachtwoord" | `navigator.clipboard.writeText(pw)` + 10s-aftelling + best-effort wipe | clipboard heeft pw, 10s timer loopt, daarna placeholder |
| Klik "Verwijder" | `kdbxweb.remove(entry)` + PUT `/vault/{id}` met If-Match | rij weg + detail dicht · 412 → conflict-warning |
| Klik "+ Nieuwe entry" | Open edit-section | inputs leeg, focus op title |
| Submit edit-form | `db.createEntry()` + db.save() + PUT `/vault/{id}` | rij toegevoegd · etag refreshed |
| Klik "Vergrendel" | Wis state.db uit RAM | terug naar S6 |
| Klik "Uitloggen" | POST `/auth/logout` + redirect S1 | sessie wissen |

## Clipboard-wipe (best-effort)

1. `navigator.clipboard.writeText(pw)` — synchroniseert direct (vereist user-gesture, hier klik)
2. Timer `setTimeout(tick, 100ms)` — bar krimpt 80px → 0
3. Na 10s: `navigator.clipboard.writeText('[HorseSafe wiped]')` — **werkt alleen als tab focus heeft**
4. v0.2.0-Schneier extension lost focus-eis op (échte clipboard-wipe via `chrome.clipboard`)

## Visuele referentie

`S07_content.png` (screenshot volgt).

## Bron

- `UI_DESIGN.md` § S7
- `frontend/vault.html`
- `frontend/js/vault-ui.js` (selectEntry, persist, addNewEntry, deleteCurrent, copyPassword, togglePwDisplay, generatePw)
- `frontend/js/crypto.js` (copyWithWipe, generatePassword)
