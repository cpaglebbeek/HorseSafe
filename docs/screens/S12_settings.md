# S12 — Settings

**Route:** `/HorseSafe/settings.html`
**Auth-eis:** JWT + mfa=true (toegankelijk vanuit vault.html)
**Doel:** TOTP management (enable/disable) + (toekomst) account-management
**Doelgroep:** ingelogde user die TOTP wil instellen of wijzigen

## Componenten (v0.0.3)

### TOTP-management

#### Status-pane (default)
- Toont `Status: Ingeschakeld` of `Niet ingeschakeld`
- **TOTP inschakelen** button (alleen zichtbaar als niet ingeschakeld) → onthul setup-pane
- **TOTP uitschakelen** (rood, alleen als ingeschakeld) → onthul disable-pane

#### Setup-pane
1. Tekst: "Scan de QR-code met je Authenticator-app"
2. **QR-code SVG render** via `vendor/qrcode/qrcode.js` van `otpauth://totp/HorseSafe:<email>?secret=<base32>&issuer=HorseSafe`
3. Fallback: secret-string als monospace tekst (voor handmatige invoer)
4. 6-cijfer-input
5. Submit → POST `/auth/totp/verify` `{secret, code}` → bij 200: secret-opslag + success-message
6. Annuleer → status-pane

#### Disable-pane
- 6-cijfer-input (huidige TOTP-code als verificatie)
- Submit → POST `/auth/totp/disable` `{code}` → bij 200: TOTP-secret weg
- Annuleer → status-pane

### Navigatie
- ← Terug naar vault → `vault.html`
- Uitloggen → POST `/auth/logout` + redirect `index.html`

## Status-probe heuristiek (v0.0.3)
Pagina doet bij load een `GET /vault` request:
- 200 → user heeft geen TOTP (cookie heeft mfa=true direct na login)
- 403 mfa_required → user heeft TOTP wel
- 401 → redirect login

> NB: in v0.0.4+ vervangen door `/auth/me` endpoint dat MFA-status expliciet retourneert.

## Bron
- `UI_DESIGN.md` § S12
- `API.md` § /auth/totp/setup + verify + disable
- `frontend/settings.html` + `frontend/js/settings.js`
- `frontend/vendor/qrcode/`
