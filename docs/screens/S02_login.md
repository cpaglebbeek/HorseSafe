# S2 — Account-login

**Route:** `/HorseSafe/login.html`
**Auth-eis:** geen (login-pagina zelf)
**Doel:** gebruiker authenticeert tegen het HorseSafe-account
**Doelgroep:** bestaande gebruikers

## Key-messages

- Onderscheid tussen **account-wachtwoord** (server kent, voor login) en **vault-wachtwoord** (alleen in browser, voor decryptie). De pagina expliciteert dit in de muted-paragraaf.
- v0.0.2 = single-factor login (MFA volgt in Fase 3, v0.0.3-Merkle)

## CTA's

- **Primair:** "Inloggen" → POST `/auth/login` → bij succes → S6/S7 via `vault.html`
- **Secundair:** "Terug" → terug naar S1

## Componenten

- `<header class="brand">`
- `.card` met:
  - muted-uitleg
  - email-input (type=email, autocomplete=email)
  - password-input (type=password, autocomplete=current-password)
  - submit + secundair-terug buttons
  - error message-area
- Footer-link "Nog geen account? Account aanmaken." → S1

## Errors

| Backend-respons | UI-melding |
|---|---|
| 401 `invalid_credentials` | "Verkeerd e-mailadres of wachtwoord." |
| 423 `throttled` | "Te veel mislukte pogingen. Wacht 15 minuten." |
| 429 `rate_limited` | "Te veel verzoeken. Wacht even." |

## Flows

| Stap | Doel | Outcome |
|---|---|---|
| Submit form | POST `/auth/login` | success → JWT-cookie + redirect `vault.html` · error → message |

## Cookie

Backend zet `horsesafe_session` (HttpOnly + Secure + SameSite=Strict) bij 200. Frontend gebruikt deze automatisch via `credentials: 'include'`.

## Visuele referentie

`S02_login.png` (screenshot volgt).

## Bron

- `UI_DESIGN.md` § S2
- `API.md` § `/auth/login`
- `frontend/login.html`
- `frontend/js/auth.js`
