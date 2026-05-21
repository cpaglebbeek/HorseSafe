# S1 — Landing

**Route:** `/HorseSafe/` (productie) of `/index.html` (dev)
**Auth-eis:** geen
**Doel:** uitleg-pagina + 2-CTA's (inloggen / account aanmaken)
**Doelgroep:** nieuwe + bestaande gebruikers

## Key-messages

- Slogan: "Jouw kluis. Niet de onze."
- Belangrijkste boodschap: **zero-knowledge** — server ziet alleen ciphertext
- Belangrijkste consequentie: **data-verlies bij vergeten wachtwoord** (geen recovery)
- Compatibiliteit-belofte: KeePassXC-desktop voor disaster-recovery
- Status-indicatie: "POC v0.0.2-Hellman"

## CTA's

- **Primair:** "Inloggen" → S2
- **Secundair:** "Account aanmaken" → onthult inline-register-formulier (zelfde scherm)

## Componenten

- `<header class="brand">` — logo (`assets/horsesafe.svg`) + naam + slogan
- `.card` met uitleg-tekst + 2 buttons
- `#register-card` (hidden by default) met:
  - email-input (type=email, required, autocomplete)
  - password-input (type=password, minlength=12)
  - ack-checkbox (required) — verklaring data-verlies
  - submit + cancel buttons
  - error/success message-areas

## Validatie (client-side)

- E-mail moet HTML5-pattern matchen
- Wachtwoord min 12 tekens (front-end check + backend `Field(min_length=12)`)
- `ack_data_loss` checkbox verplicht; backend weigert `false` met 400

## Flows

| Trigger | Doel | Outcome |
|---|---|---|
| Klik "Inloggen" | Navigatie | → S2 |
| Klik "Account aanmaken" | Onthul register-formulier | inline (geen route-change) |
| Submit register | POST `/auth/register` | success → redirect S2 na 1.2s · error → toon message |
| Klik "Annuleren" in register | Verberg register-formulier | terug naar landing-state |

## Visuele referentie

`S01_landing.png` (screenshot wordt toegevoegd na Fase 2 stabilisatie).

## Bron

- `UI_DESIGN.md` § S1
- `ARCHITECTURE.md` § 2.3 (`/auth/register`)
- `frontend/index.html`
- `frontend/js/auth.js`
