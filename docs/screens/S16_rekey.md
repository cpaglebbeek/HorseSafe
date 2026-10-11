# S16 — Wachtwoord of keyfile wijzigen

**Route:** formulier `#rekey-form` onderaan S14
**Auth-eis:** JWT+MFA, geopende kluis en S15
**Doel:** de kluis een nieuw wachtwoord en/of een nieuwe keyfile geven en alle sleutelkopieën in één keer bijwerken
**Sinds:** v0.2.0-Koblitz

## Key-messages
- "Wijzigt de kluis en werkt alle gekoppelde sleutels in één keer bij (ook de noodsleutel in je kluis)."
- "Een leeg veld laat dat onderdeel zoals het is."

## Componenten
- `#rekey-pw` + `#rekey-pw2` — nieuw wachtwoord (leeg = behouden)
- `#rekey-pw-remove` — huidig wachtwoord verwijderen (expliciet, met bevestiging)
- `#rekey-keyfile` — nieuwe keyfile (leeg = behouden)
- `#rekey-kf-remove` — huidige keyfile verwijderen (expliciet, met bevestiging)
- `#rekey-submit`, `#rekey-error`, `#rekey-status`

## Flow
1. S15 (step-up).
2. Client maakt de nieuwe KDBX4 en verzegelt het nieuwe materiaal voor elke sleutel (ook geblokkeerde noodsleutels).
3. `PUT /vault/{vid}/rekey` met `If-Match` — atomair: kluis + alle kopieën, of niets.
4. Onduidelijke uitkomst (netwerkfout, 5xx): de client vergelijkt de server-etag met de verstuurde blob en meldt of het nieuwe of het oude wachtwoord geldt; bij twijfel vergrendelt hij met het advies beide te bewaren.

## Bron
- `UI_DESIGN.md` § S16 · `docs/HARDWARE_KEYS.md` §12.6.5 · `frontend/js/hwkeys-ui.js`
