# S15 — Bevestig dat jij het bent (step-up)

**Route:** dialoog `#stepup-section` binnen `/HorseSafe/vault.html`
**Auth-eis:** JWT+MFA; levert een kortlevende step-up-claim in het sessiecookie
**Doel:** gevoelige sleutelacties pas uitvoeren na een verse bevestiging
**Sinds:** v0.2.0-Koblitz

## Wanneer
Bij een 403 `stepup_required` van: koppelen vanaf de tweede sleutel, "Bijwerken", wachtwoord/keyfile wijzigen (S16), blokkade van een noodsleutel opheffen. Na succes herhaalt de client de oorspronkelijke actie één keer.

## Componenten
- `#stepup-intro` — "Raak je YubiKey Bio aan."
- `#stepup-bio` — "🔑 Bevestig met YubiKey Bio" (standaard)
- `#stepup-totp-form` + `#stepup-code` — authenticator-code; alleen als er geen actieve Bio is of de browser geen hardware-sleutels kan
- `#stepup-error`, `#stepup-cancel`
- `role="dialog"`, `aria-modal="true"`, `aria-labelledby="stepup-title"`

## Regels
- Blokkade opheffen: alleen de YubiKey Bio (`stepup_bio_required`); een Bio die ná de blokkade is gekoppeld telt niet.
- Authenticator-code tijdelijk niet mogelijk na het verwijderen van een Bio of het (her)instellen van TOTP (`stepup_cooldown`, met resterende tijd).
- Meer dan 5 foute codes per 15 minuten → `too_many_attempts`.

## Bron
- `UI_DESIGN.md` § S15 · `docs/HARDWARE_KEYS.md` §12.8 · `frontend/js/stepup.js`
