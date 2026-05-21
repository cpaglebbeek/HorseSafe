# S4 — MFA-challenge

**Route:** `/HorseSafe/mfa.html`
**Auth-eis:** JWT-cookie met `mfa: false` (post-login, pre-vault)
**Doel:** TOTP-code of magic-link-redemption om MFA te voltooien
**Doelgroep:** ingelogde user met TOTP geconfigureerd

## Key-messages
- "Voltooi één van onderstaande stappen om door te gaan naar je vault."
- Beide methoden zijn gelijkwaardig veilig.
- v0.0.3-Merkle: TOTP (Authenticator-app) **of** magic-link (Gmail).

## Tabs
- **Authenticator-code** (default) — 6-cijfer-input
- **Magic-link via e-mail** — input e-mailadres + verstuur-knop

## Flows

| Stap | Doel | Outcome |
|---|---|---|
| Submit TOTP-code | POST `/auth/totp/verify` `{code}` | 200 → JWT-cookie upgraded mfa=true → redirect `vault.html` · 400 invalid_code → error |
| Submit magic-link aanvraag | POST `/auth/magic-link` `{email}` | 200 + e-mail verstuurd (info-leak-resistant: zelfde respons voor onbekend e-mail) |
| Klik magic-link in e-mail | GET `/auth/magic-link/redeem?t=...` | 302 → `vault.html` + cookie set met mfa=true · invalid_link → redirect `login.html?error=...` |
| Annuleer (uitloggen) | POST `/auth/logout` | redirect `index.html` |

## Throttle
- 5 mislukte TOTP-pogingen / 15 min → 423 Locked
- Hergebruikt `failed_logins`-tabel via event `mfa_fail`

## Bron
- `UI_DESIGN.md` § S4
- `API.md` § /auth/totp/verify + /auth/magic-link
- `frontend/mfa.html` + `frontend/js/mfa.js`
