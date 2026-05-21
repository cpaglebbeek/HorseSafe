# S11 — Admin-paneel

**Route:** `/HorseSafe/admin.html`
**Auth-eis:** JWT + `admin: true` + `mfa: true`
**Doel:** users beheren, stats inzien, audit-log raadplegen, admin-rescue uitvoeren
**Doelgroep:** admins (gepromoot via CLI `python -m backend.db.promote_admin <email>`)

## Componenten

### Statistieken-grid
5 cards: Users / Vaults / Storage / Logins 24u / Failed 24u

### Gebruikerstabel
| Kolom | Bron |
|---|---|
| E-mail (+ ADMIN-badge) | `users.email`, `users.is_admin` |
| Aangemaakt | `users.created_at` |
| Laatste login | `users.last_login_at` |
| Vaults | COUNT(vaults) |
| Storage | SUM(vaults.size_bytes) |
| MFA (+ TOTP-badge + N codes) | `users.totp_secret IS NOT NULL` + remaining backup-codes |
| Acties | MFA reset / Magic-link / Delete |

### Acties (alle met **reden verplicht, min 10 chars**)
- **MFA reset** — POST `/admin/users/{id}/disable-mfa` — verwijder TOTP + backup-codes
- **Magic-link** — POST `/admin/users/{id}/send-magic-link` — stuur naar user's geregistreerde e-mail (niet admin's!)
- **Delete** — DELETE `/admin/users/{id}` — cascade-delete user + vaults + backup-codes; **dubbele bevestiging via "typ EMAIL"**; **self-delete blokkering** (HTTP 400 `self_delete_forbidden`)

### Audit-log viewer
- Filters: event, user_id, limit (default 50, max 500), offset
- Pagination: ← Vorige / Volgende →
- Read-only: alleen weergave

## Errors-mapping
| HTTP | UI |
|---|---|
| 401 | Redirect `login.html` |
| 403 `admin_required` | Alert + redirect `vault.html` |
| 403 `mfa_required` | Redirect `mfa.html` |

## Niet in S11 (v0.0.4)
- CSV-export audit-log → v0.0.5-Shamir
- Per-user audit-detail-pop-up → v0.0.5+

## Bron
- `UI_DESIGN.md` § S11
- `API.md` § /admin/*
- `frontend/admin.html` + `frontend/js/admin.js`
