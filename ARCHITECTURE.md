# ARCHITECTURE.md — HorseSafe

> Drie niveaus: conceptueel → logisch → fysiek. Conform `feedback_expliciete_vastlegging.md` (alles vastleggen in repo, niet alleen in memory).

## 1. Conceptueel niveau

### 1.1 Doel
HorseSafe is een **gebruikers-bediende wachtwoord-vault**, gehost als SaaS op HorseCloud55, met de eigenschap dat de host (= server, = beheerder, = elke partij behalve de gebruiker) **geen toegang heeft tot de inhoud van de vault**, zelfs niet bij volledige server-compromittering.

### 1.2 Actoren

| Actor | Rol |
|---|---|
| **Eindgebruiker** | Maakt account, maakt vault aan, beheert eigen credentials |
| **Administrator** | Beheert user-accounts en server-stats; ziet GEEN vault-inhoud |
| **Server (HorseSafe-backend)** | Slaat encrypted vault-blobs op, doet account-auth, host MFA-flow |
| **Browser-client (HorseSafe-frontend)** | Voert crypto-operaties uit, beheert vault-content in geheugen |
| **Browser-extensie (optioneel, v0.2)** | Doet autocomplete, écht clipboard-wipe, native messaging met HorseSafe-tab |
| **MFA-provider Gmail** | Levert magic-link e-mails (hergebruik iCt_Horse magic-link stack) |
| **MFA-provider Authenticator-app** | Genereert TOTP-codes (Google Authenticator / Authy / etc.) |

### 1.3 Concepten

| Concept | Definitie |
|---|---|
| **Account** | Server-side identiteit: e-mailadres + accountwachtwoord + MFA-secret + JWT-sessie |
| **Vault** | Encrypted KDBX4-bestand. Eén-per-user in v0.0.x; meerdere benoemde in v0.1.x |
| **Master-key** | Composiet van (a) master-pw, (b) keyfile, of (c) beide. Alléén in browser. Nooit naar server |
| **Vault-blob** | KDBX4-bestand zoals server het ziet: pure ciphertext. Wordt opgevraagd, gedecrypteerd in browser, gemuteerd, geëncrypteerd, teruggeplaatst |
| **Entry** | Eén wachtwoord-record binnen vault: title, username, password, URL, notes, attachments, history, expiry |
| **Magic-link MFA** | Eenmalig e-mail-token, hergebruikt iCt_Horse magic-link infrastructuur |
| **TOTP MFA** | RFC 6238, 30s window, 6 digits, SHA-1, base32-geseed |

### 1.4 Zero-knowledge bewijs

> Stel: een aanvaller heeft volledige server-toegang (root op HC55, alle disk, alle DB, alle code). Wat kan hij?

| Aanvalsvermogen | Aanvaller heeft toegang tot | Aanvaller heeft GEEN toegang tot |
|---|---|---|
| Vault-blobs (ciphertext) | ✅ | — |
| Master-pw of derivaten | — | ✅ (nooit naar server gestuurd) |
| Keyfile-content of -hash | — | ✅ (nooit naar server gestuurd) |
| Vault-content (entries, pw's) | — | ✅ (kan KDBX4 niet decrypteren zonder master-key) |
| User-account-pw | hash met argon2id-server-side | — |
| MFA-secret TOTP | gehashed met PBKDF2 in server-DB | base32-encoded plain (server moet TOTP-codes verifiëren!) |
| Magic-link token | tijdelijk in server-RAM/DB tot redemption | — |

**Belangrijkste constraint:** MFA-secrets staan plaintext op de server (RFC 6238 kan niet anders), maar MFA-secrets geven **alleen toegang tot account-laag, niet tot vault-laag.** De vault-decryptie vereist master-pw + keyfile die alleen de gebruiker kent.

### 1.5 Wachtwoord-vergeten consequentie

**Strict zero-knowledge → server kan vault-content niet recoveren.** Bij verlies master-pw + keyfile = data **permanent** verloren. Hierop wordt expliciet gewaarschuwd bij account-aanmaak (verplichte checkbox).

## 2. Logisch niveau

### 2.1 Component-decompositie

```
┌──────────────────────────────────────────────────────────────────────┐
│ BROWSER (client, untrusted door server, trusted door user)           │
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐  │
│  │ Auth-UI        │  │ Vault-UI       │  │ Crypto-engine          │  │
│  │ (login + MFA)  │  │ (entries CRUD) │  │ (kdbxweb + libargon2)  │  │
│  └────────────────┘  └────────────────┘  └────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Clipboard-manager (best-effort wipe na 10s)                  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                              │ HTTPS (TLS 1.3)
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ HorseCloud55 nginx :443 → location /HorseSafe/ → :3997               │
└──────────────────────────────────────────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ FastAPI backend :3997                                                │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────┐  │
│  │ /auth/* routes  │  │ /vault/* routes │  │ /admin/* routes      │  │
│  │ login + MFA     │  │ blob CRUD only  │  │ user CRUD + stats    │  │
│  └─────────────────┘  └─────────────────┘  └──────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Storage-layer                                                │    │
│  │  - SQLite: users, mfa_secrets, audit_log, vault_metadata     │    │
│  │  - Filesystem: /opt/horsesafe/vaults/<u-uuid>/<v-uuid>.kdbx  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ MFA-bridge: hergebruik iCt_Horse magic-link e-mailer         │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Datamodel (SQLite)

```sql
CREATE TABLE users (
  id              TEXT PRIMARY KEY,        -- UUID
  email           TEXT UNIQUE NOT NULL,
  pw_hash         TEXT NOT NULL,           -- argon2id van accountwachtwoord
  totp_secret     TEXT,                    -- base32, optioneel
  magic_link_only BOOLEAN NOT NULL DEFAULT 0,
  is_admin        BOOLEAN NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  last_login_at   INTEGER
);

CREATE TABLE vaults (
  id            TEXT PRIMARY KEY,          -- UUID
  user_id       TEXT NOT NULL REFERENCES users(id),
  name          TEXT NOT NULL,             -- 'default' in v0.0.x
  blob_path     TEXT NOT NULL,             -- /opt/horsesafe/vaults/<uuid>/<uuid>.kdbx
  size_bytes    INTEGER NOT NULL,
  etag          TEXT NOT NULL,             -- SHA-256 van blob, voor optimistic lock
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  UNIQUE(user_id, name)
);

CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT,
  ts          INTEGER NOT NULL,
  ip          TEXT,
  event       TEXT NOT NULL,    -- login_success/login_fail/mfa_pass/export_csv/...
  detail      TEXT,             -- JSON
  reason      TEXT              -- verplicht bij plaintext-export
);

CREATE TABLE magic_links (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  redeemed_at INTEGER
);
```

### 2.3 API-endpoints (v0.0.x doel)

| Methode | Pad | Auth | Doel |
|---|---|---|---|
| POST | `/auth/register` | — | Account aanmaken (e-mail + pw + akkoord-permanent-data-verlies) |
| POST | `/auth/login` | — | Pw + MFA → JWT-cookie |
| POST | `/auth/magic-link` | — | E-mail magic-link aanvragen |
| GET | `/auth/magic-link/redeem?t=...` | — | Magic-link verzilveren |
| POST | `/auth/totp/setup` | JWT | TOTP-secret genereren + QR |
| POST | `/auth/totp/verify` | JWT | TOTP-code valideren bij setup |
| POST | `/auth/logout` | JWT | Sessie eindigen |
| GET | `/vault` | JWT+MFA | Lijst van eigen vaults |
| POST | `/vault` | JWT+MFA | Nieuwe vault aanmaken (lege KDBX4-blob upload) |
| GET | `/vault/{id}` | JWT+MFA | KDBX4-blob downloaden (+ etag-header) |
| PUT | `/vault/{id}` | JWT+MFA + If-Match | Blob updaten (optimistic lock) |
| DELETE | `/vault/{id}` | JWT+MFA | Vault permanent verwijderen |
| GET | `/admin/users` | JWT+admin | User-lijst |
| POST | `/admin/users` | JWT+admin | User aanmaken |
| DELETE | `/admin/users/{id}` | JWT+admin | User + vaults verwijderen |
| GET | `/admin/stats` | JWT+admin | Storage + login-pogingen |
| GET | `/admin/audit` | JWT+admin | Audit-log |

### 2.4 Flow: vault openen

```
1. User → frontend: voer master-pw + optioneel keyfile in
2. Frontend → backend: GET /vault/{id} (JWT+MFA cookie)
3. Backend → frontend: KDBX4-blob + ETag
4. Frontend: kdbxweb.Kdbx.load(blob, credentials(pw, keyfile))
5. Frontend: render entries (in-memory)
6. User → frontend: bewerkt entry
7. Frontend: kdbxweb.Kdbx.save() → nieuwe blob
8. Frontend → backend: PUT /vault/{id} met If-Match: <oude-etag>
9a. Backend: etag matcht → blob vervangen, nieuwe etag berekenen, 200 OK + nieuwe etag
9b. Backend: etag mismatch → 412 Precondition Failed → user moet refreshen
```

### 2.5 Flow: import KDBX

```
1. User selecteert .kdbx-bestand in browser
2. Frontend: kdbxweb.Kdbx.load(file, credentials)
3. Frontend: render entries voor preview
4. User bevestigt: "importeer in vault X"
5. Frontend: merge entries in geopende vault → save() → upload (zie 2.4 stap 7-9)
```

### 2.6 Flow: export plaintext (CSV/JSON/XLSX)

```
1. User → frontend: kies export-formaat + vul reden in (verplicht)
2. Frontend → backend: POST /vault/{id}/audit-export {format, reason}
3. Backend: schrijft audit_log entry; geeft toestemming-token terug
4. Frontend: confirm-dialog "Je gaat ALLE wachtwoorden ONVERSLEUTELD downloaden. Doorgaan?"
5. Frontend: genereert plaintext download
```

## 3. Fysiek niveau

### 3.1 Hosting

| Component | Locatie |
|---|---|
| Backend FastAPI | HC55 `:3997` via systemd `horsesafe.service` |
| Statische frontend | HC55 nginx `/HorseSafe/` → `/opt/horsesafe/web/` |
| SQLite DB | HC55 `/opt/horsesafe/db/horsesafe.db` (mode 600, eigenaar `horsesafe`) |
| Vault-blobs | HC55 `/opt/horsesafe/vaults/<user-uuid>/<vault-uuid>.kdbx` (mode 600) |
| Audit-log | SQLite + append-only file `/opt/horsesafe/logs/audit.log` |
| Backup | rsync naar Hetzner-storagebox elke nacht |

### 3.2 Nginx-config (planning, nog NIET gedeployed)

```nginx
# Toevoegen aan /etc/nginx/sites-enabled/horsecloud55 (NIET vervangen — append)
location /HorseSafe/ {
    alias /opt/horsesafe/web/;
    try_files $uri $uri/ /HorseSafe/index.html;
}

location /HorseSafe/api/ {
    proxy_pass http://127.0.0.1:3997/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $proxy_scheme;
    client_max_body_size 50M;   # KDBX4-blobs kunnen attachments bevatten
}
```

### 3.3 Systemd-unit (planning)

```ini
# /etc/systemd/system/horsesafe.service
[Unit]
Description=HorseSafe password-safe backend
After=network.target

[Service]
Type=simple
User=horsesafe
Group=horsesafe
WorkingDirectory=/opt/horsesafe/backend
ExecStart=/opt/horsesafe/venv/bin/uvicorn app:app --host 127.0.0.1 --port 3997
Restart=on-failure
RestartSec=5
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/horsesafe/db /opt/horsesafe/vaults /opt/horsesafe/logs

[Install]
WantedBy=multi-user.target
```

### 3.4 Poort + netwerk

- **3997** = HorseSafe-backend (lokaal, alleen via nginx-proxy bereikbaar)
- Geen externe firewall-poort nodig — nginx :443 doet TLS-termination
- TLS via Let's Encrypt (al beheerd op HC55)
