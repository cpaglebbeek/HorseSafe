# DATA_MODEL.md — HorseSafe

> Server-side datamodel (SQLite + filesystem). Client-side datamodel (KDBX4 in-memory) staat in KeePassXC-spec. Cross-ref: `ARCHITECTURE.md §2.2`, `THREAT_MODEL.md §vault-content vs metadata`.

## Server-side

### users
```sql
CREATE TABLE users (
  id              TEXT PRIMARY KEY,        -- UUID v4
  email           TEXT UNIQUE NOT NULL,
  pw_hash         TEXT NOT NULL,           -- argon2id, format: $argon2id$v=19$...
  totp_secret     TEXT,                    -- base32, NULL = TOTP niet ingesteld
  magic_link_only BOOLEAN NOT NULL DEFAULT 0,
  is_admin        BOOLEAN NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,        -- unix epoch
  last_login_at   INTEGER,
  CHECK (email LIKE '%@%')
);
CREATE INDEX idx_users_email ON users(email);
```

### vaults
```sql
CREATE TABLE vaults (
  id            TEXT PRIMARY KEY,          -- UUID v4
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,             -- 'default' in v0.0.x; v0.1.x = user-gekozen (max 64 chars)
  blob_path     TEXT NOT NULL,             -- absoluut pad
  size_bytes    INTEGER NOT NULL,
  etag          TEXT NOT NULL,             -- SHA-256 hex
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  UNIQUE(user_id, name)
);
CREATE INDEX idx_vaults_user ON vaults(user_id);
```

### audit_log
```sql
CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT,                        -- NULL bij login-fail vóór user-resolve
  ts          INTEGER NOT NULL,
  ip          TEXT,                        -- ipv4 of ipv6
  user_agent  TEXT,
  event       TEXT NOT NULL,
  detail      TEXT,                        -- JSON
  reason      TEXT,                        -- verplicht bij plaintext-export-events
  CHECK (event IN (
    'register','login_success','login_fail','login_throttled',
    'mfa_setup_totp','mfa_pass_totp','mfa_pass_magic_link','mfa_fail',
    'logout','session_expired',
    'vault_create','vault_read','vault_update','vault_delete',
    'export_kdbx','export_csv','export_json','export_xlsx',
    'import_kdbx','import_bitwarden','import_csv','import_xlsx',
    'admin_user_create','admin_user_delete','admin_stats_view','admin_audit_view'
  ))
);
CREATE INDEX idx_audit_user_ts ON audit_log(user_id, ts);
CREATE INDEX idx_audit_event ON audit_log(event);
```

### magic_links
```sql
CREATE TABLE magic_links (
  token       TEXT PRIMARY KEY,            -- 32 random bytes hex
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,            -- max 10 min
  redeemed_at INTEGER                       -- single-use
);
CREATE INDEX idx_magic_expires ON magic_links(expires_at);
```

### failed_logins (throttle-tracking)
```sql
CREATE TABLE failed_logins (
  ip          TEXT NOT NULL,
  email       TEXT,
  ts          INTEGER NOT NULL
);
CREATE INDEX idx_failed_ip_ts ON failed_logins(ip, ts);
CREATE INDEX idx_failed_email_ts ON failed_logins(email, ts);
-- regulier opruimen: DELETE WHERE ts < NOW - 24h
```

## Filesystem-layout

```
/opt/horsesafe/
├── backend/          # FastAPI-code (deployed)
├── venv/             # Python venv
├── web/              # Statische frontend (nginx-served)
├── db/
│   └── horsesafe.db  # SQLite (mode 600)
├── vaults/
│   └── <user-uuid>/
│       └── <vault-uuid>.kdbx   # KDBX4-blob (mode 600)
├── logs/
│   ├── audit.log     # Append-only, dagelijks geroteerd
│   └── access.log    # FastAPI request-log
└── tmp/              # Upload-staging (PrivateTmp via systemd)
```

## Data-retentie

| Categorie | Retentie | GDPR-basis |
|---|---|---|
| users-row | Tot expliciete delete door user/admin | Art. 6(1)(b) contract |
| vault-blob | Tot delete | Art. 6(1)(b) |
| audit_log | 13 maanden, daarna geanonimiseerd (user_id → NULL) | Art. 6(1)(f) gerechtvaardigd belang security |
| magic_links | Tot redemption of expiry (max 10 min) | n/a transient |
| failed_logins | 24 uur | n/a transient |
| Backups (encrypted) | 30 dagen rolling | Art. 32 security |

## Geen velden

**Bewust níet opgeslagen:**
- Master-pw (vault-pw) of hash daarvan
- Keyfile-content of hash daarvan
- Derived key (Argon2id-output)
- Vault-content (entries, attachments) in queryable vorm
- KDF-parameters apart (zit in KDBX-header binnen blob)

## Schema-versionering

Migrations in `backend/db/migrations/NNN_<naam>.sql`. Eerste migration: `001_initial.sql`. Schema-versie in tabel `schema_version (version INTEGER)`.
