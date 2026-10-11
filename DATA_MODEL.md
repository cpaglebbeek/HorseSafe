# DATA_MODEL.md — HorseSafe

> Server-side datamodel (SQLite + filesystem). Client-side datamodel (KDBX4 in-memory) staat in KeePassXC-spec. Cross-ref: `ARCHITECTURE.md §2.2`, `THREAT_MODEL.md §vault-content vs metadata`, `docs/HARDWARE_KEYS.md` §12.9 (normatieve DDL van migratie 005).
>
> **Schema-versie: 5** (v0.2.0-Koblitz). De bron van waarheid is `backend/db/schema.sql` (fresh install = alle migraties) plus `backend/db/migrations/`. De DDL hieronder voor de oudere tabellen is een samenvatting; `shares` (004) en `users_backup_codes` (002) staan alleen in `schema.sql`.

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
  -- NB: de CHECK hieronder is sinds migratie 003_audit_log_no_check vervallen;
  -- de lijst is historisch. Koblitz-events: zie 'Audit-events v0.2.0-Koblitz' hieronder.
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

### vault_keys (v0.2.0-Koblitz, migratie 005)

Hardware-sleutels per vault met hun verzegelde ontgrendelkopie (P-CRYPT-09). De server kan `sealed` niet openen: het privédeel van `public_key` bestaat alleen in de YubiKey (PRF) of, vanaf Miller, in de Android Keystore.

```sql
CREATE TABLE vault_keys (
  id                    TEXT PRIMARY KEY,                 -- UUID v4 (= key_id uit register-opties)
  user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id              TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  kind                  TEXT NOT NULL CHECK (kind IN ('bio', 'recovery', 'phone')),   -- 'phone' pas vanaf Miller
  label                 TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'revoked')),
  device_id             TEXT REFERENCES devices(id) ON DELETE CASCADE,   -- alleen kind='phone'
  credential_id         TEXT,                             -- WebAuthn, b64u
  cose_public_key       TEXT,                             -- WebAuthn, b64u (COSE_Key)
  aaguid                TEXT,                             -- UUID-string
  att_fmt               TEXT,                             -- 'packed' (of 'none' in tests)
  sign_count            INTEGER NOT NULL DEFAULT 0,
  prf_salt              TEXT,                             -- 32 B b64u, niet geheim
  public_key            TEXT NOT NULL,                    -- X25519 pk_c, 32 B b64u
  sealed                TEXT NOT NULL,                    -- Seal_v2-JSON {v,kid,epk,iv,ct}; inhoud {ph,kh}
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL,
  last_used_at          INTEGER,
  release_requested_at  INTEGER,                          -- alleen recovery
  release_at            INTEGER,                          -- alleen recovery (aanvraag + 24 u)
  release_consumed_at   INTEGER,                          -- alleen recovery
  blocked_at            INTEGER,                          -- alleen recovery
  blocked_by            TEXT,                             -- 'web' | 'device:<id>'
  CHECK ((kind = 'phone') = (device_id IS NOT NULL)),
  CHECK (kind = 'phone' OR (credential_id IS NOT NULL AND cose_public_key IS NOT NULL AND prf_salt IS NOT NULL)),
  CHECK (status <> 'blocked' OR kind = 'recovery'),
  UNIQUE (user_id, credential_id)
);
CREATE INDEX idx_vault_keys_vault ON vault_keys(vault_id);
CREATE INDEX idx_vault_keys_user ON vault_keys(user_id);
```

**Recovery-state** wordt niet opgeslagen maar afgeleid (`vault_key_service.recovery_state`): `blocked` als `status='blocked'`; `idle` zonder `release_at`; `consumed` als `release_consumed_at` gezet is; `waiting` vóór `release_at`; `released` tot `release_at + 24 u`; daarna `expired`. Een blokkade vervalt nooit vanzelf (besluit 3).

### webauthn_challenges (v0.2.0-Koblitz, migratie 005)

```sql
CREATE TABLE webauthn_challenges (
  id              TEXT PRIMARY KEY,                   -- UUID v4 = challenge_id
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose         TEXT NOT NULL CHECK (purpose IN ('register', 'register_assert', 'unlock', 'stepup')),
  parent_id       TEXT REFERENCES webauthn_challenges(id) ON DELETE CASCADE,  -- register_assert -> register
  vault_id        TEXT REFERENCES vaults(id) ON DELETE CASCADE,
  kind            TEXT CHECK (kind IS NULL OR kind IN ('bio', 'recovery', 'phone')),
  key_id          TEXT,                               -- register: het toekomstige vault_keys.id
  prf_salt        TEXT,                               -- register: b64u 32 B
  challenge_hash  TEXT NOT NULL,                      -- hex SHA-256 van de challenge; nooit de challenge zelf
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,                   -- + 300 s
  used_at         INTEGER                             -- eenmalig, atomair gezet vóór de controles
);
CREATE INDEX idx_webauthn_challenges_user ON webauthn_challenges(user_id, expires_at);
```

### devices (migratie 005, leeg tot v0.3.0-Miller)

Staat er alleen voor de foreign key van `vault_keys.device_id`, zodat Miller zonder table-rebuild kan bouwen. Kolommen: `id`, `user_id`, `label`, `model`, `k_dev_pub`, `k_biosig_pub`, `att_chains`, `security_level`, `strongbox`, `app_version`, `created_at`, `last_seen_at`, `revoked_at`. De Koblitz-API schrijft hier niets in.

### JWT-claims (geen tabel)

Sinds v0.2.0-Koblitz kan het sessie-JWT na een geslaagde step-up twee extra claims dragen: `stepup_until` (Unix-tijd) en `stepup_method` (`bio` | `totp`). Ze vervallen bij een gewone login of MFA-heruitgifte.

### Audit-events v0.2.0-Koblitz

`vault_key_add`, `vault_key_add_rejected`, `vault_key_delete`, `vault_key_unlock`, `vault_key_reseal`, `vault_key_clone_suspect`, `vault_rekey`, `recovery_release_request`, `recovery_release_cancel`, `recovery_key_used`, `recovery_block`, `recovery_unblock`, `recovery_unblock_rejected`, `stepup`, `stepup_fail`, `notify_failed`. `detail` bevat alleen ids, `kind`, `aaguid`, tijden, foutcodes en tellingen; nooit `sealed`, `ph`, `kh`, PRF-uitvoer, challenges, client-data, signatures, TOTP-codes of SMTP-gegevens.

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
| vault_keys | Tot verwijderen door de gebruiker, of mee met vault/account (CASCADE) | Art. 6(1)(b) |
| webauthn_challenges | Max. 300 s geldig; opgeruimd na 1 dag | n/a transient |
| Backups (encrypted) | 30 dagen rolling | Art. 32 security |

## Geen velden

**Bewust níet opgeslagen:**
- Master-pw (vault-pw) of hash daarvan — leesbaar of in een vorm die de server kan openen
- Keyfile-content of hash daarvan — idem. Enige uitzondering: de verzegelde kopie `{ph,kh}` in `vault_keys.sealed`, verzegeld naar gebruikershardware (P-CRYPT-09); de server heeft de sleutel niet
- PRF-uitvoer, X25519-privésleutels, WebAuthn-challenges in leesbare vorm (alleen de SHA-256-hash), assertions/signatures
- Biometrische gegevens: de vingerafdruk blijft in de YubiKey Bio; de server ziet alleen de UV-vlag
- Derived key (Argon2id-output)
- Vault-content (entries, attachments) in queryable vorm
- KDF-parameters apart (zit in KDBX-header binnen blob)

## Schema-versionering

Migrations in `backend/db/migrations/NNN_<naam>.sql`. Eerste migration: `001_initial.sql`. Schema-versie in tabel `schema_version (version INTEGER)`. Huidig: **5** (`005_vault_keys.sql`, herschreven in v0.2.0-Koblitz; de WIP-versie is nooit gedeployed). Migraties zetten de versie met `INSERT OR REPLACE INTO schema_version`, nooit met `DELETE FROM schema_version`. Gepland: 006 (Miller: `pairings`, `device_nonces`), 007 (Montgomery: `approvals`, `revoked_sessions`).
