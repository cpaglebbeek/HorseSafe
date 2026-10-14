-- HorseSafe SQLite schema v0.2.0-Koblitz
-- Server-side ONLY. Vault-content zelf ligt op disk als KDBX4-ciphertext.
-- Schema-versie 5: omvat alle migrations 001-005 in één fresh-install-blob.
-- Bestaande installs migreren via db/migrations/*.sql. De DDL van 005 hieronder is letterlijk
-- gelijk aan migrations/005_vault_keys.sql (gecontroleerd door tests/test_schema.py).
-- Migraties vanaf 006 (v0.3.4-Miller: ALTER TABLE devices, pairings, device_nonces) staan hier
-- bewust NIET in: init_db draait dit bestand bij elke start opnieuw en ALTER TABLE is niet
-- idempotent. Ook een verse installatie krijgt ze via migrate.py (lifespan: init_db -> run_migrations).

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);
INSERT OR IGNORE INTO schema_version (version) VALUES (5);

CREATE TABLE IF NOT EXISTS users (
    id                TEXT PRIMARY KEY,
    email             TEXT UNIQUE NOT NULL,
    pw_hash           TEXT NOT NULL,
    totp_secret       TEXT,
    magic_link_only   INTEGER NOT NULL DEFAULT 0,
    is_admin          INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    last_login_at     INTEGER,
    pubkey            TEXT,                       -- ECDH P-256 public key (JWK base64); v0.0.6+
    encrypted_privkey TEXT,                       -- AES-GCM-encrypted ECDH-private; v0.0.6+
    CHECK (email LIKE '%@%')
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS vaults (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    blob_path     TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    etag          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT,
    ts         INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    event      TEXT NOT NULL,
    detail     TEXT,
    reason     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_user_ts ON audit_log(user_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event);

CREATE TABLE IF NOT EXISTS magic_links (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    redeemed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_magic_expires ON magic_links(expires_at);

CREATE TABLE IF NOT EXISTS failed_logins (
    ip    TEXT NOT NULL,
    email TEXT,
    ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_failed_ip_ts ON failed_logins(ip, ts);
CREATE INDEX IF NOT EXISTS idx_failed_email_ts ON failed_logins(email, ts);

-- v0.0.6-Adleman: Vault-sharing tussen users
CREATE TABLE IF NOT EXISTS shares (
    id                 TEXT PRIMARY KEY,
    from_user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_payload  TEXT NOT NULL,
    title_hint         TEXT,
    created_at         INTEGER NOT NULL,
    accepted_at        INTEGER,
    declined_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_shares_to_user ON shares(to_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shares_from_user ON shares(from_user_id, created_at DESC);

-- v0.0.4-Rivest: MFA backup-codes
CREATE TABLE IF NOT EXISTS users_backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,         -- bcrypt
    created_at INTEGER NOT NULL,
    used_at    INTEGER                -- NULL = nog niet gebruikt; single-use
);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON users_backup_codes(user_id);

-- v0.2.0-Koblitz: hardware-sleutels per vault (P-CRYPT-09) — migratie 005
CREATE TABLE IF NOT EXISTS devices (               -- Miller vult deze tabel; nu leeg, staat er voor de FK
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    model           TEXT,
    k_dev_pub       TEXT NOT NULL,
    k_biosig_pub    TEXT NOT NULL,
    att_chains      TEXT NOT NULL,
    security_level  TEXT NOT NULL,
    strongbox       INTEGER NOT NULL DEFAULT 0,
    app_version     TEXT,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    revoked_at      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS vault_keys (
    id                    TEXT PRIMARY KEY,                 -- UUID v4 (= key_id uit register-opties)
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vault_id              TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK (kind IN ('bio', 'recovery', 'phone')),
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
    sealed                TEXT NOT NULL,                    -- Seal_v2-JSON
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    last_used_at          INTEGER,
    release_requested_at  INTEGER,                          -- alleen recovery
    release_at            INTEGER,                          -- alleen recovery
    release_consumed_at   INTEGER,                          -- alleen recovery
    blocked_at            INTEGER,                          -- alleen recovery
    blocked_by            TEXT,                             -- 'web' | 'device:<id>'
    CHECK ((kind = 'phone') = (device_id IS NOT NULL)),
    CHECK (kind = 'phone' OR (credential_id IS NOT NULL AND cose_public_key IS NOT NULL AND prf_salt IS NOT NULL)),
    CHECK (status <> 'blocked' OR kind = 'recovery'),
    UNIQUE (user_id, credential_id)
);
CREATE INDEX IF NOT EXISTS idx_vault_keys_vault ON vault_keys(vault_id);
CREATE INDEX IF NOT EXISTS idx_vault_keys_user ON vault_keys(user_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id              TEXT PRIMARY KEY,                   -- UUID v4 = challenge_id
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose         TEXT NOT NULL CHECK (purpose IN ('register', 'register_assert', 'unlock', 'stepup')),
    parent_id       TEXT REFERENCES webauthn_challenges(id) ON DELETE CASCADE,  -- register_assert -> register
    vault_id        TEXT REFERENCES vaults(id) ON DELETE CASCADE,
    kind            TEXT CHECK (kind IS NULL OR kind IN ('bio', 'recovery', 'phone')),
    key_id          TEXT,                               -- register: het toekomstige vault_keys.id
    prf_salt        TEXT,                               -- register: b64u 32 B
    challenge_hash  TEXT NOT NULL,                      -- hex SHA-256 van de 32 challenge-bytes; nooit de challenge zelf
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id, expires_at);
