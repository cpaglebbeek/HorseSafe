-- HorseSafe SQLite schema v0.0.1-Diffie
-- Server-side ONLY. Vault-content zelf ligt op disk als KDBX4-ciphertext.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    pw_hash         TEXT NOT NULL,
    totp_secret     TEXT,
    magic_link_only INTEGER NOT NULL DEFAULT 0,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_login_at   INTEGER,
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

-- v0.0.4-Rivest: MFA backup-codes
CREATE TABLE IF NOT EXISTS users_backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,         -- bcrypt
    created_at INTEGER NOT NULL,
    used_at    INTEGER                -- NULL = nog niet gebruikt; single-use
);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON users_backup_codes(user_id);
