-- Migration 002 — v0.0.4-Rivest: MFA backup-codes
-- Idempotent: alleen toepassen wanneer table niet bestaat.

CREATE TABLE IF NOT EXISTS users_backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON users_backup_codes(user_id);

INSERT OR REPLACE INTO schema_version (version) VALUES (2);
