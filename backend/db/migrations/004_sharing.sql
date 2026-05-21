-- Migration 004 — v0.0.6-Adleman: Vault-sharing tussen users via ECDH-P256
-- Server-side: public-keys + encrypted-private-keys + share-payloads (encrypted).
-- Zero-knowledge intact: server kan geen plaintext entries of private keys lezen.

-- Voeg key-pair-kolommen toe aan users
ALTER TABLE users ADD COLUMN pubkey TEXT;
ALTER TABLE users ADD COLUMN encrypted_privkey TEXT;

-- Shares: encrypted-entry-payloads van zender naar ontvanger
CREATE TABLE IF NOT EXISTS shares (
    id                 TEXT PRIMARY KEY,         -- UUID v4
    from_user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_payload  TEXT NOT NULL,            -- base64 JSON: {ephemeral_pubkey, iv, ciphertext}
    title_hint         TEXT,                     -- optional plaintext hint (entry-title) — user-controlled
    created_at         INTEGER NOT NULL,
    accepted_at        INTEGER,
    declined_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_shares_to_user ON shares(to_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shares_from_user ON shares(from_user_id, created_at DESC);

INSERT OR REPLACE INTO schema_version (version) VALUES (4);
