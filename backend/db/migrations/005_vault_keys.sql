-- Migration 005 — v0.2.0-Koblitz: ontgrendelen met hardware-sleutels (WebAuthn PRF)
-- Per gekoppelde sleutel bewaart de server een VERZEGELDE kopie van het vault-ontgrendelmateriaal
-- (master-pw en/of keyfile). Verzegeld met ECIES naar een X25519-publieke sleutel waarvan de
-- privésleutel uitsluitend in de browser wordt afgeleid uit de PRF-uitvoer van de sleutel.
-- De server kan de kopie dus NIET ontsleutelen (P-CRYPT-01, aangescherpt 2026-10-10).

CREATE TABLE IF NOT EXISTS vault_keys (
    id                    TEXT PRIMARY KEY,          -- UUID v4
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vault_id              TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK (kind IN ('bio', 'recovery')),
    label                 TEXT NOT NULL,
    credential_id         TEXT NOT NULL,             -- WebAuthn credential-id (base64url)
    prf_salt              TEXT NOT NULL,             -- 32 bytes base64url — niet geheim
    public_key            TEXT NOT NULL,             -- X25519 raw 32 bytes base64url
    sealed                TEXT NOT NULL,             -- verzegelde kopie (JSON, base64url-velden)
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    last_used_at          INTEGER,
    release_requested_at  INTEGER,                   -- alleen kind='recovery'
    release_at            INTEGER,                   -- alleen kind='recovery'
    UNIQUE (user_id, credential_id)
);
CREATE INDEX IF NOT EXISTS idx_vault_keys_vault ON vault_keys(vault_id);

DELETE FROM schema_version;
INSERT INTO schema_version (version) VALUES (5);
