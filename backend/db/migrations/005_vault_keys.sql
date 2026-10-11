-- Migration 005 — v0.2.0-Koblitz: hardware-sleutels per vault (P-CRYPT-09)
-- Per gekoppelde sleutel bewaart de server een kopie van het ontgrendelmateriaal {ph,kh}, VERZEGELD
-- (Seal_v2) naar een X25519-publieke sleutel per credential. Het privédeel bestaat alleen in de
-- hardware van de gebruiker (YubiKey-PRF); de server kan de kopie aantoonbaar niet openen.
-- Herschreven t.o.v. de WIP-005 (nooit gedeployed; productie staat op schema 4). Dev-DB's die de
-- WIP-005 al hadden, opnieuw aanmaken. Zie docs/HARDWARE_KEYS.md §12.9. Miller = 006, Montgomery = 007.

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

INSERT OR REPLACE INTO schema_version (version) VALUES (5);
