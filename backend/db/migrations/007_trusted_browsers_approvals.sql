-- Migration 007 — v0.4.0-Montgomery: vertrouwde browser + telefoonvinger (docs/HARDWARE_KEYS.md §14.7)
-- trusted_browsers: per browser per kluis de publieke sleutel K_B (SPKI) en het koppelbewijs (HMAC
--   met een sleutel uit CK; de server kan het niet narekenen). Geen ontgrendelmateriaal (P-CRYPT-09).
-- browser_challenges: eenmalige inlog-challenges (TTL 120 s), ook voor onbekende e-mailadressen.
-- approvals: ontgrendelverzoeken browser → telefoon. resp (Seal_v2 'relay') wordt bij
--   consumed/expired/cancelled gewist (NULL); verlopen rijen ruimt de server lui op.
-- revoked_sessions: ingetrokken JWT-sessies (sid); jwt-decode controleert deze tabel.
-- schema.sql blijft op versie 5; migrate.py past deze migratie toe (ook bij een verse installatie).

CREATE TABLE trusted_browsers (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, pub_b TEXT NOT NULL, label TEXT NOT NULL,
  proof TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER, revoke_reason TEXT,
  cooldown_until INTEGER);
CREATE INDEX idx_tb_user ON trusted_browsers(user_id);
CREATE TABLE browser_challenges (id TEXT PRIMARY KEY, email_lc TEXT NOT NULL, challenge TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE approvals (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  browser_id TEXT NOT NULL REFERENCES trusted_browsers(id) ON DELETE CASCADE, sid TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft','pending','approved','denied','consumed','cancelled','expired')),
  epk_l TEXT, nonce_l TEXT, sig_req TEXT, resp TEXT, device_id TEXT, deny_reason TEXT, ip TEXT, ua TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER);
CREATE INDEX idx_approvals_user ON approvals(user_id, created_at);
CREATE TABLE revoked_sessions (sid TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
INSERT OR REPLACE INTO schema_version (version) VALUES (7);
