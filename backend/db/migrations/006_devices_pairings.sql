-- Migration 006 — v0.3.4-Miller deel 2: telefoon koppelen (docs/HARDWARE_KEYS.md §13.7)
-- De tabel devices bestaat al sinds 005 (leeg, voor de FK van vault_keys.device_id).
-- pairings: koppelsessies (QR + SAS). De server bewaart alleen k_srv (HKDF uit het browsergeheim s),
-- nooit s of k_web; k_srv wordt bij 'confirmed'/'cancelled' gewist ('').
-- device_nonces: eenmalige nonces van device-requests (§13.6), opgeruimd na 120 s.
-- schema.sql blijft op versie 5; migrate.py past deze migratie toe (ook bij een verse installatie).

ALTER TABLE devices ADD COLUMN confirmed_at INTEGER;
CREATE TABLE pairings (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, k_srv TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','claimed','confirmed','cancelled')),
  mac_failures INTEGER NOT NULL DEFAULT 0, device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  key_id TEXT, claim_json TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  claimed_at INTEGER, confirmed_at INTEGER);
CREATE INDEX idx_pairings_user ON pairings(user_id, created_at);
CREATE TABLE device_nonces (device_id TEXT NOT NULL, nonce TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (device_id, nonce));
INSERT OR REPLACE INTO schema_version (version) VALUES (6);
