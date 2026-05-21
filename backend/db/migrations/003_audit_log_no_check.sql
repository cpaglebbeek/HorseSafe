-- Migration 003 — v0.0.4-Rivest: verwijder hardcoded CHECK-constraint op audit_log.event
-- Reden: nieuwe admin-rescue events worden frequent toegevoegd; CHECK in DDL is te rigide.
-- Event-validatie blijft via Pydantic AuditEvent in models/audit.py.
-- Idempotent: alleen vervang als de oude CHECK aanwezig is.

PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS audit_log_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT,
    ts         INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    event      TEXT NOT NULL,
    detail     TEXT,
    reason     TEXT
);

INSERT INTO audit_log_new (id, user_id, ts, ip, user_agent, event, detail, reason)
SELECT id, user_id, ts, ip, user_agent, event, detail, reason FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_user_ts ON audit_log(user_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event);

PRAGMA foreign_keys = ON;

INSERT OR REPLACE INTO schema_version (version) VALUES (3);
