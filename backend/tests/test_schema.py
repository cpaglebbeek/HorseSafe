"""v0.2.0-Koblitz — migratie 005 (herschreven) en schema.sql (§12.9)."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

DB_DIR = Path(__file__).resolve().parent.parent / "db"
SCHEMA = (DB_DIR / "schema.sql").read_text(encoding="utf-8")
MIG005 = (DB_DIR / "migrations" / "005_vault_keys.sql").read_text(encoding="utf-8")
KOBLITZ_MARKER = "-- v0.2.0-Koblitz: hardware-sleutels per vault"
TABLES = (
    "devices",
    "vault_keys",
    "webauthn_challenges",
    "pairings",
    "device_nonces",
    "trusted_browsers",
    "browser_challenges",
    "approvals",
    "revoked_sessions",
)


def _ddl(db: Path) -> dict[str, str]:
    con = sqlite3.connect(db)
    try:
        rows = con.execute(
            f"SELECT name, sql FROM sqlite_master WHERE tbl_name IN ({','.join('?' * len(TABLES))}) "  # noqa: S608
            "AND sql IS NOT NULL",
            TABLES,
        ).fetchall()
    finally:
        con.close()
    return dict(rows)


def _version(db: Path) -> int:
    con = sqlite3.connect(db)
    try:
        return int(con.execute("SELECT MAX(version) FROM schema_version").fetchone()[0])
    finally:
        con.close()


def test_005_has_no_delete_and_sets_version() -> None:
    assert "DELETE FROM schema_version" not in MIG005
    assert "INSERT OR REPLACE INTO schema_version (version) VALUES (5);" in MIG005
    assert "INSERT OR IGNORE INTO schema_version (version) VALUES (5);" in SCHEMA


async def test_schema_sql_equals_schema4_plus_005(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A: verse installatie via schema.sql (schema 5) + migrate.py (006 Miller, 007 Montgomery)
    a = tmp_path / "a.db"
    con = sqlite3.connect(a)
    con.executescript(SCHEMA)
    con.close()
    assert _version(a) == 5
    from backend.db.migrate import run_migrations

    monkeypatch.setenv("HORSESAFE_DB_PATH", str(a))
    assert await run_migrations() == [6, 7]
    assert _version(a) == 7

    # B: schema 4 (schema.sql zonder het Koblitz-deel) + migratie 005 via de migratierunner
    assert KOBLITZ_MARKER in SCHEMA
    schema4 = SCHEMA.split(KOBLITZ_MARKER)[0].replace(
        "INSERT OR IGNORE INTO schema_version (version) VALUES (5);",
        "INSERT OR IGNORE INTO schema_version (version) VALUES (4);",
    )
    b = tmp_path / "b.db"
    con = sqlite3.connect(b)
    con.executescript(schema4)
    con.close()
    assert _version(b) == 4 and _ddl(b) == {}

    monkeypatch.setenv("HORSESAFE_DB_PATH", str(b))
    assert await run_migrations() == [5, 6, 7]
    assert _version(b) == 7
    ddl_a, ddl_b = _ddl(a), _ddl(b)
    assert set(ddl_a) >= {"devices", "vault_keys", "webauthn_challenges", "idx_vault_keys_vault"}
    assert set(ddl_a) >= {"pairings", "device_nonces", "idx_pairings_user"}
    assert "confirmed_at" in ddl_a["devices"]
    assert set(ddl_a) >= {
        "trusted_browsers",
        "browser_challenges",
        "approvals",
        "revoked_sessions",
        "idx_tb_user",
        "idx_approvals_user",
    }
    assert ddl_a == ddl_b


def test_005_ddl_block_identical_in_both_files() -> None:
    def block(s: str) -> str:
        start = s.index("CREATE TABLE IF NOT EXISTS devices")
        end = s.index("idx_webauthn_challenges_user")
        return re.sub(r"[ \t]+\n", "\n", s[start:end])

    assert block(SCHEMA) == block(MIG005)


def test_vault_keys_constraints(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    con.execute("INSERT INTO users (id, email, pw_hash, created_at) VALUES ('u', 'u@x.nl', 'h', 0)")
    con.execute(
        "INSERT INTO vaults (id, user_id, name, blob_path, size_bytes, etag, created_at, updated_at)"
        " VALUES ('v', 'u', 'n', 'p', 0, 'e', 0, 0)"
    )
    base = (
        "INSERT INTO vault_keys (id, user_id, vault_id, kind, label, status, credential_id,"
        " cose_public_key, prf_salt, public_key, sealed, created_at, updated_at)"
        " VALUES (?, 'u', 'v', ?, 'l', ?, ?, 'c', 's', 'p', 'x', 0, 0)"
    )
    con.execute(base, ("k1", "bio", "active", "cred1"))
    with pytest.raises(sqlite3.IntegrityError):  # bio kan niet geblokkeerd worden
        con.execute(base, ("k2", "bio", "blocked", "cred2"))
    with pytest.raises(sqlite3.IntegrityError):  # phone vereist device_id
        con.execute(base, ("k3", "phone", "active", "cred3"))
    with pytest.raises(sqlite3.IntegrityError):  # zelfde credential bij zelfde gebruiker
        con.execute(base, ("k4", "recovery", "active", "cred1"))
    con.execute(base, ("k5", "recovery", "blocked", "cred5"))
    con.close()


async def test_wip_005_db_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "wip.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE vault_keys (id TEXT PRIMARY KEY, kind TEXT)")
    con.close()
    monkeypatch.setenv("HORSESAFE_DB_PATH", str(db))
    from backend.db.migrate import check_vault_keys_schema

    with pytest.raises(RuntimeError, match="WIP-schema"):
        await check_vault_keys_schema()
