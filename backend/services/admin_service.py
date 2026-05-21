from __future__ import annotations

import contextlib
import time
from pathlib import Path

import aiosqlite


async def list_users(conn: aiosqlite.Connection) -> list[dict[str, object]]:
    """Return user-meta lijst met vault-count + storage + has_totp + has_backup_codes."""
    cursor = await conn.execute("""
        SELECT
            u.id, u.email, u.is_admin, u.created_at, u.last_login_at,
            (u.totp_secret IS NOT NULL) AS has_totp,
            (SELECT COUNT(*) FROM users_backup_codes b
                WHERE b.user_id = u.id AND b.used_at IS NULL) AS backup_codes_remaining,
            (SELECT COUNT(*) FROM vaults v WHERE v.user_id = u.id) AS vault_count,
            (SELECT COALESCE(SUM(v.size_bytes), 0) FROM vaults v
                WHERE v.user_id = u.id) AS storage_bytes
        FROM users u
        ORDER BY u.created_at DESC
        """)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def delete_user_cascade(conn: aiosqlite.Connection, user_id: str, vaults_dir: Path) -> bool:
    """Verwijder user + vault-blobs van disk + DB-rows (cascading via FK)."""
    # Eerst blobs van disk halen
    cursor = await conn.execute("SELECT blob_path FROM vaults WHERE user_id = ?", (user_id,))
    blobs = [str(r["blob_path"]) for r in await cursor.fetchall()]
    for blob in blobs:
        with contextlib.suppress(OSError):
            Path(blob).unlink(missing_ok=True)
    # Probeer user-dir te verwijderen (best-effort)
    user_dir = vaults_dir / user_id
    if user_dir.exists():
        with contextlib.suppress(OSError):
            user_dir.rmdir()
    # DB-cascade
    cursor = await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await conn.commit()
    return cursor.rowcount > 0


async def get_stats(conn: aiosqlite.Connection) -> dict[str, object]:
    """Aggregate stats voor dashboard."""
    now = int(time.time())
    day_ago = now - 86400

    async def scalar(sql: str, params: tuple = ()) -> int:
        cur = await conn.execute(sql, params)
        row = await cur.fetchone()
        if row is None:
            return 0
        val = next(iter(row), 0)
        return int(val or 0)

    users_total = await scalar("SELECT COUNT(*) FROM users")
    vaults_total = await scalar("SELECT COUNT(*) FROM vaults")
    storage_bytes = await scalar("SELECT COALESCE(SUM(size_bytes), 0) FROM vaults")
    logins_24h = await scalar(
        "SELECT COUNT(*) FROM audit_log WHERE event = 'login_success' AND ts > ?",
        (day_ago,),
    )
    failed_logins_24h = await scalar(
        "SELECT COUNT(*) FROM audit_log WHERE event = 'login_fail' AND ts > ?",
        (day_ago,),
    )
    cursor = await conn.execute("""SELECT u.email, COALESCE(SUM(v.size_bytes), 0) AS bytes
           FROM users u LEFT JOIN vaults v ON v.user_id = u.id
           GROUP BY u.id ORDER BY bytes DESC LIMIT 10""")
    top10 = [{"email": str(r["email"]), "bytes": int(r["bytes"])} for r in await cursor.fetchall()]

    return {
        "users_total": users_total,
        "vaults_total": vaults_total,
        "storage_bytes": storage_bytes,
        "logins_24h": logins_24h,
        "failed_logins_24h": failed_logins_24h,
        "top10_users_by_storage": top10,
    }


async def query_audit(
    conn: aiosqlite.Connection,
    user_id: str | None = None,
    event: str | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, object]]:
    clauses = []
    params: list[object] = []
    if user_id:
        clauses.append("user_id = ?")
        params.append(user_id)
    if event:
        clauses.append("event = ?")
        params.append(event)
    if from_ts:
        clauses.append("ts >= ?")
        params.append(from_ts)
    if to_ts:
        clauses.append("ts <= ?")
        params.append(to_ts)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    # SQL is opgebouwd uit gewhitelistede clauses (geen user-input concatenation);
    # alle waarden gaan als parameters mee. S608 false positive op f-string-format.
    sql = f"SELECT * FROM audit_log{where} ORDER BY ts DESC LIMIT ? OFFSET ?"  # noqa: S608
    params.extend([limit, offset])
    cursor = await conn.execute(sql, tuple(params))
    return [dict(r) for r in await cursor.fetchall()]
