from __future__ import annotations

import time
import uuid

import aiosqlite


async def set_keypair(
    conn: aiosqlite.Connection, user_id: str, pubkey: str, encrypted_privkey: str
) -> None:
    await conn.execute(
        "UPDATE users SET pubkey = ?, encrypted_privkey = ? WHERE id = ?",
        (pubkey, encrypted_privkey, user_id),
    )
    await conn.commit()


async def rewrap_privkey(conn: aiosqlite.Connection, user_id: str, encrypted_privkey: str) -> None:
    """Bij pw-change: vervang alleen encrypted_privkey (pubkey blijft)."""
    await conn.execute(
        "UPDATE users SET encrypted_privkey = ? WHERE id = ?",
        (encrypted_privkey, user_id),
    )
    await conn.commit()


async def get_keypair(conn: aiosqlite.Connection, user_id: str) -> tuple[str | None, str | None]:
    cursor = await conn.execute(
        "SELECT pubkey, encrypted_privkey FROM users WHERE id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    if not row:
        return None, None
    return row["pubkey"], row["encrypted_privkey"]


async def lookup_pubkey_by_email(conn: aiosqlite.Connection, email: str) -> tuple[str, str] | None:
    """Return (user_id, pubkey) of None als user niet bestaat of geen key heeft."""
    cursor = await conn.execute("SELECT id, pubkey FROM users WHERE email = ?", (email.lower(),))
    row = await cursor.fetchone()
    if not row or not row["pubkey"]:
        return None
    return str(row["id"]), str(row["pubkey"])


async def create_share(
    conn: aiosqlite.Connection,
    from_user_id: str,
    to_user_id: str,
    encrypted_payload: str,
    title_hint: str | None,
) -> str:
    share_id = str(uuid.uuid4())
    await conn.execute(
        """INSERT INTO shares
           (id, from_user_id, to_user_id, encrypted_payload, title_hint, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (share_id, from_user_id, to_user_id, encrypted_payload, title_hint, int(time.time())),
    )
    await conn.commit()
    return share_id


async def list_inbox(conn: aiosqlite.Connection, user_id: str) -> list[dict[str, object]]:
    """List pending shares (geen accepted_at, geen declined_at) voor deze user."""
    cursor = await conn.execute(
        """SELECT s.id, s.encrypted_payload, s.title_hint, s.created_at,
                  u.email AS from_email, u.pubkey AS from_pubkey
           FROM shares s
           JOIN users u ON u.id = s.from_user_id
           WHERE s.to_user_id = ? AND s.accepted_at IS NULL AND s.declined_at IS NULL
           ORDER BY s.created_at DESC""",
        (user_id,),
    )
    return [dict(r) for r in await cursor.fetchall()]


async def list_sent(conn: aiosqlite.Connection, user_id: str) -> list[dict[str, object]]:
    """List verzonden shares (alle statussen)."""
    cursor = await conn.execute(
        """SELECT s.id, s.title_hint, s.created_at, s.accepted_at, s.declined_at,
                  u.email AS to_email
           FROM shares s
           JOIN users u ON u.id = s.to_user_id
           WHERE s.from_user_id = ?
           ORDER BY s.created_at DESC""",
        (user_id,),
    )
    return [dict(r) for r in await cursor.fetchall()]


async def accept_share(conn: aiosqlite.Connection, share_id: str, user_id: str) -> bool:
    """Markeer share als accepted. Returnt False als share niet van user is of al verwerkt."""
    cursor = await conn.execute(
        """UPDATE shares SET accepted_at = ?
           WHERE id = ? AND to_user_id = ? AND accepted_at IS NULL AND declined_at IS NULL""",
        (int(time.time()), share_id, user_id),
    )
    await conn.commit()
    return bool(cursor.rowcount and cursor.rowcount > 0)


async def decline_share(conn: aiosqlite.Connection, share_id: str, user_id: str) -> bool:
    cursor = await conn.execute(
        """UPDATE shares SET declined_at = ?
           WHERE id = ? AND to_user_id = ? AND accepted_at IS NULL AND declined_at IS NULL""",
        (int(time.time()), share_id, user_id),
    )
    await conn.commit()
    return bool(cursor.rowcount and cursor.rowcount > 0)
