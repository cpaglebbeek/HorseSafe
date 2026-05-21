from __future__ import annotations

import aiosqlite

from . import auth_service


async def change_account_password(
    conn: aiosqlite.Connection,
    user_id: str,
    old_password: str,
    new_password: str,
) -> bool:
    """Verifieer oude account-pw + hash nieuwe + opslaan.

    Returns False bij verkeerde old_password. Raise ValueError bij zwakke new_password (< 12).
    NB: account-pw, NIET vault-master-pw (die blijft client-only).
    """
    if len(new_password) < 12:
        raise ValueError("password_too_short")
    cursor = await conn.execute("SELECT pw_hash FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    if not row:
        return False
    if not auth_service.verify_password(old_password, row["pw_hash"]):
        return False
    new_hash = auth_service.hash_password(new_password)
    await conn.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (new_hash, user_id))
    await conn.commit()
    return True
