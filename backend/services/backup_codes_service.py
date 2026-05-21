from __future__ import annotations

import secrets
import time

import aiosqlite
import bcrypt

# Char-set zonder look-alikes (geen 0/O, 1/I/L)
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _hash(code: str) -> str:
    import os

    # In test-mode lichte rounds voor snelheid; productie default 12
    rounds = int(os.environ.get("HORSESAFE_BCRYPT_ROUNDS", "12"))
    return bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def _verify(code: str, hashed: str) -> bool:
    try:
        return bool(bcrypt.checkpw(code.encode("utf-8"), hashed.encode("utf-8")))
    except (ValueError, TypeError):
        return False


def _generate_code() -> str:
    """Genereer XXXXX-XXXXX code (10 chars uit ambiguity-free alphabet)."""
    left = "".join(secrets.choice(_ALPHABET) for _ in range(5))
    right = "".join(secrets.choice(_ALPHABET) for _ in range(5))
    return f"{left}-{right}"


def normalize(code: str) -> str:
    """Whitespace + casing normalisatie voor user-input."""
    return code.strip().upper().replace(" ", "")


async def generate_for_user(conn: aiosqlite.Connection, user_id: str, count: int = 10) -> list[str]:
    """Verwijder bestaande backup-codes + genereer N nieuwe. Returnt plaintext-codes
    (alleen show-once aan caller; in DB worden hashes opgeslagen)."""
    await conn.execute("DELETE FROM users_backup_codes WHERE user_id = ?", (user_id,))
    codes: list[str] = []
    now = int(time.time())
    for _ in range(count):
        code = _generate_code()
        codes.append(code)
        code_hash = _hash(code)
        await conn.execute(
            """INSERT INTO users_backup_codes (user_id, code_hash, created_at)
               VALUES (?, ?, ?)""",
            (user_id, code_hash, now),
        )
    await conn.commit()
    return codes


async def consume_code(conn: aiosqlite.Connection, user_id: str, code: str) -> bool:
    """Verifieer + markeer als used. Single-use."""
    norm = normalize(code)
    cursor = await conn.execute(
        """SELECT id, code_hash FROM users_backup_codes
           WHERE user_id = ? AND used_at IS NULL""",
        (user_id,),
    )
    rows = await cursor.fetchall()
    now = int(time.time())
    for row in rows:
        if _verify(norm, row["code_hash"]):
            await conn.execute(
                "UPDATE users_backup_codes SET used_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            await conn.commit()
            return True
    return False


async def count_remaining(conn: aiosqlite.Connection, user_id: str) -> int:
    cursor = await conn.execute(
        """SELECT COUNT(*) AS n FROM users_backup_codes
           WHERE user_id = ? AND used_at IS NULL""",
        (user_id,),
    )
    row = await cursor.fetchone()
    return int(row["n"]) if row else 0


async def remove_all(conn: aiosqlite.Connection, user_id: str) -> int:
    cursor = await conn.execute("DELETE FROM users_backup_codes WHERE user_id = ?", (user_id,))
    await conn.commit()
    return int(cursor.rowcount or 0)
