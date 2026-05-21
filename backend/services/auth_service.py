from __future__ import annotations

import time
import uuid

import aiosqlite
from passlib.context import CryptContext

from ..config import get_settings

_settings = get_settings()
_pwd = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__time_cost=_settings.argon2_time_cost,
    argon2__memory_cost=_settings.argon2_memory_kib,
    argon2__parallelism=_settings.argon2_parallelism,
)


def hash_password(plain: str) -> str:
    return str(_pwd.hash(plain))


def verify_password(plain: str, pw_hash: str) -> bool:
    try:
        return bool(_pwd.verify(plain, pw_hash))
    except (ValueError, TypeError):
        return False


async def create_user(conn: aiosqlite.Connection, email: str, password: str) -> str:
    """Maak nieuwe user. Geeft user_id terug.

    Raise ValueError als e-mail al bestaat.
    """
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(password)
    now = int(time.time())
    try:
        await conn.execute(
            "INSERT INTO users (id, email, pw_hash, created_at) VALUES (?, ?, ?, ?)",
            (user_id, email.lower(), pw_hash, now),
        )
        await conn.commit()
    except aiosqlite.IntegrityError as e:
        raise ValueError("email_in_use") from e
    return user_id


async def authenticate(
    conn: aiosqlite.Connection, email: str, password: str
) -> tuple[str, bool] | None:
    """Verifieer e-mail+pw. Geeft (user_id, is_admin) terug bij succes, anders None."""
    cursor = await conn.execute(
        "SELECT id, pw_hash, is_admin FROM users WHERE email = ?",
        (email.lower(),),
    )
    row = await cursor.fetchone()
    if row is None:
        # Tijd-equivalente hash om timing-attack te beperken
        _pwd.dummy_verify()
        return None
    if not verify_password(password, row["pw_hash"]):
        return None
    await conn.execute(
        "UPDATE users SET last_login_at = ? WHERE id = ?",
        (int(time.time()), row["id"]),
    )
    await conn.commit()
    return str(row["id"]), bool(row["is_admin"])


async def is_throttled(conn: aiosqlite.Connection, ip: str, email: str | None) -> bool:
    settings = get_settings()
    window_start = int(time.time()) - settings.failed_login_window_minutes * 60
    cursor = await conn.execute(
        """SELECT COUNT(*) AS n FROM failed_logins
           WHERE ts > ? AND (ip = ? OR (email IS NOT NULL AND email = ?))""",
        (window_start, ip, email.lower() if email else None),
    )
    row = await cursor.fetchone()
    return bool(row and row["n"] >= settings.failed_login_max)


async def record_failed_login(conn: aiosqlite.Connection, ip: str, email: str | None) -> None:
    await conn.execute(
        "INSERT INTO failed_logins (ip, email, ts) VALUES (?, ?, ?)",
        (ip, email.lower() if email else None, int(time.time())),
    )
    await conn.commit()
