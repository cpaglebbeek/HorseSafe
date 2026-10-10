"""Hardware-sleutels per vault (v0.2.0-Koblitz).

De server bewaart per sleutel alleen een verzegelde kopie (ECIES naar een X25519-publieke sleutel
die in de browser uit de WebAuthn-PRF-uitvoer wordt afgeleid). Hij kan die kopie niet openen;
hij beslist alleen WANNEER hij hem uitlevert (noodsleutel: pas na de wachttijd).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

import aiosqlite

from ..config import get_settings

logger = logging.getLogger("horsesafe.vault_keys")

_PUBLIC_COLS = (
    "id, kind, label, credential_id, prf_salt, public_key, created_at, updated_at, "
    "last_used_at, release_requested_at, release_at"
)


def now() -> int:
    """Losse functie zodat tests de klok kunnen verzetten."""
    return int(time.time())


def validate_sealed(sealed: str) -> bool:
    """Vormcontrole (geen inhoud): {"v":1,"epk":..,"iv":..,"ct":..} met base64url-strings."""
    try:
        obj = json.loads(sealed)
    except ValueError:
        return False
    if not isinstance(obj, dict) or obj.get("v") != 1:
        return False
    for k in ("epk", "iv", "ct"):
        v = obj.get(k)
        if not isinstance(v, str) or not v or any(c not in _B64URL_CHARS for c in v):
            return False
    return len(obj["epk"]) == 43 and len(obj["iv"]) == 16


_B64URL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _with_window(row: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    rel = row.get("release_at")
    row["release_until"] = rel + settings.recovery_window_hours * 3600 if rel else None
    return row


async def list_keys(conn: aiosqlite.Connection, user_id: str, vault_id: str) -> list[dict[str, Any]]:
    cur = await conn.execute(
        f"SELECT {_PUBLIC_COLS} FROM vault_keys WHERE user_id = ? AND vault_id = ? ORDER BY created_at",
        (user_id, vault_id),
    )
    return [_with_window(dict(r)) for r in await cur.fetchall()]


async def get_key(conn: aiosqlite.Connection, user_id: str, vault_id: str, key_id: str) -> dict[str, Any] | None:
    cur = await conn.execute(
        f"SELECT {_PUBLIC_COLS}, sealed FROM vault_keys WHERE user_id = ? AND vault_id = ? AND id = ?",
        (user_id, vault_id, key_id),
    )
    row = await cur.fetchone()
    return _with_window(dict(row)) if row else None


async def add_key(
    conn: aiosqlite.Connection, user_id: str, vault_id: str, data: dict[str, Any]
) -> dict[str, Any]:
    settings = get_settings()
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM vault_keys WHERE user_id = ? AND vault_id = ?", (user_id, vault_id)
    )
    row = await cur.fetchone()
    if row and int(row["n"]) >= settings.vault_keys_max:
        raise ValueError("too_many_keys")
    key_id = str(uuid.uuid4())
    t = now()
    try:
        await conn.execute(
            """INSERT INTO vault_keys (id, user_id, vault_id, kind, label, credential_id, prf_salt,
                                       public_key, sealed, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                key_id, user_id, vault_id, data["kind"], data["label"], data["credential_id"],
                data["prf_salt"], data["public_key"], data["sealed"], t, t,
            ),
        )
    except aiosqlite.IntegrityError as e:
        raise ValueError("credential_exists") from e
    await conn.commit()
    created = await get_key(conn, user_id, vault_id, key_id)
    assert created is not None
    created.pop("sealed", None)
    return created


async def delete_key(conn: aiosqlite.Connection, user_id: str, vault_id: str, key_id: str) -> bool:
    cur = await conn.execute(
        "DELETE FROM vault_keys WHERE user_id = ? AND vault_id = ? AND id = ?", (user_id, vault_id, key_id)
    )
    await conn.commit()
    return cur.rowcount > 0


async def reseal(
    conn: aiosqlite.Connection, user_id: str, vault_id: str, items: list[dict[str, str]]
) -> int:
    t = now()
    n = 0
    for it in items:
        cur = await conn.execute(
            "UPDATE vault_keys SET sealed = ?, updated_at = ? WHERE user_id = ? AND vault_id = ? AND id = ?",
            (it["sealed"], t, user_id, vault_id, it["id"]),
        )
        n += cur.rowcount
    await conn.commit()
    return n


def recovery_state(key: dict[str, Any]) -> str:
    """'idle' | 'waiting' | 'released' | 'expired' voor een noodsleutel."""
    rel, until = key.get("release_at"), key.get("release_until")
    if not rel:
        return "idle"
    t = now()
    if t < rel:
        return "waiting"
    if until is not None and t < until:
        return "released"
    return "expired"


async def mark_used(conn: aiosqlite.Connection, key_id: str) -> None:
    await conn.execute("UPDATE vault_keys SET last_used_at = ? WHERE id = ?", (now(), key_id))
    await conn.commit()


async def request_release(conn: aiosqlite.Connection, key: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    t = now()
    rel = t + settings.recovery_delay_hours * 3600
    await conn.execute(
        "UPDATE vault_keys SET release_requested_at = ?, release_at = ? WHERE id = ?", (t, rel, key["id"])
    )
    await conn.commit()
    key.update(release_requested_at=t, release_at=rel)
    return _with_window(key)


async def cancel_release(conn: aiosqlite.Connection, key_id: str) -> None:
    await conn.execute(
        "UPDATE vault_keys SET release_requested_at = NULL, release_at = NULL WHERE id = ?", (key_id,)
    )
    await conn.commit()


async def notify_user(conn: aiosqlite.Connection, user_id: str, subject: str, body: str) -> bool:
    """Best-effort e-mail (zelfde zender als magic-link). Faalt stil als mail niet geconfigureerd is."""
    from . import magic_link_service

    settings = get_settings()
    if not settings.gmail_user or not settings.gmail_app_password:
        logger.warning("Melding niet verstuurd (geen mail geconfigureerd): %s", subject)
        return False
    cur = await conn.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    row = await cur.fetchone()
    if not row:
        return False
    try:
        magic_link_service._sender.send(str(row["email"]), subject, body)
        return True
    except Exception:  # noqa: BLE001 — melding mag de actie nooit breken
        logger.exception("Melding versturen mislukt: %s", subject)
        return False
