"""Hardware-sleutels per vault (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.

P-CRYPT-09: de server bewaart per sleutel alleen een kopie van ``{ph,kh}`` die VERZEGELD is
(Seal_v2) naar een X25519-publieke sleutel per credential. Het privédeel bestaat alleen in de
hardware van de gebruiker; de server kan de kopie niet openen en controleert alleen de vorm.
Hij beslist wel WANNEER hij een kopie uitlevert: pas na een geverifieerde WebAuthn-assertion, en
bij een noodsleutel pas na de wachttijd.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from ..config import get_settings
from . import audit_service, mail_service
from .webauthn_service import authenticator_description

logger = logging.getLogger("horsesafe.vault_keys")

_B64URL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_SEALED_KEYS = frozenset({"v", "kid", "epk", "iv", "ct"})

_COLS = (
    "id, user_id, vault_id, kind, label, status, credential_id, cose_public_key, aaguid, att_fmt, "
    "sign_count, prf_salt, public_key, created_at, updated_at, last_used_at, "
    "release_requested_at, release_at, release_consumed_at, blocked_at, blocked_by"
)


def now() -> int:
    """Losse functie zodat tests de klok kunnen verzetten (ook voor challenges en step-up)."""
    return int(time.time())


def fmt_time(ts: int) -> str:
    """``dd-mm-jjjj uu:mm UTC`` voor meldingen."""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%d-%m-%Y %H:%M UTC")


# ─────────────── Seal_v2: alleen vormcontrole (§12.5) ───────────────


def _b64u(v: object, *, exact: int | None = None, lo: int = 1, hi: int = 1024) -> bool:
    if not isinstance(v, str) or not v or any(c not in _B64URL_CHARS for c in v):
        return False
    if exact is not None:
        return len(v) == exact
    return lo <= len(v) <= hi


def validate_sealed(sealed: str, kid: str) -> bool:
    """``{"v":2,"kid":..,"epk":..,"iv":..,"ct":..}`` met exact deze sleutels; geen inhoud."""
    if not isinstance(sealed, str) or len(sealed) > 1024:
        return False
    try:
        obj = json.loads(sealed)
    except ValueError:
        return False
    if not isinstance(obj, dict) or set(obj) != _SEALED_KEYS:
        return False
    v = obj["v"]
    if type(v) is not int or v != 2:  # bool is ook int: expliciet uitsluiten
        return False
    if obj["kid"] != kid:
        return False
    return (
        _b64u(obj["epk"], exact=43)
        and _b64u(obj["iv"], exact=16)
        and _b64u(obj["ct"], lo=40, hi=400)
    )


# ─────────────── Recovery-state (§12.7) ───────────────


def recovery_state(key: dict[str, Any], t: int | None = None) -> str:
    settings = get_settings()
    t = now() if t is None else t
    if key.get("status") == "blocked":
        return "blocked"
    rel = key.get("release_at")
    if rel is None:
        return "idle"
    if key.get("release_consumed_at") is not None:
        return "consumed"
    if t < rel:
        return "waiting"
    if t < rel + settings.recovery_window_hours * 3600:
        return "released"
    return "expired"


def release_until(key: dict[str, Any]) -> int | None:
    rel = key.get("release_at")
    if rel is None:
        return None
    return int(rel) + get_settings().recovery_window_hours * 3600


def public_key_object(key: dict[str, Any]) -> dict[str, Any]:
    """Het sleutelobject van §12.6.3 — nooit sealed, cose_public_key of sign_count."""
    recovery = None
    if key["kind"] == "recovery":
        recovery = {
            "state": recovery_state(key),
            "release_requested_at": key.get("release_requested_at"),
            "release_at": key.get("release_at"),
            "release_until": release_until(key),
            "release_consumed_at": key.get("release_consumed_at"),
            "blocked_at": key.get("blocked_at"),
            "blocked_by": key.get("blocked_by"),
        }
    return {
        "id": key["id"],
        "kind": key["kind"],
        "label": key["label"],
        "status": key["status"],
        "credential_id": key["credential_id"],
        "prf_salt": key["prf_salt"],
        "public_key": key["public_key"],
        "aaguid": key.get("aaguid"),
        "authenticator": authenticator_description(key.get("aaguid")),
        "created_at": key["created_at"],
        "updated_at": key["updated_at"],
        "last_used_at": key.get("last_used_at"),
        "recovery": recovery,
    }


# ─────────────── Opvragen ───────────────


async def list_keys(conn: aiosqlite.Connection, user_id: str, vault_id: str) -> list[dict[str, Any]]:
    """Sleutels van een vault, oplopend op created_at, zonder 'revoked'."""
    cur = await conn.execute(
        f"SELECT {_COLS} FROM vault_keys WHERE user_id = ? AND vault_id = ? "
        "AND status != 'revoked' ORDER BY created_at, rowid",
        (user_id, vault_id),
    )
    return [dict(r) for r in await cur.fetchall()]


async def get_key(
    conn: aiosqlite.Connection, user_id: str, vault_id: str, key_id: str, *, with_sealed: bool = False
) -> dict[str, Any] | None:
    cols = _COLS + (", sealed" if with_sealed else "")
    cur = await conn.execute(
        f"SELECT {cols} FROM vault_keys WHERE user_id = ? AND vault_id = ? AND id = ? "
        "AND status != 'revoked'",
        (user_id, vault_id, key_id),
    )
    row = await cur.fetchone()
    return dict(row) if row else None


async def count_vault_keys(conn: aiosqlite.Connection, vault_id: str) -> int:
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM vault_keys WHERE vault_id = ? AND status != 'revoked'",
        (vault_id,),
    )
    row = await cur.fetchone()
    return int(row["n"]) if row else 0


async def user_has_keys(conn: aiosqlite.Connection, user_id: str) -> bool:
    """Bepaalt de step-up-eis bij registratie (§12.6.1): al een sleutel, in welke vault dan ook."""
    cur = await conn.execute(
        "SELECT 1 FROM vault_keys WHERE user_id = ? AND status != 'revoked' LIMIT 1", (user_id,)
    )
    return await cur.fetchone() is not None


async def user_bio_keys(conn: aiosqlite.Connection, user_id: str) -> list[dict[str, Any]]:
    cur = await conn.execute(
        f"SELECT {_COLS} FROM vault_keys WHERE user_id = ? AND kind = 'bio' AND status = 'active' "
        "ORDER BY created_at, rowid",
        (user_id,),
    )
    return [dict(r) for r in await cur.fetchall()]


async def user_credential_ids(conn: aiosqlite.Connection, user_id: str) -> list[str]:
    cur = await conn.execute(
        "SELECT credential_id FROM vault_keys WHERE user_id = ? AND credential_id IS NOT NULL "
        "ORDER BY created_at, rowid",
        (user_id,),
    )
    return [str(r["credential_id"]) for r in await cur.fetchall()]


async def credential_exists(conn: aiosqlite.Connection, user_id: str, credential_id: str) -> bool:
    cur = await conn.execute(
        "SELECT 1 FROM vault_keys WHERE user_id = ? AND credential_id = ?", (user_id, credential_id)
    )
    return await cur.fetchone() is not None


async def user_email(conn: aiosqlite.Connection, user_id: str) -> str | None:
    cur = await conn.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    row = await cur.fetchone()
    return str(row["email"]) if row else None


# ─────────────── Schrijven ───────────────


async def insert_key(conn: aiosqlite.Connection, data: dict[str, Any]) -> None:
    """INSERT in één transactie. Unieke-sleutelfout → ``ValueError('credential_exists')``."""
    t = now()
    try:
        await conn.execute(
            """INSERT INTO vault_keys (id, user_id, vault_id, kind, label, status, credential_id,
                   cose_public_key, aaguid, att_fmt, sign_count, prf_salt, public_key, sealed,
                   created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data["id"], data["user_id"], data["vault_id"], data["kind"], data["label"],
                data["credential_id"], data["cose_public_key"], data["aaguid"], data["att_fmt"],
                data["sign_count"], data["prf_salt"], data["public_key"], data["sealed"], t, t,
            ),
        )
        await conn.commit()
    except aiosqlite.IntegrityError as e:
        await conn.rollback()
        raise ValueError("credential_exists") from e


async def update_key(conn: aiosqlite.Connection, key_id: str, **fields: Any) -> None:
    """Werk kolommen bij (vaste whitelist) + updated_at; commit."""
    allowed = {
        "sign_count", "last_used_at", "release_requested_at", "release_at",
        "release_consumed_at", "status", "blocked_at", "blocked_by", "sealed",
    }
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(f"onbekende kolommen: {sorted(unknown)}")
    fields["updated_at"] = now()
    cols = ", ".join(f"{k} = ?" for k in fields)
    await conn.execute(f"UPDATE vault_keys SET {cols} WHERE id = ?", (*fields.values(), key_id))  # noqa: S608
    await conn.commit()


async def delete_key(conn: aiosqlite.Connection, user_id: str, vault_id: str, key_id: str) -> bool:
    cur = await conn.execute(
        "DELETE FROM vault_keys WHERE user_id = ? AND vault_id = ? AND id = ?",
        (user_id, vault_id, key_id),
    )
    await conn.commit()
    return cur.rowcount > 0


async def reseal(
    conn: aiosqlite.Connection, user_id: str, vault_id: str, items: list[dict[str, str]]
) -> int:
    """Alles of niets: elke id moet een sleutel van deze vault zijn (anders ``unknown_key``)."""
    t = now()
    await conn.execute("BEGIN IMMEDIATE")
    try:
        n = 0
        for it in items:
            cur = await conn.execute(
                "UPDATE vault_keys SET sealed = ?, updated_at = ? "
                "WHERE user_id = ? AND vault_id = ? AND id = ? AND status != 'revoked'",
                (it["sealed"], t, user_id, vault_id, it["id"]),
            )
            if cur.rowcount != 1:
                raise ValueError("unknown_key")
            n += 1
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return n


# ─────────────── Meldingen ───────────────


def notify_body(text: str, *, label: str | None, ip: str | None, advice: str) -> str:
    """Nederlandse body met label, tijd (UTC), IP en "Was jij dit niet?"-advies. Nooit geheimen."""
    lines = [text, ""]
    if label:
        lines.append(f"Sleutel: {label}")
    lines.append(f"Tijd: {fmt_time(now())}")
    lines.append(f"IP-adres: {ip or 'onbekend'}")
    lines += ["", f"Was jij dit niet? {advice}", "", "— HorseSafe (zero-knowledge wachtwoord-vault)"]
    return "\n".join(lines)


async def notify_user(
    email: str | None,
    subject: str,
    body: str,
    *,
    user_id: str,
    event: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> bool:
    """Niet-blokkerende melding (``asyncio.to_thread``), NA het sluiten van de DB-verbinding.

    Mislukt versturen (bij een geconfigureerde mailer) → audit ``notify_failed {event}``;
    de actie zelf slaagt. Geen mailer → alleen een logregel.
    """
    if not email:
        return False
    if not mail_service.is_configured():
        logger.warning("Melding niet verstuurd (geen meldkanaal): %s", event)
        return False
    ok = await mail_service.send_async(email, subject, body)
    if not ok:
        from ..db.connection import connect

        async with connect(get_settings().db_path) as conn:
            await audit_service.log(
                conn, user_id=user_id, event="notify_failed", ip=ip, user_agent=user_agent,
                detail={"event": event},
            )
    return ok
