"""Telefoon koppelen (v0.3.4-Miller deel 2) — docs/HARDWARE_KEYS.md §13.

Zero-knowledge (§13.0): de browser maakt het QR-geheim ``s`` en stuurt alleen ``k_srv``. De server
controleert met ``k_srv`` de ``mac_srv`` van de telefoon en geeft ``mac_web`` door; die controleert
de browser zelf met ``k_web``, zodat een kwaadwillende server geen andere ``pk_c`` kan laten
verzegelen. De server bewaart van een toestel alleen publieke sleutels en attestatieketens, en per
kluis een Seal_v2-kopie die hij niet kan openen.

Device-requests (``/device/v1/*``) zijn getekend met K_dev (§13.6); nonces zijn eenmalig.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import uuid
from typing import Any

import aiosqlite
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key
from fastapi import HTTPException, Request

from ..config import get_settings
from ..db.connection import connect
from . import audit_service
from . import vault_key_service as svc

PAIRING_TTL_SECONDS = 300  # §13.4
CONFIRM_WITHIN_SECONDS = 600  # §13.4: confirm binnen 600 s na start
PAIRINGS_PER_HOUR = 10  # §13.3
MAC_FAILURES_MAX = 3  # §13.5 stap 3
DEVICES_MAX = 5  # §13.5 stap 7
DEVICE_TS_SKEW = 60  # §13.6
NONCE_TTL = 120  # §13.6

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")  # 16 bytes b64u
_SIG_RE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if any(c in s for c in "=+/"):
        raise ValueError("geen base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError("geen base64url") from e


# ─────────────── Afleidingen (§13.1; testvectoren pair_v1.json) ───────────────


def _hkdf(ikm: bytes, info: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info.encode("utf-8")
    ).derive(ikm)


def k_srv_from_secret(s: bytes) -> bytes:
    """Alleen voor tests en de nep-app: de server krijgt ``s`` nooit."""
    return _hkdf(s, "HSv2 pair srv")


def k_web_from_secret(s: bytes) -> bytes:
    """Alleen voor tests en de nep-app: de server krijgt ``s`` en ``k_web`` nooit."""
    return _hkdf(s, "HSv2 pair web")


def att_challenge(pairing_id: str, k_srv: bytes) -> bytes:
    return hashlib.sha256(
        b"HSv2 pair att\x00" + pairing_id.encode("utf-8") + b"\x00" + k_srv
    ).digest()


TRANSCRIPT_FIELDS = ("pk_c", "k_dev_pub", "k_biosig_pub", "label", "model", "app_version")


def transcript(pairing_id: str, fields: dict[str, str]) -> bytes:
    """``"HSv2 pair" ‖ 0 ‖ pairing_id ‖ 0 ‖ pk_c ‖ … ‖ 0 ‖ app_version`` (UTF-8, letterlijk)."""
    parts = ["HSv2 pair", pairing_id, *(fields[k] for k in TRANSCRIPT_FIELDS)]
    if any("\x00" in p for p in parts):
        raise ValueError("veld bevat \\0")
    return "\x00".join(parts).encode("utf-8")


def mac(key: bytes, t: bytes) -> bytes:
    return hmac.new(key, t, hashlib.sha256).digest()


def sas(t: bytes) -> str:
    d = hashlib.sha256(b"HSv2 pair sas\x00" + t).digest()
    return f"{int.from_bytes(d[:4], 'big') % 1_000_000:06d}"


def verify_p256(spki_b64u: str, signature_der: bytes, data: bytes) -> bool:
    try:
        key = load_der_public_key(b64u_decode(spki_b64u))
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        key.verify(signature_der, data, ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


# ─────────────── Pairings (DB) ───────────────


async def get_pairing(conn: aiosqlite.Connection, pairing_id: str) -> dict[str, Any] | None:
    cur = await conn.execute("SELECT * FROM pairings WHERE id = ?", (pairing_id,))
    row = await cur.fetchone()
    return dict(row) if row else None


async def own_pairing(
    conn: aiosqlite.Connection, user_id: str, pairing_id: str
) -> dict[str, Any] | None:
    p = await get_pairing(conn, pairing_id)
    return p if p and p["user_id"] == user_id else None


async def pairings_last_hour(conn: aiosqlite.Connection, user_id: str, t: int) -> int:
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM pairings WHERE user_id = ? AND created_at > ?",
        (user_id, t - 3600),
    )
    row = await cur.fetchone()
    return int(row["n"]) if row else 0


async def cancel_open_pairings(conn: aiosqlite.Connection, user_id: str) -> list[str]:
    """Zet open koppelingen (pending/claimed) op cancelled; nog niet bevestigde toestellen weg.

    Geen commit: hoort in de transactie van de aanroeper. Geeft de geannuleerde ids terug."""
    cur = await conn.execute(
        "SELECT id, device_id FROM pairings WHERE user_id = ? AND status IN ('pending', 'claimed')",
        (user_id,),
    )
    rows = [dict(r) for r in await cur.fetchall()]
    for r in rows:
        await _cancel(conn, r["id"], r["device_id"])
    return [str(r["id"]) for r in rows]


async def _cancel(conn: aiosqlite.Connection, pairing_id: str, device_id: str | None) -> None:
    await conn.execute(
        "UPDATE pairings SET status = 'cancelled', k_srv = '' WHERE id = ?", (pairing_id,)
    )
    if device_id:
        # Alleen een nog niet bevestigd toestel; ON DELETE CASCADE zet pairings.device_id niet op
        # NULL maar zou de koppeling zelf wissen, dus eerst ontkoppelen.
        await conn.execute("UPDATE pairings SET device_id = NULL WHERE id = ?", (pairing_id,))
        await conn.execute(
            "DELETE FROM devices WHERE id = ? AND confirmed_at IS NULL", (device_id,)
        )


async def expire_stale_claims(
    conn: aiosqlite.Connection,
    t: int,
    *,
    user_id: str | None = None,
    device_id: str | None = None,
) -> list[str]:
    """Lui opruimen: een geclaimde koppeling die na ``CONFIRM_WITHIN_SECONDS`` (600 s na start) nog
    niet bevestigd is, kan niet meer bevestigd worden (§13.4). Zet hem op ``cancelled``
    (``k_srv = ''``) en verwijder het nog niet bevestigde toestel, zodat er geen eeuwig ``claimed``
    toestel blijft staan. Aangeroepen bij elke relevante web- en device-aanroep, beperkt tot
    ``user_id`` en/of ``device_id``. Eigen transactie. Geeft de opgeruimde ids terug."""
    sql = (
        "SELECT id, user_id, device_id FROM pairings "
        "WHERE status = 'claimed' AND created_at + ? < ?"
    )
    args: list[Any] = [CONFIRM_WITHIN_SECONDS, t]
    if user_id is not None:
        sql += " AND user_id = ?"
        args.append(user_id)
    if device_id is not None:
        sql += " AND device_id = ?"
        args.append(device_id)
    # Eerst zonder schrijfslot kijken (het web pollt elke seconde); pas bij treffers de transactie,
    # en daarin opnieuw selecteren zodat een gelijktijdige bevestiging niet overschreven wordt.
    cur = await conn.execute(sql, args)
    if await cur.fetchone() is None:
        return []
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cur = await conn.execute(sql, args)
        rows = [dict(r) for r in await cur.fetchall()]
        for r in rows:
            await _cancel(conn, r["id"], r["device_id"])
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    for r in rows:  # na de commit: audit_service.log commit zelf
        await audit_service.log(
            conn,
            user_id=str(r["user_id"]),
            event="device_pairing_cancel",
            detail={"pairing_id": str(r["id"]), "reason": "not_confirmed"},
        )
    return [str(r["id"]) for r in rows]


async def cancel_pairing(conn: aiosqlite.Connection, pairing: dict[str, Any]) -> None:
    await _cancel(conn, pairing["id"], pairing.get("device_id"))
    await conn.commit()


async def create_pairing(
    conn: aiosqlite.Connection, *, user_id: str, vault_id: str, k_srv: str, t: int
) -> tuple[str, int, list[str]]:
    """Nieuwe koppeling; oude open koppelingen worden in dezelfde transactie geannuleerd."""
    pairing_id = str(uuid.uuid4())
    expires_at = t + PAIRING_TTL_SECONDS
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cancelled = await cancel_open_pairings(conn, user_id)
        await conn.execute(
            "INSERT INTO pairings (id, user_id, vault_id, k_srv, status, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?)",
            (pairing_id, user_id, vault_id, k_srv, t, expires_at),
        )
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return pairing_id, expires_at, cancelled


async def register_mac_failure(conn: aiosqlite.Connection, pairing_id: str) -> bool:
    """Tel een mac-fout; bij de derde gaat de koppeling op cancelled. True = nu geannuleerd."""
    await conn.execute(
        "UPDATE pairings SET mac_failures = mac_failures + 1 WHERE id = ? AND status = 'pending'",
        (pairing_id,),
    )
    cur = await conn.execute(
        "UPDATE pairings SET status = 'cancelled', k_srv = '' "
        "WHERE id = ? AND status = 'pending' AND mac_failures >= ?",
        (pairing_id, MAC_FAILURES_MAX),
    )
    await conn.commit()
    return cur.rowcount == 1


async def active_device_count(conn: aiosqlite.Connection, user_id: str) -> int:
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND revoked_at IS NULL "
        "AND confirmed_at IS NOT NULL",
        (user_id,),
    )
    row = await cur.fetchone()
    return int(row["n"]) if row else 0


async def store_claim(
    conn: aiosqlite.Connection,
    pairing: dict[str, Any],
    claim: dict[str, Any],
    *,
    chains: dict[str, list[str]],
    security_level: str,
    strongbox: bool,
    t: int,
) -> tuple[str, str] | None:
    """Stap 8 in één transactie. ``None`` = de koppeling was intussen niet meer ``pending``."""
    device_id = str(uuid.uuid4())
    key_id = str(uuid.uuid4())
    claim_json = {
        "device_id": device_id,
        "key_id": key_id,
        **{k: claim[k] for k in TRANSCRIPT_FIELDS},
        "mac_web": claim["mac_web"],
        "security_level": security_level,
        "strongbox": strongbox,
    }
    await conn.execute("BEGIN IMMEDIATE")
    try:
        await conn.execute(
            """INSERT INTO devices (id, user_id, label, model, k_dev_pub, k_biosig_pub, att_chains,
                   security_level, strongbox, app_version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                device_id,
                pairing["user_id"],
                claim["label"],
                claim["model"],
                claim["k_dev_pub"],
                claim["k_biosig_pub"],
                json.dumps(chains, separators=(",", ":")),
                security_level,
                1 if strongbox else 0,
                claim["app_version"],
                t,
            ),
        )
        cur = await conn.execute(
            "UPDATE pairings SET status = 'claimed', device_id = ?, key_id = ?, claim_json = ?, "
            "claimed_at = ? WHERE id = ? AND status = 'pending' AND expires_at >= ?",
            (
                device_id,
                key_id,
                json.dumps(claim_json, separators=(",", ":")),
                t,
                pairing["id"],
                t,
            ),
        )
        if cur.rowcount != 1:
            await conn.rollback()
            return None
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return device_id, key_id


async def confirm_pairing(
    conn: aiosqlite.Connection,
    pairing: dict[str, Any],
    claim: dict[str, Any],
    sealed: str,
    t: int,
) -> bool:
    """Eén transactie: toestel bevestigd, koppeling confirmed (k_srv gewist), phone-sleutel erbij.

    False = de koppeling of het toestel veranderde intussen (niet meer claimed / ingetrokken)."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cur = await conn.execute(
            "UPDATE pairings SET status = 'confirmed', confirmed_at = ?, k_srv = '' "
            "WHERE id = ? AND status = 'claimed'",
            (t, pairing["id"]),
        )
        dev = await conn.execute(
            "UPDATE devices SET confirmed_at = ? WHERE id = ? AND revoked_at IS NULL "
            "AND confirmed_at IS NULL",
            (t, claim["device_id"]),
        )
        if cur.rowcount != 1 or dev.rowcount != 1:
            await conn.rollback()
            return False
        await conn.execute(
            """INSERT INTO vault_keys (id, user_id, vault_id, kind, label, status, device_id,
                   public_key, sealed, created_at, updated_at)
               VALUES (?, ?, ?, 'phone', ?, 'active', ?, ?, ?, ?, ?)""",
            (
                claim["key_id"],
                pairing["user_id"],
                pairing["vault_id"],
                claim["label"],
                claim["device_id"],
                claim["pk_c"],
                sealed,
                t,
                t,
            ),
        )
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return True


# ─────────────── Toestellen (DB) ───────────────


def device_state(device: dict[str, Any]) -> str:
    if device.get("revoked_at") is not None:
        return "revoked"
    return "active" if device.get("confirmed_at") is not None else "pending"


async def get_device(conn: aiosqlite.Connection, device_id: str) -> dict[str, Any] | None:
    cur = await conn.execute(
        "SELECT id, user_id, label, model, k_dev_pub, security_level, strongbox, app_version, "
        "created_at, confirmed_at, last_seen_at, revoked_at FROM devices WHERE id = ?",
        (device_id,),
    )
    row = await cur.fetchone()
    return dict(row) if row else None


async def list_devices(conn: aiosqlite.Connection, user_id: str) -> list[dict[str, Any]]:
    """Eigen, niet-ingetrokken toestellen (zonder ketens), oplopend op created_at."""
    cur = await conn.execute(
        "SELECT id, label, model, security_level, strongbox, app_version, created_at, "
        "confirmed_at, last_seen_at, revoked_at FROM devices "
        "WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at, rowid",
        (user_id,),
    )
    return [dict(r) for r in await cur.fetchall()]


def device_public(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": d["id"],
        "label": d["label"],
        "model": d.get("model"),
        "state": device_state(d),
        "security_level": d["security_level"],
        "strongbox": bool(d["strongbox"]),
        "app_version": d.get("app_version"),
        "created_at": d["created_at"],
        "confirmed_at": d.get("confirmed_at"),
        "last_seen_at": d.get("last_seen_at"),
    }


async def revoke_device(
    conn: aiosqlite.Connection, user_id: str, device_id: str, t: int
) -> list[dict[str, Any]]:
    """``revoked_at = nu``; phone-sleutels van dit toestel weg (geen kopie laten liggen); open
    koppeling van dit toestel geannuleerd. Eén transactie. Geeft de verwijderde sleutels terug."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cur = await conn.execute(
            "SELECT id, vault_id FROM vault_keys WHERE user_id = ? AND device_id = ?",
            (user_id, device_id),
        )
        keys = [dict(r) for r in await cur.fetchall()]
        await conn.execute(
            "DELETE FROM vault_keys WHERE user_id = ? AND device_id = ?", (user_id, device_id)
        )
        await conn.execute(
            "UPDATE pairings SET status = 'cancelled', k_srv = '' "
            "WHERE device_id = ? AND status IN ('pending', 'claimed')",
            (device_id,),
        )
        await conn.execute(
            "UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
            (t, device_id, user_id),
        )
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return keys


async def device_keys(conn: aiosqlite.Connection, device_id: str) -> list[dict[str, Any]]:
    cur = await conn.execute(
        "SELECT id, vault_id, label FROM vault_keys WHERE device_id = ? AND kind = 'phone' "
        "AND status = 'active' ORDER BY created_at, rowid",
        (device_id,),
    )
    return [dict(r) for r in await cur.fetchall()]


async def device_key_sealed(
    conn: aiosqlite.Connection, device_id: str, key_id: str
) -> dict[str, Any] | None:
    cur = await conn.execute(
        "SELECT id, vault_id, sealed FROM vault_keys WHERE id = ? AND device_id = ? "
        "AND kind = 'phone' AND status = 'active'",
        (key_id, device_id),
    )
    row = await cur.fetchone()
    return dict(row) if row else None


# ─────────────── Device-handtekening (§13.6) ───────────────


def device_message(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    """``"HSv2 dev" ‖ 0 ‖ METHOD ‖ 0 ‖ PATH ‖ 0 ‖ ts ‖ 0 ‖ nonce ‖ 0 ‖ b64u(SHA-256(body))``."""
    parts = ["HSv2 dev", method.upper(), path, ts, nonce, b64u(hashlib.sha256(body).digest())]
    return "\x00".join(parts).encode("utf-8")


def _api_path(request: Request) -> str:
    """PATH vanaf ``/api`` incl. querystring; nginx stript ``/HorseSafe/api`` (§12.1)."""
    path = "/api" + request.url.path
    q = request.url.query
    return f"{path}?{q}" if q else path


def _auth_failed() -> HTTPException:
    return HTTPException(status_code=401, detail={"error": "device_auth_failed"})


async def authenticate_device(request: Request, *, allow_revoked: bool = False) -> dict[str, Any]:
    """D (§13.6): toestel bestaat (en is niet ingetrokken, behalve bij ``allow_revoked``),
    ``|nu − ts| ≤ 60``, nonce nog niet gezien, handtekening geldig. Anders 401
    ``device_auth_failed`` zonder detail. Succes: ``last_seen_at = nu``; nonces > 120 s weg."""
    h = request.headers
    device_id = h.get("x-hs-device", "")
    ts = h.get("x-hs-ts", "")
    nonce = h.get("x-hs-nonce", "")
    sig = h.get("x-hs-sig", "")
    if not (
        _UUID_RE.match(device_id)
        and ts.isascii()
        and ts.isdigit()
        and len(ts) <= 12
        and _NONCE_RE.match(nonce)
        and _SIG_RE.match(sig)
    ):
        raise _auth_failed()
    t = svc.now()
    if abs(t - int(ts)) > DEVICE_TS_SKEW:
        raise _auth_failed()
    body = await request.body()
    async with connect(get_settings().db_path) as conn:
        await conn.execute("DELETE FROM device_nonces WHERE created_at < ?", (t - NONCE_TTL,))
        await conn.commit()
        # Nooit bevestigd binnen 600 s → toestel weg (lui opruimen, zie expire_stale_claims).
        await expire_stale_claims(conn, t, device_id=device_id)
        device = await get_device(conn, device_id)
        if device is None or (device["revoked_at"] is not None and not allow_revoked):
            raise _auth_failed()
        cur = await conn.execute(
            "SELECT 1 FROM device_nonces WHERE device_id = ? AND nonce = ?", (device_id, nonce)
        )
        if await cur.fetchone() is not None:
            raise _auth_failed()
        try:
            sig_der = b64u_decode(sig)
        except ValueError as e:
            raise _auth_failed() from e
        msg = device_message(request.method, _api_path(request), ts, nonce, body)
        if not verify_p256(str(device["k_dev_pub"]), sig_der, msg):
            raise _auth_failed()
        try:  # eenmalig, ook bij gelijktijdige requests (PRIMARY KEY)
            await conn.execute(
                "INSERT INTO device_nonces (device_id, nonce, created_at) VALUES (?, ?, ?)",
                (device_id, nonce, t),
            )
        except aiosqlite.IntegrityError as e:
            await conn.rollback()
            raise _auth_failed() from e
        await conn.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (t, device_id))
        await conn.commit()
    device["last_seen_at"] = t
    return device
