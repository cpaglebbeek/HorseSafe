"""Vertrouwde browser + telefoonvinger (v0.4.0-Montgomery) — docs/HARDWARE_KEYS.md §14.

Zero-knowledge (§11.3): vertrouwen = herkennen + koppelen, niet ontsleutelen. De server bewaart per
vertrouwde browser alleen de publieke sleutel K_B (SPKI) en het koppelbewijs ``proof`` (HMAC met een
sleutel uit CK). Hij kan dat bewijs niet narekenen of vervalsen; de telefoon doet dat ná de vinger.
Een ontgrendelverzoek levert hooguit een ``resp`` op die de telefoon naar de tijdelijke
X25519-sleutel van de browser-tab verzegelde (Seal_v2 ``relay``); de server ziet CK nooit en wist
``resp`` na ophalen of verlopen.

Afleidingen (§14.2) staan hier als losse functies; ``k_bind``/``proof`` alleen voor tests en de
nep-app (de server heeft geen CK).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from typing import Any

import aiosqlite
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..config import get_settings
from . import device_service as dev
from . import vault_key_service as svc

TRUSTED_BROWSERS_MAX = 10  # actief per gebruiker (§14.3)
CHALLENGE_TTL = 120  # §14.4
CHALLENGES_PER_WINDOW = 10  # per e-mail (en per IP in de middleware) per 10 min
CHALLENGE_WINDOW = 600
DRAFT_TTL = 30  # §14.5 noot volgorde
PENDING_TTL = 120  # §14.5
APPROVALS_PER_HOUR = 10  # per gebruiker
DENY_COOLDOWN = 15 * 60  # na weigeren geen nieuwe verzoeken voor die browser
WAIT_MAX = 25  # long-poll (s)
POLL_INTERVAL = 0.5  # s tussen DB-controles tijdens een long-poll (tests zetten dit lager)
FINAL_ROW_TTL = 24 * 3600  # afgehandelde verzoeken daarna weg (de audit blijft)

OPEN_STATUSES = ("draft", "pending", "approved")

b64u = dev.b64u
b64u_decode = dev.b64u_decode


# ─────────────── Afleidingen (§14.2; testvectoren trust_v1.json) ───────────────


def k_bind(pt_ck: bytes, vault_id: str) -> bytes:
    """Alleen tests/nep-app (de server heeft geen CK):
    ``HKDF(pt_ck, salt=SHA-256("HSv2 bind salt" ‖ 0 ‖ vault_id), info="HSv2 browser bind")``."""
    salt = hashlib.sha256(b"HSv2 bind salt\x00" + vault_id.encode("utf-8")).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"HSv2 browser bind").derive(
        pt_ck
    )


def _join(parts: list[str]) -> bytes:
    if any("\x00" in p for p in parts):
        raise ValueError("veld bevat \\0")
    return "\x00".join(parts).encode("utf-8")


def bind_t(vault_id: str, browser_id: str, pub_b: str, label: str) -> bytes:
    return _join(["HSv2 browser", vault_id, browser_id, pub_b, label])


def proof(k: bytes, t: bytes) -> bytes:
    """Alleen tests/nep-app: ``HMAC-SHA256(k_bind, bind_t)``."""
    return hmac.new(k, t, hashlib.sha256).digest()


def login_t(challenge_id: str, challenge: bytes, browser_id: str, email_lc: str) -> bytes:
    return _join(["HSv2 blogin", challenge_id, b64u(challenge), browser_id, email_lc])


def req_t(
    approval_id: str, vault_id: str, browser_id: str, epk_l: str, nonce_l: bytes, created_at: int
) -> bytes:
    return _join(
        [
            "HSv2 approve",
            approval_id,
            vault_id,
            browser_id,
            epk_l,
            b64u(nonce_l),
            str(created_at),
        ]
    )


def relay_bind(approval_id: str, nonce_l_b64u: str) -> str:
    """``bind`` van de relay-Seal_v2: ``approval_id ‖ 0 ‖ b64u(nonce_L)``."""
    return approval_id + "\x00" + nonce_l_b64u


def valid_p256_spki(spki_b64u: str) -> bool:
    try:
        key = load_der_public_key(b64u_decode(spki_b64u))
    except (ValueError, TypeError):
        return False
    return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)


def verify_p1363(spki_b64u: str, sig_raw: bytes, data: bytes) -> bool:
    """ECDSA-P256-SHA256 met een **ruwe** handtekening r‖s (64 B, WebCrypto/P1363)."""
    if len(sig_raw) != 64:
        return False
    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    if r == 0 or s == 0:
        return False
    return dev.verify_p256(spki_b64u, encode_dss_signature(r, s), data)


def verify_p1363_b64u(spki_b64u: str, sig_b64u: str, data: bytes) -> bool:
    try:
        sig = b64u_decode(sig_b64u)
    except ValueError:
        return False
    return verify_p1363(spki_b64u, sig, data)


# ─────────────── Lui opruimen ───────────────


async def cleanup(conn: aiosqlite.Connection, t: int, *, user_id: str | None = None) -> None:
    """Verlopen verzoeken → ``expired`` (``resp`` gewist); oude afgehandelde rijen, verlopen
    challenges en verlopen ingetrokken sessies weg. Commit zelf."""
    sql = (
        "UPDATE approvals SET status = 'expired', resp = NULL "
        "WHERE status IN ('draft', 'pending', 'approved') AND expires_at < ?"
    )
    args: list[Any] = [t]
    if user_id is not None:
        sql += " AND user_id = ?"
        args.append(user_id)
    await conn.execute(sql, args)
    await conn.execute(
        "DELETE FROM approvals WHERE status IN ('denied', 'consumed', 'cancelled', 'expired') "
        "AND created_at < ?",
        (t - FINAL_ROW_TTL,),
    )
    await conn.execute("DELETE FROM browser_challenges WHERE created_at < ?", (t - 3600,))
    await conn.execute("DELETE FROM revoked_sessions WHERE expires_at < ?", (t,))
    await conn.commit()


# ─────────────── Vertrouwde browsers ───────────────


async def get_browser(conn: aiosqlite.Connection, browser_id: str) -> dict[str, Any] | None:
    cur = await conn.execute("SELECT * FROM trusted_browsers WHERE id = ?", (browser_id,))
    row = await cur.fetchone()
    return dict(row) if row else None


async def own_active_browser(
    conn: aiosqlite.Connection, user_id: str, browser_id: str
) -> dict[str, Any] | None:
    b = await get_browser(conn, browser_id)
    if b is None or b["user_id"] != user_id or b["revoked_at"] is not None:
        return None
    return b


async def active_browser_count(conn: aiosqlite.Connection, user_id: str) -> int:
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM trusted_browsers WHERE user_id = ? AND revoked_at IS NULL",
        (user_id,),
    )
    row = await cur.fetchone()
    return int(row["n"]) if row else 0


async def list_browsers(conn: aiosqlite.Connection, user_id: str) -> list[dict[str, Any]]:
    cur = await conn.execute(
        "SELECT id, vault_id, label, created_at, last_used_at FROM trusted_browsers "
        "WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at, rowid",
        (user_id,),
    )
    return [dict(r) for r in await cur.fetchall()]


async def create_browser(
    conn: aiosqlite.Connection,
    *,
    user_id: str,
    browser_id: str,
    vault_id: str,
    pub_b: str,
    label: str,
    proof_b64u: str,
    t: int,
) -> str | None:
    """Eén transactie: max opnieuw tellen, dan INSERT. Geeft een foutcode of None."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        if await active_browser_count(conn, user_id) >= TRUSTED_BROWSERS_MAX:
            await conn.rollback()
            return "too_many_browsers"
        try:
            await conn.execute(
                "INSERT INTO trusted_browsers (id, user_id, vault_id, pub_b, label, proof, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (browser_id, user_id, vault_id, pub_b, label, proof_b64u, t),
            )
        except aiosqlite.IntegrityError:
            await conn.rollback()
            return "browser_exists"
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return None


async def revoke_session(conn: aiosqlite.Connection, sid: str, t: int) -> None:
    """``sid`` in ``revoked_sessions``. Elk token met deze sid verloopt uiterlijk nu + ttl: na
    intrekken kan er geen nieuw token met deze sid bijkomen (reissue/step-up eisen een geldig,
    niet-ingetrokken token). Geen commit."""
    ttl = get_settings().jwt_ttl_minutes * 60
    await conn.execute(
        "INSERT OR REPLACE INTO revoked_sessions (sid, revoked_at, expires_at) VALUES (?, ?, ?)",
        (sid, t, t + ttl),
    )


async def revoke_browser_sessions(
    conn: aiosqlite.Connection, browser_ids: list[str], t: int
) -> int:
    """Trek alle nog geldige sessies in die via deze browser(s) zijn ingelogd. De sid van elke
    browser-login staat in de audit-detail van ``browser_login`` (geen schemawijziging nodig);
    alleen logins binnen de JWT-levensduur tellen. Geen commit."""
    if not browser_ids:
        return 0
    ttl = get_settings().jwt_ttl_minutes * 60
    marks = ",".join("?" * len(browser_ids))
    cur = await conn.execute(
        "SELECT DISTINCT json_extract(detail, '$.sid') AS sid FROM audit_log "  # noqa: S608
        f"WHERE event = 'browser_login' AND json_extract(detail, '$.browser_id') IN ({marks}) "
        "AND json_extract(detail, '$.sid') IS NOT NULL AND ts > ?",
        (*browser_ids, int(time.time()) - ttl - 60),
    )
    sids = [str(r["sid"]) for r in await cur.fetchall()]
    for sid in sids:
        await revoke_session(conn, sid, t)
    return len(sids)


async def _close_open_approvals(
    conn: aiosqlite.Connection, where: str, args: tuple[Any, ...], t: int, reason: str
) -> int:
    """Open verzoeken (draft/pending/approved) → ``denied`` met ``deny_reason``; ``resp`` weg.
    Geen commit."""
    cur = await conn.execute(
        "UPDATE approvals SET status = 'denied', resp = NULL, deny_reason = ?, decided_at = ? "  # noqa: S608
        f"WHERE status IN ('draft', 'pending', 'approved') AND {where}",
        (reason, t, *args),
    )
    return int(cur.rowcount)


async def revoke_browser(
    conn: aiosqlite.Connection, user_id: str, browser_id: str, t: int, reason: str
) -> bool:
    """``revoked_at = nu``; open verzoeken van die browser → ``denied``. Eén transactie."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cur = await conn.execute(
            "UPDATE trusted_browsers SET revoked_at = ?, revoke_reason = ? "
            "WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
            (t, reason, browser_id, user_id),
        )
        if cur.rowcount != 1:
            await conn.rollback()
            return False
        await _close_open_approvals(conn, "browser_id = ?", (browser_id,), t, "browser_revoked")
        await revoke_browser_sessions(conn, [browser_id], t)
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return True


async def revoke_vault_browsers(conn: aiosqlite.Connection, vault_id: str, t: int) -> list[str]:
    """Rekey (§14.7): alle vertrouwde browsers van de kluis ingetrokken (``rekey``), open
    verzoeken van de kluis gesloten. GEEN commit: hoort in de rekey-transactie."""
    cur = await conn.execute(
        "SELECT id FROM trusted_browsers WHERE vault_id = ? AND revoked_at IS NULL", (vault_id,)
    )
    ids = [str(r["id"]) for r in await cur.fetchall()]
    await conn.execute(
        "UPDATE trusted_browsers SET revoked_at = ?, revoke_reason = 'rekey' "
        "WHERE vault_id = ? AND revoked_at IS NULL",
        (t, vault_id),
    )
    await _close_open_approvals(conn, "vault_id = ?", (vault_id,), t, "rekey")
    await revoke_browser_sessions(conn, ids, t)
    return ids


# ─────────────── Inlog-challenges ───────────────


async def create_challenge(conn: aiosqlite.Connection, email_lc: str, t: int) -> dict[str, Any]:
    cid = str(uuid.uuid4())
    challenge = b64u(os.urandom(32))
    expires_at = t + CHALLENGE_TTL
    await conn.execute(
        "INSERT INTO browser_challenges (id, email_lc, challenge, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (cid, email_lc, challenge, t, expires_at),
    )
    await conn.commit()
    return {"challenge_id": cid, "challenge": challenge, "expires_at": expires_at}


async def challenges_in_window(conn: aiosqlite.Connection, email_lc: str, t: int) -> int:
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM browser_challenges WHERE email_lc = ? AND created_at > ?",
        (email_lc, t - CHALLENGE_WINDOW),
    )
    row = await cur.fetchone()
    return int(row["n"]) if row else 0


async def consume_challenge(conn: aiosqlite.Connection, challenge_id: str) -> dict[str, Any] | None:
    """Eenmalig, meteen verbruikt (ook als de rest daarna faalt). None = onbekend of al gebruikt."""
    cur = await conn.execute(
        "UPDATE browser_challenges SET used = 1 WHERE id = ? AND used = 0", (challenge_id,)
    )
    await conn.commit()
    if cur.rowcount != 1:
        return None
    cur = await conn.execute("SELECT * FROM browser_challenges WHERE id = ?", (challenge_id,))
    row = await cur.fetchone()
    return dict(row) if row else None


async def user_by_email(conn: aiosqlite.Connection, email_lc: str) -> dict[str, Any] | None:
    cur = await conn.execute("SELECT id, is_admin FROM users WHERE email = ?", (email_lc,))
    row = await cur.fetchone()
    return dict(row) if row else None


async def mark_browser_used(conn: aiosqlite.Connection, browser_id: str, t: int) -> None:
    await conn.execute("UPDATE trusted_browsers SET last_used_at = ? WHERE id = ?", (t, browser_id))
    await conn.execute(
        "UPDATE users SET last_login_at = ? WHERE id = "
        "(SELECT user_id FROM trusted_browsers WHERE id = ?)",
        (t, browser_id),
    )
    await conn.commit()


# ─────────────── Ontgrendelverzoeken ───────────────


async def get_approval(conn: aiosqlite.Connection, approval_id: str) -> dict[str, Any] | None:
    cur = await conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
    row = await cur.fetchone()
    return dict(row) if row else None


async def vault_has_phone_key(conn: aiosqlite.Connection, user_id: str, vault_id: str) -> bool:
    """Actieve telefoonsleutel van een actief (bevestigd, niet ingetrokken) toestel."""
    cur = await conn.execute(
        "SELECT 1 FROM vault_keys k JOIN devices d ON d.id = k.device_id "
        "WHERE k.user_id = ? AND k.vault_id = ? AND k.kind = 'phone' AND k.status = 'active' "
        "AND d.revoked_at IS NULL AND d.confirmed_at IS NOT NULL LIMIT 1",
        (user_id, vault_id),
    )
    return await cur.fetchone() is not None


async def device_key_for_vault(
    conn: aiosqlite.Connection, device_id: str, vault_id: str
) -> dict[str, Any] | None:
    cur = await conn.execute(
        "SELECT k.id, k.user_id FROM vault_keys k JOIN devices d ON d.id = k.device_id "
        "WHERE k.device_id = ? AND k.vault_id = ? AND k.kind = 'phone' AND k.status = 'active' "
        "AND d.revoked_at IS NULL AND d.confirmed_at IS NOT NULL "
        "ORDER BY k.created_at, k.rowid LIMIT 1",
        (device_id, vault_id),
    )
    row = await cur.fetchone()
    return dict(row) if row else None


async def create_approval(
    conn: aiosqlite.Connection,
    *,
    user_id: str,
    vault_id: str,
    browser_id: str,
    sid: str,
    ip: str | None,
    ua: str | None,
    t: int,
) -> tuple[str | None, str | None]:
    """Eén transactie: één open verzoek per sid, max per uur, dan een ``draft`` (30 s).

    Geeft ``(approval_id, None)`` of ``(None, foutcode)``."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cur = await conn.execute(
            "SELECT 1 FROM approvals WHERE sid = ? AND status IN ('draft', 'pending', 'approved') "
            "AND expires_at >= ? LIMIT 1",
            (sid, t),
        )
        if await cur.fetchone() is not None:
            await conn.rollback()
            return None, "approval_open"
        cur = await conn.execute(
            "SELECT COUNT(*) AS n FROM approvals WHERE user_id = ? AND created_at > ?",
            (user_id, t - 3600),
        )
        row = await cur.fetchone()
        if row and int(row["n"]) >= APPROVALS_PER_HOUR:
            await conn.rollback()
            return None, "too_many_approvals"
        approval_id = str(uuid.uuid4())
        await conn.execute(
            "INSERT INTO approvals (id, user_id, vault_id, browser_id, sid, status, ip, ua, "
            "created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?)",
            (
                approval_id,
                user_id,
                vault_id,
                browser_id,
                sid,
                ip,
                (ua or "")[:512] or None,
                t,
                t + DRAFT_TTL,
            ),
        )
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return approval_id, None


async def submit_approval(
    conn: aiosqlite.Connection,
    approval_id: str,
    *,
    epk_l: str,
    nonce_l: str,
    sig_req: str,
    t: int,
) -> int | None:
    """``draft`` → ``pending`` (expires_at = nu + 120) als het concept nog geldig is."""
    expires_at = t + PENDING_TTL
    cur = await conn.execute(
        "UPDATE approvals SET status = 'pending', epk_l = ?, nonce_l = ?, sig_req = ?, "
        "expires_at = ? WHERE id = ? AND status = 'draft' AND expires_at >= ?",
        (epk_l, nonce_l, sig_req, expires_at, approval_id, t),
    )
    await conn.commit()
    return expires_at if cur.rowcount == 1 else None


async def take_response(conn: aiosqlite.Connection, approval_id: str, t: int) -> str | None:
    """``approved`` → ``consumed`` atomair; geeft ``resp`` eenmalig terug en wist het."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        cur = await conn.execute(
            "SELECT resp FROM approvals WHERE id = ? AND status = 'approved' AND expires_at >= ?",
            (approval_id, t),
        )
        row = await cur.fetchone()
        if row is None or row["resp"] is None:
            await conn.rollback()
            return None
        resp = str(row["resp"])
        await conn.execute(
            "UPDATE approvals SET status = 'consumed', resp = NULL WHERE id = ?", (approval_id,)
        )
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return resp


async def cancel_approval(conn: aiosqlite.Connection, approval_id: str) -> bool:
    cur = await conn.execute(
        "UPDATE approvals SET status = 'cancelled', resp = NULL "
        "WHERE id = ? AND status IN ('draft', 'pending', 'approved')",
        (approval_id,),
    )
    await conn.commit()
    return cur.rowcount == 1


async def pending_for_device(
    conn: aiosqlite.Connection, device_id: str, t: int
) -> list[dict[str, Any]]:
    """Alleen ``pending`` en niet verlopen, voor kluizen waarvoor dit toestel een actieve
    sleutel heeft."""
    cur = await conn.execute(
        "SELECT a.id, a.vault_id FROM approvals a "
        "JOIN vault_keys k ON k.vault_id = a.vault_id AND k.user_id = a.user_id "
        "JOIN devices d ON d.id = k.device_id "
        "WHERE k.device_id = ? AND k.kind = 'phone' AND k.status = 'active' "
        "AND d.revoked_at IS NULL AND d.confirmed_at IS NOT NULL "
        "AND a.status = 'pending' AND a.expires_at >= ? "
        "GROUP BY a.id ORDER BY a.created_at, a.rowid",
        (device_id, t),
    )
    return [dict(r) for r in await cur.fetchall()]


async def decide(
    conn: aiosqlite.Connection,
    approval: dict[str, Any],
    *,
    device_id: str,
    decision: str,
    resp: str | None,
    reason: str | None,
    t: int,
) -> bool:
    """``pending`` → ``approved``/``denied`` atomair binnen ``expires_at``. Bij weigeren in dezelfde
    transactie: sessie ``sid`` ingetrokken, browser 15 min afkoelen; ``deny_revoke`` trekt ook de
    browser in (open verzoeken daarvan → denied). False = niet (meer) pending/verlopen of het
    toestel heeft intussen geen sleutel meer voor deze kluis."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        if await device_key_for_vault(conn, device_id, approval["vault_id"]) is None:
            await conn.rollback()
            return False
        if decision == "approve":
            cur = await conn.execute(
                "UPDATE approvals SET status = 'approved', resp = ?, device_id = ?, "
                "decided_at = ? WHERE id = ? AND status = 'pending' AND expires_at >= ?",
                (resp, device_id, t, approval["id"], t),
            )
        else:
            cur = await conn.execute(
                "UPDATE approvals SET status = 'denied', resp = NULL, device_id = ?, "
                "deny_reason = ?, decided_at = ? WHERE id = ? AND status = 'pending' "
                "AND expires_at >= ?",
                (device_id, reason or decision, t, approval["id"], t),
            )
        if cur.rowcount != 1:
            await conn.rollback()
            return False
        if decision != "approve":
            await revoke_session(conn, str(approval["sid"]), t)
            await conn.execute(
                "UPDATE trusted_browsers SET cooldown_until = ? WHERE id = ?",
                (t + DENY_COOLDOWN, approval["browser_id"]),
            )
            if decision == "deny_revoke":
                await conn.execute(
                    "UPDATE trusted_browsers SET revoked_at = ?, revoke_reason = 'phone_deny' "
                    "WHERE id = ? AND revoked_at IS NULL",
                    (t, approval["browser_id"]),
                )
                await _close_open_approvals(
                    conn, "browser_id = ?", (approval["browser_id"],), t, "browser_revoked"
                )
                await revoke_browser_sessions(conn, [str(approval["browser_id"])], t)
        await conn.commit()
    except BaseException:
        await conn.rollback()
        raise
    return True


async def vault_name(conn: aiosqlite.Connection, vault_id: str) -> str | None:
    cur = await conn.execute("SELECT name FROM vaults WHERE id = ?", (vault_id,))
    row = await cur.fetchone()
    return str(row["name"]) if row else None


def now() -> int:
    return svc.now()
