"""Step-up (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.8.

Een step-up is een kortlevende JWT-claim (``stepup_until`` + ``stepup_method``) bovenop een
gewone sessie met MFA. Bio = assertion met een actieve YubiKey Bio; TOTP alleen als de gebruiker
geen actieve Bio heeft. Opheffen van een noodsleutel-blokkade kan nooit met TOTP (besluit 3), en
alleen met een Bio die al gekoppeld was vóór de blokkade (``stepup_key``, R6).

TOTP-step-up heeft een afkoelperiode (``recovery_delay_hours``) na het verwijderen van een Bio en na
het instellen van TOTP terwijl er al hardware-sleutels waren. Zo kan wie het accountwachtwoord en
TOTP buitmaakt niet direct de Bio wegnemen en een eigen sleutel koppelen; de gebruiker krijgt eerst
de meldingen.
"""

from __future__ import annotations

import time
from typing import Any

import aiosqlite
from fastapi import HTTPException, Request, status

from ..config import get_settings
from . import jwt_service
from . import vault_key_service as svc

STEPUP_METHODS = ("bio", "totp")


def session(request: Request) -> dict[str, Any]:
    """S: geldig JWT met ``mfa=true`` (zelfde regels als ``routes/vault.py::_user``)."""
    payload = jwt_service.require_auth(request)
    if not bool(payload.get("mfa", False)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "mfa_required"})
    return payload


def stepup_until(payload: dict[str, Any]) -> int | None:
    """De step-up-claim als die nog geldig is, anders None."""
    until = payload.get("stepup_until")
    if not isinstance(until, int) or isinstance(until, bool):
        return None
    if payload.get("stepup_method") not in STEPUP_METHODS:
        return None
    return until if until >= svc.now() else None


def require_stepup(request: Request, methods: tuple[str, ...] = STEPUP_METHODS) -> dict[str, Any]:
    """SU: S + geldige step-up.

    Verkeerde methode (alleen bij unblock relevant) → ``stepup_bio_required``."""
    payload = session(request)
    check_stepup(payload, methods)
    return payload


def check_stepup(payload: dict[str, Any], methods: tuple[str, ...] = STEPUP_METHODS) -> None:
    if stepup_until(payload) is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail={"error": "stepup_required"}
        )
    if payload.get("stepup_method") not in methods:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail={"error": "stepup_bio_required"}
        )


async def totp_cooldown_until(conn: aiosqlite.Connection, user_id: str) -> int | None:
    """Tijdstip (epoch) waarop TOTP-step-up weer mag, of None als dat nu al mag.

    Bron: de audit-log (zelfde klok als de ``stepup_fail``-telling)."""
    window = get_settings().recovery_delay_hours * 3600
    cur = await conn.execute(
        "SELECT MAX(ts) AS ts FROM audit_log WHERE user_id = ? AND ts > ? AND ("
        "(event = 'vault_key_delete' AND json_extract(detail, '$.kind') = 'bio') OR "
        "(event = 'mfa_setup_totp' AND json_extract(detail, '$.had_keys') = 1))",
        (user_id, int(time.time()) - window),
    )
    row = await cur.fetchone()
    if not row or row["ts"] is None:
        return None
    return int(row["ts"]) + window
