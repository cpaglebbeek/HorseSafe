"""Step-up (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.8.

Een step-up is een kortlevende JWT-claim (``stepup_until`` + ``stepup_method``) bovenop een
gewone sessie met MFA. Bio = assertion met een actieve YubiKey Bio; TOTP alleen als de gebruiker
geen actieve Bio heeft. Opheffen van een noodsleutel-blokkade kan nooit met TOTP (besluit 3).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request, status

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


def has_stepup(payload: dict[str, Any], methods: tuple[str, ...] = STEPUP_METHODS) -> bool:
    return stepup_until(payload) is not None and payload.get("stepup_method") in methods


def require_stepup(
    request: Request, methods: tuple[str, ...] = STEPUP_METHODS
) -> dict[str, Any]:
    """SU: S + geldige step-up. Verkeerde methode (alleen bij unblock relevant) → stepup_bio_required."""
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
