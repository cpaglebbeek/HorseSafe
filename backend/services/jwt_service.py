from __future__ import annotations

import sqlite3
import time
import uuid
from typing import Any

import jwt
from fastapi import HTTPException, Request, Response, status

from ..config import get_settings


def issue(
    user_id: str,
    is_admin: bool,
    mfa_passed: bool = False,
    *,
    stepup_until: int | None = None,
    stepup_method: str | None = None,
    stepup_key: str | None = None,
    sid: str | None = None,
    amr: list[str] | None = None,
    browser_id: str | None = None,
    fresh_sid: bool = True,
) -> str:
    """Nieuw JWT. Step-up-claims (v0.2.0-Koblitz, §12.8) alleen als beide gezet zijn;
    een gewone login of ``reissue_with_mfa`` laat ze weg, zodat een step-up dan vervalt.

    v0.4.0-Montgomery (§14.4): elke sessie heeft een ``sid`` (UUID). Een login maakt een nieuwe;
    ``reissue_with_mfa`` en step-up nemen hem over (``carry_claims``), zodat een ingetrokken sessie
    ingetrokken blijft. Een oud cookie zonder ``sid`` krijgt er bij overnemen geen
    (``fresh_sid=False``): zo'n sessie mag geen ontgrendelverzoek starten (opnieuw inloggen)."""
    settings = get_settings()
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": user_id,
        "admin": is_admin,
        "mfa": mfa_passed,
        "iat": now,
        "exp": now + settings.jwt_ttl_minutes * 60,
    }
    if sid is None and fresh_sid:
        sid = str(uuid.uuid4())
    if sid is not None:
        payload["sid"] = sid
    if amr is not None:
        payload["amr"] = list(amr)
    if browser_id is not None:  # alleen bij inloggen op een vertrouwde browser
        payload["browser_id"] = browser_id
    if stepup_until is not None and stepup_method is not None:
        payload["stepup_until"] = int(stepup_until)
        payload["stepup_method"] = stepup_method
        if stepup_key is not None:  # bio: welke sleutel bevestigde (unblock, §12.6.7)
            payload["stepup_key"] = stepup_key
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def carry_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Sessieclaims die bij ``reissue_with_mfa`` en step-up behouden blijven (§14.4)."""
    amr = payload.get("amr")
    browser_id = payload.get("browser_id")
    sid = payload.get("sid")
    return {
        "sid": sid if isinstance(sid, str) else None,
        "amr": [str(a) for a in amr] if isinstance(amr, list) else None,
        "browser_id": browser_id if isinstance(browser_id, str) else None,
        "fresh_sid": False,
    }


def session_revoked(sid: str) -> bool:
    """Staat ``sid`` in ``revoked_sessions`` (§14.7)? Synchroon: ``require_auth`` is synchroon.

    Een database zonder de tabel (vóór migratie 007) kent geen ingetrokken sessies. Elke andere
    fout (bv. een vergrendelde database) → 503: nooit stilzwijgend een ingetrokken sessie toelaten.
    """
    path = get_settings().db_path
    if not path.exists():
        return False
    try:
        con = sqlite3.connect(str(path), timeout=5)
        try:
            row = con.execute("SELECT 1 FROM revoked_sessions WHERE sid = ?", (sid,)).fetchone()
        finally:
            con.close()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return False
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_check_unavailable"},
        ) from e
    return row is not None


def decode(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = dict(jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]))
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": str(e)},
        ) from e
    sid = payload.get("sid")
    if isinstance(sid, str) and session_revoked(sid):
        # §14.5: geweigerd op de telefoon → deze sessie is uitgelogd.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "reason": "session_revoked"},
        )
    return payload


def set_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_ttl_minutes * 60,
        path="/",
    )


def clear_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.cookie_name, path="/")


def require_auth(request: Request) -> dict[str, Any]:
    settings = get_settings()
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated"},
        )
    return decode(token)


def reissue_with_mfa(response: Response, payload: dict[str, Any]) -> None:
    """Maak nieuw JWT-cookie met mfa=true op basis van bestaande payload."""
    new_token = issue(
        user_id=str(payload["sub"]),
        is_admin=bool(payload.get("admin", False)),
        mfa_passed=True,
        **carry_claims(payload),
    )
    set_cookie(response, new_token)
