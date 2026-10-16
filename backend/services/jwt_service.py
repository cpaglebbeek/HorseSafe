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
    scope: str | None = None,
    auth_time: int | None = None,
) -> str:
    """Nieuw JWT. Step-up-claims (v0.2.0-Koblitz, §12.8) alleen als beide gezet zijn;
    een gewone login of ``reissue_with_mfa`` laat ze weg, zodat een step-up dan vervalt.

    v0.4.0-Montgomery (§14.4): elke sessie heeft een ``sid`` (UUID). Een login maakt een nieuwe;
    ``reissue_with_mfa`` en step-up nemen hem over (``carry_claims``), zodat een ingetrokken sessie
    ingetrokken blijft. Een oud cookie zonder ``sid`` krijgt er bij overnemen geen
    (``fresh_sid=False``): zo'n sessie mag geen ontgrendelverzoek starten (opnieuw inloggen).

    Review 4db1810: ``auth_time`` = moment van de eerste login; reissue/step-up nemen het over en
    een sessie leeft nooit langer dan ``auth_time + jwt_ttl`` (absolute grens, geen eindeloos
    verlengen). ``scope="browser_pending"``: sessie van een vertrouwde browser die nog geen
    telefoongoedkeuring had (zie ``scope_guard``)."""
    settings = get_settings()
    now = int(time.time())
    ttl = settings.jwt_ttl_minutes * 60
    if auth_time is None:
        auth_time = now
    payload: dict[str, Any] = {
        "sub": user_id,
        "admin": is_admin,
        "mfa": mfa_passed,
        "iat": now,
        "exp": min(now + ttl, auth_time + ttl),
        "auth_time": int(auth_time),
    }
    if scope is not None:
        payload["scope"] = scope
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
    scope = payload.get("scope")
    auth_time = payload.get("auth_time", payload.get("iat"))
    return {
        "sid": sid if isinstance(sid, str) else None,
        "amr": [str(a) for a in amr] if isinstance(amr, list) else None,
        "browser_id": browser_id if isinstance(browser_id, str) else None,
        "fresh_sid": False,
        # beperking blijft bij elke reissue; alleen de goedgekeurde ontgrendeling haalt hem weg
        "scope": scope if isinstance(scope, str) else None,
        "auth_time": int(auth_time) if isinstance(auth_time, int) else None,
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
    auth_time = payload.get("auth_time")
    if isinstance(auth_time, int) and time.time() > auth_time + settings.jwt_ttl_minutes * 60:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "reason": "session_expired"},
        )
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


# ─────────────── Beperkte browsersessie (review 4db1810, H1) ───────────────

SCOPE_BROWSER_PENDING = "browser_pending"

# Met scope browser_pending ALLEEN deze routes (methode, route-sjabloon). Default deny.
BROWSER_PENDING_ALLOWED: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/auth/me"),
        ("POST", "/auth/logout"),
        ("GET", "/vault"),
        ("GET", "/vault/{vault_id}"),
        ("GET", "/vault/{vault_id}/keys"),
        ("POST", "/vault/{vault_id}/approvals"),
        ("PUT", "/vault/{vault_id}/approvals/{approval_id}"),
        ("GET", "/vault/{vault_id}/approvals/{approval_id}"),
        ("DELETE", "/vault/{vault_id}/approvals/{approval_id}"),
        ("GET", "/trusted-browsers"),
        ("DELETE", "/trusted-browsers/{browser_id}"),  # alleen de eigen browser (route)
    }
)

# Routes die het sessiecookie niet gebruiken (eigen authenticatie of publiek). Daar weigert de guard
# niet, zodat bv. opnieuw inloggen met een beperkt cookie in de browser gewoon kan.
SESSIONLESS_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health"),
        ("POST", "/auth/register"),
        ("POST", "/auth/login"),
        ("POST", "/auth/magic-link"),
        ("GET", "/auth/magic-link/redeem"),
        ("POST", "/auth/browser/challenge"),
        ("POST", "/auth/browser/login"),
        ("POST", "/devices/pairings/{pairing_id}/claim"),
        ("GET", "/device/v1/status"),
        ("GET", "/device/v1/keys/{key_id}/sealed"),
        ("GET", "/device/v1/approvals/{approval_id}"),
        ("POST", "/device/v1/approvals/{approval_id}"),
    }
)


def phone_approval_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail={"error": "phone_approval_required"}
    )


def scope_guard(request: Request) -> None:
    """App-brede dependency (draait vóór body-validatie en vóór de route): een sessie met
    ``scope=browser_pending`` mag alleen de routes uit ``BROWSER_PENDING_ALLOWED``; al het andere
    → 403 ``phone_approval_required``. Geen of ongeldig cookie: niets doen (de route beslist)."""
    token = request.cookies.get(get_settings().cookie_name)
    if not token:
        return
    try:
        payload = decode(token)
    except HTTPException:
        return
    if payload.get("scope") != SCOPE_BROWSER_PENDING:
        return
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    key = (request.method.upper(), str(path))
    if key in BROWSER_PENDING_ALLOWED or key in SESSIONLESS_ROUTES:
        return
    raise phone_approval_required()


def require_full_session(payload: dict[str, Any]) -> None:
    """Defensie in de diepte voor routes buiten de whitelist (ook als de guard ooit ontbreekt)."""
    if payload.get("scope") == SCOPE_BROWSER_PENDING:
        raise phone_approval_required()


def is_browser_session(payload: dict[str, Any]) -> bool:
    amr = payload.get("amr")
    return isinstance(amr, list) and "browser" in amr
