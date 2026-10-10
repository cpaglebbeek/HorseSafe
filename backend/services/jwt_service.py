from __future__ import annotations

import time
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
) -> str:
    """Nieuw JWT. Step-up-claims (v0.2.0-Koblitz, §12.8) alleen als beide gezet zijn;
    een gewone login of ``reissue_with_mfa`` laat ze weg, zodat een step-up dan vervalt."""
    settings = get_settings()
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": user_id,
        "admin": is_admin,
        "mfa": mfa_passed,
        "iat": now,
        "exp": now + settings.jwt_ttl_minutes * 60,
    }
    if stepup_until is not None and stepup_method is not None:
        payload["stepup_until"] = int(stepup_until)
        payload["stepup_method"] = stepup_method
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return dict(jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]))
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": str(e)},
        ) from e


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
    )
    set_cookie(response, new_token)
