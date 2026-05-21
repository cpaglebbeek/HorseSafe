from __future__ import annotations

import time
from typing import Any

import jwt
from fastapi import HTTPException, Request, Response, status

from ..config import get_settings


def issue(user_id: str, is_admin: bool) -> str:
    settings = get_settings()
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": user_id,
        "admin": is_admin,
        "iat": now,
        "exp": now + settings.jwt_ttl_minutes * 60,
    }
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
