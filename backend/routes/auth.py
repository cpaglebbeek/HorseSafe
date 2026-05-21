from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status

from ..config import get_settings
from ..db.connection import connect
from ..models.user import UserLogin, UserRegister
from ..services import audit_service, auth_service, jwt_service

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, request: Request) -> dict[str, str]:
    if not payload.ack_data_loss:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ack_required",
                "message": (
                    "Je moet bevestigen dat data permanent verloren gaat bij vergeten wachtwoord"
                ),
            },
        )
    settings = get_settings()
    ip = request.client.host if request.client else None
    async with connect(settings.db_path) as conn:
        try:
            user_id = await auth_service.create_user(conn, payload.email, payload.password)
        except ValueError as e:
            raise HTTPException(
                status_code=409,
                detail={"error": str(e), "message": "E-mail al in gebruik"},
            ) from e
        await audit_service.log(
            conn,
            user_id=user_id,
            event="register",
            ip=ip,
            user_agent=request.headers.get("user-agent"),
        )
    return {"user_id": user_id, "email": payload.email}


@router.post("/login")
async def login(payload: UserLogin, request: Request, response: Response) -> dict[str, object]:
    settings = get_settings()
    ip = request.client.host if request.client else "unknown"
    async with connect(settings.db_path) as conn:
        if await auth_service.is_throttled(conn, ip, payload.email):
            await audit_service.log(
                conn,
                user_id=None,
                event="login_throttled",
                ip=ip,
                user_agent=request.headers.get("user-agent"),
                detail={"email": payload.email},
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={"error": "throttled", "message": "Te veel mislukte pogingen"},
            )
        result = await auth_service.authenticate(conn, payload.email, payload.password)
        if result is None:
            await auth_service.record_failed_login(conn, ip, payload.email)
            await audit_service.log(
                conn,
                user_id=None,
                event="login_fail",
                ip=ip,
                user_agent=request.headers.get("user-agent"),
                detail={"email": payload.email},
            )
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_credentials"},
            )
        user_id, is_admin = result
        token = jwt_service.issue(user_id, is_admin)
        jwt_service.set_cookie(response, token)
        await audit_service.log(
            conn,
            user_id=user_id,
            event="login_success",
            ip=ip,
            user_agent=request.headers.get("user-agent"),
        )
        # NB: Fase 3 voegt mfa_required toe; v0.0.1 = single-factor account-login
        return {"ok": True, "mfa_required": False, "is_admin": is_admin}


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict[str, bool]:
    settings = get_settings()
    token_payload = jwt_service.require_auth(request)
    async with connect(settings.db_path) as conn:
        await audit_service.log(
            conn,
            user_id=str(token_payload["sub"]),
            event="logout",
            ip=request.client.host if request.client else None,
        )
    jwt_service.clear_cookie(response)
    return {"ok": True}
