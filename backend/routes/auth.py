from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from ..config import get_settings
from ..db.connection import connect
from ..models.admin import BackupCodeVerify, MeResponse
from ..models.auth import MagicLinkRequest
from ..models.user import UserLogin, UserRegister
from ..models.webauthn import StepupBio, StepupRequest
from ..services import (
    audit_service,
    auth_service,
    backup_codes_service,
    jwt_service,
    magic_link_service,
    mfa_service,
    pw_service,
    stepup_service,
)
from ..services import vault_key_service as vk_svc
from ..services import webauthn_service as wa

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
        # MFA-status: heeft user TOTP geconfigureerd? Zo ja → JWT met mfa=false; vault-gate
        # weigert tot /auth/totp/verify of /auth/magic-link/redeem doorlopen is.
        has_totp = await mfa_service.user_has_totp(conn, user_id)
        token = jwt_service.issue(user_id, is_admin, mfa_passed=not has_totp)
        jwt_service.set_cookie(response, token)
        await audit_service.log(
            conn,
            user_id=user_id,
            event="login_success",
            ip=ip,
            user_agent=request.headers.get("user-agent"),
        )
        return {"ok": True, "mfa_required": has_totp, "is_admin": is_admin}


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


# ─────────────── MFA: TOTP ───────────────


@router.post("/totp/setup")
async def totp_setup(request: Request) -> dict[str, str]:
    """Genereer nieuw TOTP-secret + otpauth-URL. Wordt pas opgeslagen na /verify."""
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    secret = mfa_service.generate_secret()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail={"error": "user_not_found"})
        uri = mfa_service.provisioning_uri(secret, str(row["email"]))
    # Secret in response — caller moet hem direct verifiëren via /verify;
    # zonder verify wordt hij niet aan account gekoppeld.
    return {"secret": secret, "otpauth_url": uri}


@router.post("/totp/verify")
async def totp_verify(
    body: dict[str, str], request: Request, response: Response
) -> dict[str, bool]:
    """Verifieer code. Twee gebruikspaden:

    1. Setup-flow: body bevat 'secret' + 'code' → bij succes: secret opslaan + mfa-cookie upgrade.
    2. Challenge-flow: alleen 'code' → tegen stored secret, upgrade mfa-cookie.
    """
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    code = body.get("code", "")
    secret_arg = body.get("secret")
    ip = request.client.host if request.client else "unknown"

    async with connect(settings.db_path) as conn:
        # Throttle op MFA-failed-pogingen (hergebruik failed_logins-tabel via event)
        if await auth_service.is_throttled(conn, ip, None):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={"error": "throttled"},
            )

        if secret_arg:
            # Setup-flow
            ok = mfa_service.verify_code(secret_arg, code)
            if not ok:
                await auth_service.record_failed_login(conn, ip, None)
                await audit_service.log(
                    conn, user_id=user_id, event="mfa_fail", ip=ip, detail={"flow": "setup"}
                )
                raise HTTPException(status_code=400, detail={"error": "invalid_code"})
            await mfa_service.set_user_totp(conn, user_id, secret_arg)
            await audit_service.log(conn, user_id=user_id, event="mfa_setup_totp", ip=ip)
        else:
            # Challenge-flow
            stored = await mfa_service.get_user_totp(conn, user_id)
            if not stored:
                raise HTTPException(status_code=400, detail={"error": "totp_not_configured"})
            ok = mfa_service.verify_code(stored, code)
            if not ok:
                await auth_service.record_failed_login(conn, ip, None)
                await audit_service.log(
                    conn, user_id=user_id, event="mfa_fail", ip=ip, detail={"flow": "challenge"}
                )
                raise HTTPException(status_code=400, detail={"error": "invalid_code"})
            await audit_service.log(conn, user_id=user_id, event="mfa_pass_totp", ip=ip)

    # Upgrade JWT met mfa=true
    jwt_service.reissue_with_mfa(response, payload)
    return {"ok": True, "mfa_passed": True}


@router.post("/totp/disable")
async def totp_disable(body: dict[str, str], request: Request) -> dict[str, bool]:
    """Disable TOTP. Vereist huidige TOTP-code als verificatie."""
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    code = body.get("code", "")
    async with connect(settings.db_path) as conn:
        stored = await mfa_service.get_user_totp(conn, user_id)
        if not stored:
            raise HTTPException(status_code=400, detail={"error": "totp_not_configured"})
        if not mfa_service.verify_code(stored, code):
            raise HTTPException(status_code=400, detail={"error": "invalid_code"})
        await mfa_service.remove_user_totp(conn, user_id)
        await audit_service.log(
            conn, user_id=user_id, event="mfa_setup_totp", ip=None, detail={"action": "disabled"}
        )
    return {"ok": True}


# ─────────────── MFA: Magic-link ───────────────


@router.post("/magic-link")
async def magic_link_request(body: MagicLinkRequest, request: Request) -> dict[str, bool]:
    """Vraag magic-link aan. Stuurt e-mail. Geeft GEEN onthullende informatie over
    of het e-mailadres bestaat (info-leak-resistant)."""
    settings = get_settings()
    mail_body: str | None = None
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute("SELECT id FROM users WHERE email = ?", (body.email.lower(),))
        row = await cursor.fetchone()
        if row:
            user_id = str(row["id"])
            _token, mail_body = await magic_link_service.create_magic_link(conn, user_id)
            await audit_service.log(
                conn,
                user_id=user_id,
                event="mfa_pass_magic_link",
                ip=request.client.host if request.client else None,
                detail={"step": "issued"},
            )
    # Mail pas na het sluiten van de DB-verbinding, buiten de event-loop (v0.2.0-Koblitz).
    if mail_body is not None:
        await magic_link_service.send_magic_link(body.email, mail_body)
    return {"ok": True}


@router.get("/magic-link/redeem")
async def magic_link_redeem(t: str, request: Request) -> RedirectResponse:
    """Verzilver magic-link → set JWT-cookie met mfa=true → redirect frontend."""
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        user_id = await magic_link_service.consume_magic_link(conn, t)
        if not user_id:
            # Redirect naar login met error-param
            return RedirectResponse(
                url=f"{settings.public_url.rstrip('/')}/login.html?error=invalid_link",
                status_code=302,
            )
        cursor = await conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        is_admin = bool(row and row["is_admin"])
        token = jwt_service.issue(user_id, is_admin, mfa_passed=True)
        await audit_service.log(
            conn,
            user_id=user_id,
            event="mfa_pass_magic_link",
            ip=request.client.host if request.client else None,
            detail={"step": "redeemed"},
        )
    redirect = RedirectResponse(
        url=f"{settings.public_url.rstrip('/')}/vault.html",
        status_code=302,
    )
    redirect.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_ttl_minutes * 60,
        path="/",
    )
    return redirect


# ─────────────── /auth/me ───────────────


@router.get("/me", response_model=MeResponse)
async def me(request: Request) -> MeResponse:
    """Geeft current-user-meta terug (vervangt de /vault-probe-hack)."""
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute(
            "SELECT email, is_admin, last_login_at, pubkey FROM users WHERE id = ?",
            (user_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail={"error": "user_not_found"})
        has_totp = await mfa_service.user_has_totp(conn, user_id)
        backup_remaining = await backup_codes_service.count_remaining(conn, user_id)
    return MeResponse(
        id=user_id,
        email=str(row["email"]),
        is_admin=bool(row["is_admin"]),
        has_totp=has_totp,
        backup_codes_remaining=backup_remaining,
        has_keypair=bool(row["pubkey"]),
        mfa_pass=bool(payload.get("mfa", False)),
        last_login_at=int(row["last_login_at"]) if row["last_login_at"] else None,
    )


# ─────────────── Backup-codes ───────────────


@router.post("/backup-codes/generate")
async def backup_codes_generate(request: Request) -> dict[str, list[str]]:
    """Genereer 10 nieuwe codes (returnt plaintext — show-once aan client)."""
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        codes = await backup_codes_service.generate_for_user(conn, user_id, count=10)
        await audit_service.log(
            conn,
            user_id=user_id,
            event="backup_codes_generate",
            ip=request.client.host if request.client else None,
            detail={"count": len(codes)},
        )
    return {"codes": codes}


@router.post("/backup-codes/verify")
async def backup_codes_verify(
    body: BackupCodeVerify, request: Request, response: Response
) -> dict[str, bool]:
    """Verifieer backup-code als MFA-bypass (single-use). Upgrade JWT met mfa=true."""
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    ip = request.client.host if request.client else "unknown"
    async with connect(settings.db_path) as conn:
        if await auth_service.is_throttled(conn, ip, None):
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail={"error": "throttled"})
        ok = await backup_codes_service.consume_code(conn, user_id, body.code)
        if not ok:
            await auth_service.record_failed_login(conn, ip, None)
            await audit_service.log(
                conn,
                user_id=user_id,
                event="mfa_fail",
                ip=ip,
                detail={"flow": "backup_code"},
            )
            raise HTTPException(status_code=400, detail={"error": "invalid_code"})
        remaining = await backup_codes_service.count_remaining(conn, user_id)
        await audit_service.log(
            conn,
            user_id=user_id,
            event="backup_codes_consume",
            ip=ip,
            detail={"remaining": remaining},
        )
    jwt_service.reissue_with_mfa(response, payload)
    return {"ok": True, "mfa_passed": True}


# ─────────────── Account-pw change ───────────────


@router.post("/password")
async def change_password(body: dict[str, str], request: Request) -> dict[str, bool]:
    """Wijzig account-pw (NIET vault-master-pw, dat blijft client-side).

    Body: {old_password, new_password}. Vereist JWT.
    """
    payload = jwt_service.require_auth(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    old_pw = body.get("old_password", "")
    new_pw = body.get("new_password", "")
    if not old_pw or not new_pw:
        raise HTTPException(status_code=400, detail={"error": "missing_fields"})
    async with connect(settings.db_path) as conn:
        try:
            ok = await pw_service.change_account_password(conn, user_id, old_pw, new_pw)
        except ValueError as e:
            raise HTTPException(status_code=400, detail={"error": str(e)}) from e
        if not ok:
            raise HTTPException(status_code=401, detail={"error": "wrong_old_password"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event="account_password_changed",
            ip=request.client.host if request.client else None,
        )
    return {"ok": True}


# ─────────────── Step-up (v0.2.0-Koblitz, docs/HARDWARE_KEYS.md §12.8) ───────────────

STEPUP_FAIL_MAX = 5
STEPUP_FAIL_WINDOW_SECONDS = 15 * 60


@router.post("/stepup")
async def stepup(body: StepupRequest, request: Request, response: Response) -> dict[str, object]:
    """Korte bevestiging bovenop de sessie: YubiKey Bio, of TOTP als er geen actieve Bio is."""
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    clone: tuple[str, str] | None = None
    async with connect(settings.db_path) as conn:
        if isinstance(body, StepupBio):
            try:
                row = await wa.consume_challenge(conn, body.challenge_id, user_id)
                if row["purpose"] != "stepup":
                    raise wa.WebAuthnError("invalid_challenge")
                key = next(
                    (k for k in await vk_svc.user_bio_keys(conn, user_id)
                     if k["credential_id"] == body.credential_id),
                    None,
                )
                if key is None:
                    raise wa.WebAuthnError("credential_mismatch")
                new_count = wa.verify_assertion(
                    credential_id=body.credential_id,
                    client_data_json=body.client_data_json,
                    authenticator_data=body.authenticator_data,
                    signature=body.signature,
                    user_handle=body.user_handle,
                    challenge_row=row,
                    cose_public_key=key["cose_public_key"],
                    stored_sign_count=int(key["sign_count"]),
                )
            except wa.WebAuthnError as e:
                if e.code == "sign_count_regression":
                    await audit_service.log(
                        conn, user_id=user_id, event="vault_key_clone_suspect", ip=ip,
                        user_agent=ua,
                        detail={"vault_id": key["vault_id"], "key_id": key["id"], "kind": "bio"},
                    )
                    clone = (await vk_svc.user_email(conn, user_id) or "", str(key["label"]))
                    err = HTTPException(status_code=e.status, detail={"error": e.code})
                else:
                    raise HTTPException(status_code=e.status, detail={"error": e.code}) from e
            else:
                err = None
                await vk_svc.update_key(
                    conn, key["id"], sign_count=new_count, last_used_at=vk_svc.now()
                )
        else:
            err = None
            if await vk_svc.user_bio_keys(conn, user_id):
                raise HTTPException(status_code=403, detail={"error": "stepup_method_not_allowed"})
            secret = await mfa_service.get_user_totp(conn, user_id)
            if not secret:
                raise HTTPException(status_code=409, detail={"error": "stepup_unavailable"})
            cur = await conn.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ? AND event = 'stepup_fail' "
                "AND ts > ?",
                (user_id, int(time.time()) - STEPUP_FAIL_WINDOW_SECONDS),
            )
            fails = await cur.fetchone()
            if fails and int(fails["n"]) >= STEPUP_FAIL_MAX:
                raise HTTPException(status_code=429, detail={"error": "too_many_attempts"})
            if not mfa_service.verify_code(secret, body.code):
                await audit_service.log(
                    conn, user_id=user_id, event="stepup_fail", ip=ip, user_agent=ua,
                    detail={"method": "totp"},
                )
                raise HTTPException(status_code=401, detail={"error": "invalid_code"})
        if err is None:
            until = vk_svc.now() + settings.stepup_ttl_seconds
            await audit_service.log(
                conn, user_id=user_id, event="stepup", ip=ip, user_agent=ua,
                detail={"method": body.method},
            )
    if err is not None:
        if clone is not None:
            await vk_svc.notify_user(
                clone[0], "HorseSafe: verdachte sleutel-teller",
                vk_svc.notify_body(
                    "De teller van een hardware-sleutel ging terug. Dat kan wijzen op een "
                    "gekloonde sleutel; de sleutel is geweigerd.",
                    label=clone[1], ip=ip,
                    advice="Ontgrendel met je keyfile, controleer je sleutels en verwijder deze sleutel.",
                ),
                user_id=user_id, event="vault_key_clone_suspect", ip=ip, user_agent=ua,
            )
        raise err
    token = jwt_service.issue(
        user_id,
        bool(payload.get("admin", False)),
        mfa_passed=True,
        stepup_until=until,
        stepup_method=body.method,
    )
    jwt_service.set_cookie(response, token)
    return {"ok": True, "method": body.method, "stepup_until": until}
