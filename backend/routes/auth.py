from __future__ import annotations

import time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from ..config import get_settings
from ..db.connection import connect
from ..models.admin import BackupCodeVerify, MeResponse
from ..models.auth import MagicLinkRedeem, MagicLinkRequest
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
    trust_service,
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
        sid = token_payload.get("sid")
        if isinstance(sid, str) and sid:  # v0.4.0-Montgomery: uitgelogd = sessie ingetrokken
            await trust_service.revoke_session(conn, sid, vk_svc.now())
            await conn.commit()
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

    notify: str | None = None
    async with connect(settings.db_path) as conn:
        # Throttle op MFA-failed-pogingen (hergebruik failed_logins-tabel via event)
        if await auth_service.is_throttled(conn, ip, None):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail={"error": "throttled"},
            )

        if secret_arg:
            # Setup-flow. Een bestaand secret vervangen kan niet (eerst /totp/disable met de
            # huidige code); met hardware-sleutels alleen vanuit een sessie die MFA al heeft —
            # anders zou het accountwachtwoord alleen genoeg zijn voor S en TOTP-step-up.
            if await mfa_service.user_has_totp(conn, user_id):
                raise HTTPException(status_code=409, detail={"error": "totp_already_configured"})
            had_keys = await vk_svc.user_has_keys(conn, user_id)
            if had_keys and not bool(payload.get("mfa", False)):
                raise HTTPException(status_code=403, detail={"error": "mfa_required"})
            step = mfa_service.matched_step(secret_arg, code)
            ok = step is not None
            if not ok:
                await auth_service.record_failed_login(conn, ip, None)
                await audit_service.log(
                    conn, user_id=user_id, event="mfa_fail", ip=ip, detail={"flow": "setup"}
                )
                raise HTTPException(status_code=400, detail={"error": "invalid_code"})
            await mfa_service.set_user_totp(conn, user_id, secret_arg)
            await audit_service.log(
                conn,
                user_id=user_id,
                event="mfa_setup_totp",
                ip=ip,
                user_agent=request.headers.get("user-agent"),
                detail={"action": "enabled", "had_keys": had_keys, "totp_step": step},
            )
            notify = await vk_svc.user_email(conn, user_id)
        else:
            # Challenge-flow
            stored = await mfa_service.get_user_totp(conn, user_id)
            if not stored:
                raise HTTPException(status_code=400, detail={"error": "totp_not_configured"})
            step = mfa_service.matched_step(stored, code)
            # Review 4db1810 (M2): een code geldt één keer (atomair via totp_used).
            if step is None or not await mfa_service.use_step(conn, user_id, step):
                await auth_service.record_failed_login(conn, ip, None)
                await audit_service.log(
                    conn, user_id=user_id, event="mfa_fail", ip=ip, detail={"flow": "challenge"}
                )
                raise HTTPException(status_code=400, detail={"error": "invalid_code"})
            await audit_service.log(
                conn, user_id=user_id, event="mfa_pass_totp", ip=ip, detail={"totp_step": step}
            )

    if notify:
        await _totp_changed_mail(request, user_id, notify, enabled=True)
    # Upgrade JWT met mfa=true
    jwt_service.reissue_with_mfa(response, payload)
    return {"ok": True, "mfa_passed": True}


async def _totp_changed_mail(request: Request, user_id: str, email: str, *, enabled: bool) -> None:
    """Melding bij elke TOTP-wijziging (v0.2.0-Koblitz), na het sluiten van de DB-verbinding."""
    ip = request.client.host if request.client else None
    text = (
        "Er is een authenticator-app (TOTP) aan je account gekoppeld."
        if enabled
        else "De authenticator-app (TOTP) is van je account verwijderd."
    )
    await vk_svc.notify_user(
        email,
        "HorseSafe: authenticator-app " + ("ingesteld" if enabled else "verwijderd"),
        vk_svc.notify_body(
            text,
            label=None,
            ip=ip,
            advice="Log direct in, controleer je account en je sleutels, en wijzig je wachtwoord.",
        ),
        user_id=user_id,
        event="mfa_setup_totp",
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )


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
            conn,
            user_id=user_id,
            event="mfa_setup_totp",
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={"action": "disabled"},
        )
        email = await vk_svc.user_email(conn, user_id)
    if email:
        await _totp_changed_mail(request, user_id, email, enabled=False)
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
async def magic_link_redeem_redirect(t: str) -> RedirectResponse:
    """Compat voor links uit oudere mails: stuur zonder bijwerkingen door naar ``mfa.html#ml=…``.

    Reviewronde 3: het sessie-cookie is SameSite=Strict en gaat dus niet mee bij een klik vanuit
    webmail (cross-site navigatie). Daarom verzilvert deze GET niets en kijkt hij niet naar het
    cookie; de pagina ``mfa.html`` doet een same-site ``POST /auth/magic-link/redeem`` waarbij het
    cookie wel meegaat. Het token staat in het fragment (``#``), dus niet in logs of Referer.
    """
    base = get_settings().public_url.rstrip("/")
    return RedirectResponse(url=f"{base}/mfa.html#ml={quote(t, safe='')}", status_code=302)


@router.post("/magic-link/redeem")
async def magic_link_redeem(
    body: MagicLinkRedeem, request: Request, response: Response
) -> dict[str, bool]:
    """Verzilver magic-link als TWEEDE stap: upgrade een bestaande wachtwoordsessie naar mfa=true.

    v0.2.0-Koblitz (reviewronde 2): de link geeft nooit zelf een sessie. Zonder geldig sessie-cookie
    van dezelfde gebruiker (dus na een wachtwoord-login in deze browser) wordt de link geweigerd en
    NIET verbruikt; toegang tot de mailbox alleen is zo geen S (zie THREAT_MODEL, HARDWARE_KEYS §9).
    Reviewronde 3: verzilveren gaat via deze POST vanaf ``mfa.html`` (same-site, dus het
    SameSite=Strict-cookie gaat mee), niet meer via de GET uit de mail.
    """
    settings = get_settings()
    t = body.t
    try:
        payload: dict[str, object] | None = jwt_service.require_auth(request)
    except HTTPException:
        payload = None
    async with connect(settings.db_path) as conn:
        owner = await magic_link_service.peek_magic_link(conn, t)
        if owner is None:
            raise HTTPException(status_code=400, detail={"error": "invalid_link"})
        if payload is None or str(payload.get("sub")) != owner:
            await audit_service.log(
                conn,
                user_id=owner,
                event="mfa_fail",
                ip=request.client.host if request.client else None,
                detail={"flow": "magic_link", "reason": "no_password_session"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "magic_link_login_first"},
            )
        user_id = await magic_link_service.consume_magic_link(conn, t)
        if user_id != owner:
            raise HTTPException(status_code=400, detail={"error": "invalid_link"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event="mfa_pass_magic_link",
            ip=request.client.host if request.client else None,
            detail={"step": "redeemed"},
        )
    jwt_service.reissue_with_mfa(response, payload)
    return {"ok": True}


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
    """Genereer 10 nieuwe codes (returnt plaintext — show-once aan client).

    Alleen vanuit een sessie met MFA (S, v0.2.0-Koblitz reviewronde 2): anders maakt het
    accountwachtwoord alleen via generate + /backup-codes/verify een mfa=true-sessie, en
    zouden bestaande codes zonder tweede factor ongeldig gemaakt kunnen worden.
    """
    payload = stepup_service.session(request)
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
    stepup_key: str | None = None
    totp_step: int | None = None
    async with connect(settings.db_path) as conn:
        if isinstance(body, StepupBio):
            try:
                row = await wa.consume_challenge(conn, body.challenge_id, user_id)
                if row["purpose"] != "stepup":
                    raise wa.WebAuthnError("invalid_challenge")
                key = next(
                    (
                        k
                        for k in await vk_svc.user_bio_keys(conn, user_id)
                        if k["credential_id"] == body.credential_id
                    ),
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
                        conn,
                        user_id=user_id,
                        event="vault_key_clone_suspect",
                        ip=ip,
                        user_agent=ua,
                        detail={"vault_id": key["vault_id"], "key_id": key["id"], "kind": "bio"},
                    )
                    clone = (await vk_svc.user_email(conn, user_id) or "", str(key["label"]))
                    err = HTTPException(status_code=e.status, detail={"error": e.code})
                else:
                    raise HTTPException(status_code=e.status, detail={"error": e.code}) from e
            else:
                err = None
                stepup_key = str(key["id"])
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
            retry_at = await stepup_service.totp_cooldown_until(conn, user_id)
            if retry_at is not None:
                raise HTTPException(
                    status_code=403, detail={"error": "stepup_cooldown", "retry_at": retry_at}
                )
            cur = await conn.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ? AND event = 'stepup_fail' "
                "AND ts > ?",
                (user_id, int(time.time()) - STEPUP_FAIL_WINDOW_SECONDS),
            )
            fails = await cur.fetchone()
            if fails and int(fails["n"]) >= STEPUP_FAIL_MAX:
                raise HTTPException(status_code=429, detail={"error": "too_many_attempts"})
            totp_step = mfa_service.matched_step(secret, body.code)
            if totp_step is None or not await mfa_service.use_step(conn, user_id, totp_step):
                await audit_service.log(
                    conn,
                    user_id=user_id,
                    event="stepup_fail",
                    ip=ip,
                    user_agent=ua,
                    detail={"method": "totp"},
                )
                raise HTTPException(status_code=401, detail={"error": "invalid_code"})
        if err is None:
            until = vk_svc.now() + settings.stepup_ttl_seconds
            await audit_service.log(
                conn,
                user_id=user_id,
                event="stepup",
                ip=ip,
                user_agent=ua,
                detail=(
                    {"method": body.method, "totp_step": totp_step}
                    if body.method == "totp"
                    else {"method": body.method}
                ),
            )
    if err is not None:
        if clone is not None:
            await vk_svc.notify_user(
                clone[0],
                vk_svc.CLONE_SUBJECT,
                vk_svc.notify_body(
                    vk_svc.CLONE_TEXT, label=clone[1], ip=ip, advice=vk_svc.CLONE_ADVICE
                ),
                user_id=user_id,
                event="vault_key_clone_suspect",
                ip=ip,
                user_agent=ua,
            )
        raise err
    token = jwt_service.issue(
        user_id,
        bool(payload.get("admin", False)),
        mfa_passed=True,
        stepup_until=until,
        stepup_method=body.method,
        stepup_key=stepup_key,
        **jwt_service.carry_claims(payload),
    )
    jwt_service.set_cookie(response, token)
    return {"ok": True, "method": body.method, "stepup_until": until}
