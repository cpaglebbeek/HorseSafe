"""Vertrouwde browsers (v0.4.0-Montgomery) — docs/HARDWARE_KEYS.md §14.3, §14.4 en §14.6.

``/trusted-browsers``: vertrouwen (SU), lijst en intrekken (S).
``/auth/browser/*``: inloggen op een vertrouwde browser met e-mail + handtekening van K_B + TOTP,
zonder accountwachtwoord. Elke fout bij inloggen → 401 ``browser_login_failed`` zonder detail;
de reden staat alleen in de audit.

Mail gaat altijd NA het sluiten van de DB-verbinding (niet-blokkerend, zoals bij vault_keys).
"""

from __future__ import annotations

import uuid
from typing import Any

import aiosqlite
from fastapi import APIRouter, HTTPException, Request, Response, status

from ..config import get_settings
from ..db.connection import connect
from ..models.audit import AuditEvent
from ..models.trust import (
    BrowserChallenge,
    BrowserChallengeRequest,
    BrowserLoginRequest,
    TrustedBrowserCreate,
    TrustedBrowserCreated,
    TrustedBrowserList,
    TrustedBrowserPublic,
)
from ..services import (
    audit_service,
    auth_service,
    jwt_service,
    mfa_service,
    stepup_service,
    storage_service,
)
from ..services import trust_service as trust
from ..services import vault_key_service as svc

router = APIRouter()
auth_router = APIRouter()

ADVICE_BROWSER = (
    "Log direct in met je wachtwoord, controleer je vertrouwde browsers en trek in wat je niet "
    "herkent."
)


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _ua(request: Request) -> str | None:
    return request.headers.get("user-agent")


async def _audit(
    conn: aiosqlite.Connection,
    request: Request,
    user_id: str | None,
    event: AuditEvent,
    detail: dict[str, Any],
) -> None:
    # Nooit challenge, proof, handtekeningen, epk_L, nonce of resp in de audit (§14.8).
    await audit_service.log(
        conn, user_id=user_id, event=event, ip=_ip(request), user_agent=_ua(request), detail=detail
    )


async def browser_mail(
    *,
    user_id: str,
    email: str | None,
    event: str,
    subject: str,
    text: str,
    ip: str | None,
    user_agent: str | None,
) -> None:
    body = svc.notify_body(text, label=None, ip=ip, advice=ADVICE_BROWSER)
    await svc.notify_user(
        email, subject, body, user_id=user_id, event=event, ip=ip, user_agent=user_agent
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "not_found"})


# ─────────────── Vertrouwen (SU) ───────────────


@router.post("", status_code=status.HTTP_201_CREATED, response_model=TrustedBrowserCreated)
async def trust_browser(body: TrustedBrowserCreate, request: Request) -> TrustedBrowserCreated:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        if not await storage_service.get_vault_meta(conn, user_id, body.vault_id):
            raise _not_found()
        stepup_service.check_stepup(payload)
        # Zonder TOTP kan de browser nooit inloggen (§14.4); de UI blokkeert dit al (§14.3.1).
        if not await mfa_service.user_has_totp(conn, user_id):
            raise HTTPException(status_code=409, detail={"error": "totp_required"})
        if not trust.valid_p256_spki(body.pub_B):
            raise HTTPException(status_code=400, detail={"error": "invalid_public_key"})
        t = svc.now()
        err = await trust.create_browser(
            conn,
            user_id=user_id,
            browser_id=body.browser_id,
            vault_id=body.vault_id,
            pub_b=body.pub_B,
            label=body.label,
            proof_b64u=body.proof,
            t=t,
        )
        if err is not None:
            raise HTTPException(status_code=409, detail={"error": err})
        await _audit(
            conn,
            request,
            user_id,
            "browser_trust",
            {"browser_id": body.browser_id, "vault_id": body.vault_id},
        )
        email = await svc.user_email(conn, user_id)
    await browser_mail(
        user_id=user_id,
        email=email,
        event="browser_trust",
        subject="HorseSafe: browser vertrouwd",
        text=(
            f"De browser '{body.label}' is als vertrouwde browser aan je kluis gekoppeld. Daarop "
            "kun je voortaan inloggen met je authenticator-app en ontgrendelen met je telefoon."
        ),
        ip=_ip(request),
        user_agent=_ua(request),
    )
    return TrustedBrowserCreated(browser_id=body.browser_id, created_at=t)


@router.get("", response_model=TrustedBrowserList)
async def list_browsers(request: Request) -> TrustedBrowserList:
    payload = stepup_service.session(request)
    async with connect(get_settings().db_path) as conn:
        rows = await trust.list_browsers(conn, str(payload["sub"]))
    return TrustedBrowserList(
        browsers=[
            TrustedBrowserPublic(
                browser_id=r["id"],
                vault_id=r["vault_id"],
                label=r["label"],
                created_at=r["created_at"],
                last_used_at=r["last_used_at"],
            )
            for r in rows
        ]
    )


@router.delete("/{browser_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_browser(browser_id: str, request: Request) -> Response:
    """Defensief, geen step-up (zoals een toestel verwijderen)."""
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        b = await trust.own_active_browser(conn, user_id, browser_id)
        if b is None or not await trust.revoke_browser(
            conn, user_id, browser_id, svc.now(), "user"
        ):
            raise _not_found()
        await _audit(
            conn,
            request,
            user_id,
            "browser_revoke",
            {"browser_id": browser_id, "vault_id": b["vault_id"], "reason": "user"},
        )
        email = await svc.user_email(conn, user_id)
    await browser_mail(
        user_id=user_id,
        email=email,
        event="browser_revoke",
        subject="HorseSafe: browser ingetrokken",
        text=f"De vertrouwde browser '{b['label']}' is ingetrokken.",
        ip=_ip(request),
        user_agent=_ua(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─────────────── Inloggen op een vertrouwde browser (publiek) ───────────────


@auth_router.post("/challenge", response_model=BrowserChallenge)
async def browser_challenge(body: BrowserChallengeRequest) -> BrowserChallenge:
    """Altijd 200, ook bij een onbekend e-mailadres (geen enumeratie). 10 per 10 min per e-mail
    (per IP: RateLimitMiddleware)."""
    email_lc = body.email.strip().lower()
    async with connect(get_settings().db_path) as conn:
        t = svc.now()
        await trust.cleanup(conn, t)
        if await trust.challenges_in_window(conn, email_lc, t) >= trust.CHALLENGES_PER_WINDOW:
            raise HTTPException(status_code=429, detail={"error": "rate_limited"})
        ch = await trust.create_challenge(conn, email_lc, t)
    return BrowserChallenge(**ch)


class _LoginFail(Exception):
    def __init__(
        self, reason: str, user_id: str | None = None, email_lc: str | None = None
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.user_id = user_id
        self.email_lc = email_lc


async def _check_login(
    conn: aiosqlite.Connection, body: BrowserLoginRequest, ip: str
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """§14.4 stap 3, in volgorde; eerste fout wint. Geeft (gebruiker, browser, totp-stap)."""
    t = svc.now()
    ch = await trust.consume_challenge(conn, body.challenge_id)  # meteen verbruikt
    if ch is None:
        raise _LoginFail("challenge_invalid")
    email_lc = str(ch["email_lc"])
    if int(ch["expires_at"]) < t:
        raise _LoginFail("challenge_expired", None, email_lc)
    user = await trust.user_by_email(conn, email_lc)
    if user is None:
        raise _LoginFail("unknown_email", None, email_lc)
    user_id = str(user["id"])
    if await auth_service.is_throttled(conn, ip, email_lc):
        raise _LoginFail("throttled", user_id, email_lc)
    b = await trust.get_browser(conn, body.browser_id)
    if b is None or b["user_id"] != user_id:
        raise _LoginFail("browser_unknown", user_id, email_lc)
    if b["revoked_at"] is not None:
        raise _LoginFail("browser_revoked", user_id, email_lc)
    msg = trust.login_t(
        str(ch["id"]), trust.b64u_decode(str(ch["challenge"])), body.browser_id, email_lc
    )
    if not trust.verify_p1363_b64u(str(b["pub_b"]), body.sig, msg):
        raise _LoginFail("signature_invalid", user_id, email_lc)
    secret = await mfa_service.get_user_totp(conn, user_id)
    if not secret:
        raise _LoginFail("totp_missing", user_id, email_lc)
    step = mfa_service.matched_step(secret, body.totp)
    if step is None:
        raise _LoginFail("totp_invalid", user_id, email_lc)
    last = await mfa_service.last_totp_step(conn, user_id)
    if last is not None and step <= last:
        raise _LoginFail("totp_replay", user_id, email_lc)
    return user, b, step


@auth_router.post("/login")
async def browser_login(
    body: BrowserLoginRequest, request: Request, response: Response
) -> dict[str, object]:
    ip = _ip(request) or "unknown"
    async with connect(get_settings().db_path) as conn:
        try:
            user, b, step = await _check_login(conn, body, ip)
        except _LoginFail as e:
            if e.reason != "throttled":  # telt mee voor de bestaande login-throttle
                await auth_service.record_failed_login(conn, ip, e.email_lc)
            await _audit(
                conn,
                request,
                e.user_id,
                "browser_login_failed",
                {"reason": e.reason, "browser_id": body.browser_id[:64]},
            )
            raise HTTPException(status_code=401, detail={"error": "browser_login_failed"}) from None
        user_id = str(user["id"])
        sid = str(uuid.uuid4())
        await trust.mark_browser_used(conn, str(b["id"]), svc.now())
        await _audit(
            conn,
            request,
            user_id,
            "browser_login",
            # sid (geen geheim: zonder het JWT zelf waardeloos) zodat intrekken van de browser
            # ook deze sessie kan intrekken.
            {
                "browser_id": str(b["id"]),
                "vault_id": b["vault_id"],
                "totp_step": step,
                "sid": sid,
            },
        )
    token = jwt_service.issue(
        user_id,
        bool(user["is_admin"]),
        mfa_passed=True,
        sid=sid,
        amr=["browser", "totp"],
        browser_id=str(b["id"]),
    )
    jwt_service.set_cookie(response, token)
    return {
        "ok": True,
        "is_admin": bool(user["is_admin"]),
        "browser_id": str(b["id"]),
        "vault_id": str(b["vault_id"]),
    }
