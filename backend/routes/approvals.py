"""Ontgrendelen met de telefoon — browserkant (v0.4.0-Montgomery), HARDWARE_KEYS.md §14.5-§14.6.

``POST`` maakt een ``draft`` (30 s) met ``approval_id`` en ``created_at``; de browser tekent daarna
``req_t`` (waar die in staan) en zet het verzoek met ``PUT`` op ``pending`` (120 s). Alleen
``pending`` is zichtbaar voor de telefoon. ``GET ?wait=25`` long-pollt; een goedgekeurd antwoord
gaat precies één keer mee en wordt dan gewist (``consumed``; daarna 410 ``gone``).

Alle routes: S + ``sid`` in het JWT; PUT/GET/DELETE alleen vanuit dezelfde ``sid`` als het verzoek
(anders 404). Een sessie zonder ``sid`` (cookie van vóór 0.4.0) → 409 ``session_too_old``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from ..config import get_settings
from ..db.connection import connect
from ..models.trust import ApprovalCreate, ApprovalCreated, ApprovalSubmit, ApprovalSubmitted
from ..services import audit_service, stepup_service, storage_service
from ..services import trust_service as trust
from ..services import vault_key_service as svc

router = APIRouter()


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "not_found"})


def _session(request: Request) -> tuple[dict[str, Any], str, str]:
    payload = stepup_service.session(request)
    sid = payload.get("sid")
    if not isinstance(sid, str) or not sid:
        raise HTTPException(status_code=409, detail={"error": "session_too_old"})
    return payload, str(payload["sub"]), sid


async def _own_approval(
    conn: Any, user_id: str, sid: str, vault_id: str, approval_id: str
) -> dict[str, Any]:
    a = await trust.get_approval(conn, approval_id)
    if a is None or a["user_id"] != user_id or a["vault_id"] != vault_id or a["sid"] != sid:
        raise _not_found()
    return a


@router.post(
    "/{vault_id}/approvals", status_code=status.HTTP_201_CREATED, response_model=ApprovalCreated
)
async def create_approval(vault_id: str, body: ApprovalCreate, request: Request) -> ApprovalCreated:
    payload, user_id, sid = _session(request)
    async with connect(get_settings().db_path) as conn:
        if not await storage_service.get_vault_meta(conn, user_id, vault_id):
            raise _not_found()
        t = svc.now()
        await trust.cleanup(conn, t, user_id=user_id)
        claim_bid = payload.get("browser_id")
        b = await trust.own_active_browser(conn, user_id, body.browser_id)
        if (
            b is None
            or b["vault_id"] != vault_id
            or (isinstance(claim_bid, str) and claim_bid != body.browser_id)
        ):
            raise _not_found()
        if b["cooldown_until"] is not None and int(b["cooldown_until"]) > t:
            raise HTTPException(
                status_code=409,
                detail={"error": "browser_cooldown", "retry_at": int(b["cooldown_until"])},
            )
        if not await trust.vault_has_phone_key(conn, user_id, vault_id):
            raise HTTPException(status_code=409, detail={"error": "no_phone_key"})
        approval_id, err = await trust.create_approval(
            conn,
            user_id=user_id,
            vault_id=vault_id,
            browser_id=body.browser_id,
            sid=sid,
            ip=_ip(request),
            ua=request.headers.get("user-agent"),
            t=t,
        )
        if err is not None:
            code = 429 if err == "too_many_approvals" else 409
            raise HTTPException(status_code=code, detail={"error": err})
        assert approval_id is not None
        await audit_service.log(
            conn,
            user_id=user_id,
            event="approval_request",
            ip=_ip(request),
            user_agent=request.headers.get("user-agent"),
            detail={
                "approval_id": approval_id,
                "vault_id": vault_id,
                "browser_id": body.browser_id,
            },
        )
    return ApprovalCreated(approval_id=approval_id, created_at=t)


@router.put("/{vault_id}/approvals/{approval_id}", response_model=ApprovalSubmitted)
async def submit_approval(
    vault_id: str, approval_id: str, body: ApprovalSubmit, request: Request
) -> ApprovalSubmitted:
    _payload, user_id, sid = _session(request)
    async with connect(get_settings().db_path) as conn:
        a = await _own_approval(conn, user_id, sid, vault_id, approval_id)
        t = svc.now()
        if a["status"] != "draft" or int(a["expires_at"]) < t:
            raise HTTPException(status_code=409, detail={"error": "approval_not_draft"})
        b = await trust.own_active_browser(conn, user_id, a["browser_id"])
        if b is None:
            raise HTTPException(status_code=409, detail={"error": "approval_not_draft"})
        msg = trust.req_t(
            approval_id,
            vault_id,
            a["browser_id"],
            body.epk_L,
            trust.b64u_decode(body.nonce_L),
            int(a["created_at"]),
        )
        if not trust.verify_p1363_b64u(str(b["pub_b"]), body.sig_req, msg):
            raise HTTPException(status_code=400, detail={"error": "signature_invalid"})
        expires_at = await trust.submit_approval(
            conn,
            approval_id,
            epk_l=body.epk_L,
            nonce_l=body.nonce_L,
            sig_req=body.sig_req,
            t=t,
        )
        if expires_at is None:
            raise HTTPException(status_code=409, detail={"error": "approval_not_draft"})
    return ApprovalSubmitted(expires_at=expires_at)


async def _poll_once(
    request: Request, user_id: str, sid: str, vault_id: str, approval_id: str
) -> tuple[bool, dict[str, Any]]:
    """Eén blik op het verzoek: ``(klaar, antwoord)``; niet klaar = nog draft/pending."""
    async with connect(get_settings().db_path) as conn:
        t = svc.now()
        await trust.cleanup(conn, t, user_id=user_id)
        a = await _own_approval(conn, user_id, sid, vault_id, approval_id)
        st = str(a["status"])
        if st == "approved":
            resp = await trust.take_response(conn, approval_id, t)
            if resp is None:  # gelijktijdig opgehaald of net verlopen
                a = await _own_approval(conn, user_id, sid, vault_id, approval_id)
                st = str(a["status"])
            else:
                await audit_service.log(
                    conn,
                    user_id=user_id,
                    event="approval_consumed",
                    ip=_ip(request),
                    user_agent=request.headers.get("user-agent"),
                    detail={"approval_id": approval_id, "vault_id": vault_id},
                )
                return True, {"status": "approved", "resp": resp}
        if st == "consumed":
            raise HTTPException(status_code=410, detail={"error": "gone"})
        # draft | pending → nog open; denied | expired | cancelled → klaar
        return st not in ("draft", "pending"), {"status": st}


@router.get("/{vault_id}/approvals/{approval_id}")
async def get_approval(
    vault_id: str,
    approval_id: str,
    request: Request,
    wait: int = Query(default=0, ge=0, le=trust.WAIT_MAX),
) -> dict[str, Any]:
    """``{status}`` of eenmalig ``{status:"approved", resp}``; daarna 410 ``gone``."""
    _payload, user_id, sid = _session(request)
    deadline = time.monotonic() + wait
    while True:
        done, out = await _poll_once(request, user_id, sid, vault_id, approval_id)
        if done or time.monotonic() >= deadline:
            return out
        await asyncio.sleep(min(trust.POLL_INTERVAL, max(0.0, deadline - time.monotonic())))


@router.delete("/{vault_id}/approvals/{approval_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_approval(vault_id: str, approval_id: str, request: Request) -> Response:
    _payload, user_id, sid = _session(request)
    async with connect(get_settings().db_path) as conn:
        await _own_approval(conn, user_id, sid, vault_id, approval_id)
        await trust.cancel_approval(conn, approval_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
