"""Device-API voor de telefoon-app (v0.3.4-Miller deel 2) — docs/HARDWARE_KEYS.md §13.4 en §13.6.

Geen sessiecookie: elk request is getekend met K_dev (headers ``X-HS-Device``, ``X-HS-Ts``,
``X-HS-Nonce``, ``X-HS-Sig``); zie ``device_service.authenticate_device``. Fout → 401
``device_auth_failed`` zonder detail.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from ..config import get_settings
from ..db.connection import connect
from ..models.device import DeviceApprovalRef, DeviceKeyRef, DeviceSealed, DeviceStatus
from ..models.trust import ApprovalBrowser, DeviceApproval, DeviceDecided, DeviceDecision
from ..services import audit_service
from ..services import device_service as dev
from ..services import trust_service as trust
from ..services import vault_key_service as svc
from .trusted_browsers import browser_mail

router = APIRouter()


async def _status_snapshot(device_id: str) -> tuple[list[DeviceKeyRef], list[DeviceApprovalRef]]:
    async with connect(get_settings().db_path) as conn:
        t = svc.now()
        await trust.cleanup(conn, t)
        keys = [
            DeviceKeyRef(key_id=k["id"], vault_id=k["vault_id"], label=k["label"])
            for k in await dev.device_keys(conn, device_id)
        ]
        approvals = [
            DeviceApprovalRef(approval_id=a["id"], vault_id=a["vault_id"])
            for a in await trust.pending_for_device(conn, device_id, t)
        ]
    return keys, approvals


@router.get("/status", response_model=DeviceStatus)
async def device_status(
    request: Request, wait: int = Query(default=0, ge=0, le=trust.WAIT_MAX)
) -> DeviceStatus:
    """Ook voor een ingetrokken toestel (200, lege lijst), zodat de app lokaal kan wissen.

    v0.4.0-Montgomery: ``approvals`` = open (``pending``) ontgrendelverzoeken voor kluizen waarvoor
    dit toestel een actieve sleutel heeft. ``?wait=25`` long-pollt tot er een verzoek is."""
    device = await dev.authenticate_device(request, allow_revoked=True)
    state = dev.device_state(device)
    keys: list[DeviceKeyRef] = []
    approvals: list[DeviceApprovalRef] = []
    if state == "active":
        deadline = time.monotonic() + wait
        while True:
            keys, approvals = await _status_snapshot(str(device["id"]))
            if approvals or time.monotonic() >= deadline:
                break
            await asyncio.sleep(min(trust.POLL_INTERVAL, max(0.0, deadline - time.monotonic())))
    return DeviceStatus(device_id=str(device["id"]), state=state, keys=keys, approvals=approvals)


async def _visible_approval(
    device: dict[str, Any], approval_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verzoek dat dit toestel mag zien: ``pending``, niet verlopen, van dezelfde gebruiker, en het
    toestel heeft een actieve sleutel voor die kluis. Anders 404 (geen onderscheid)."""
    if dev.device_state(device) != "active":
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    async with connect(get_settings().db_path) as conn:
        a = await trust.get_approval(conn, approval_id)
        key = (
            await trust.device_key_for_vault(conn, str(device["id"]), str(a["vault_id"]))
            if a is not None
            else None
        )
    if a is None or key is None or a["user_id"] != device["user_id"]:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return a, key


@router.get("/approvals/{approval_id}", response_model=DeviceApproval)
async def device_get_approval(approval_id: str, request: Request) -> DeviceApproval:
    device = await dev.authenticate_device(request)
    a, key = await _visible_approval(device, approval_id)
    if a["status"] != "pending" or int(a["expires_at"]) < svc.now():
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    async with connect(get_settings().db_path) as conn:
        b = await trust.get_browser(conn, str(a["browser_id"]))
        name = await trust.vault_name(conn, str(a["vault_id"]))
    if b is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return DeviceApproval(
        approval_id=str(a["id"]),
        vault_id=str(a["vault_id"]),
        vault_name=name,
        key_id=str(key["id"]),
        browser=ApprovalBrowser(
            browser_id=str(b["id"]),
            pub_B=str(b["pub_b"]),
            label=str(b["label"]),
            proof=str(b["proof"]),
        ),
        epk_L=str(a["epk_l"]),
        nonce_L=str(a["nonce_l"]),
        created_at=int(a["created_at"]),
        sig_req=str(a["sig_req"]),
        ip=a["ip"],
        ua=trust.clean_ua(a["ua"]),
        requested_at=int(a["expires_at"]) - trust.PENDING_TTL,
        expires_at=int(a["expires_at"]),
    )


@router.post("/approvals/{approval_id}", response_model=DeviceDecided)
async def device_decide(approval_id: str, body: DeviceDecision, request: Request) -> DeviceDecided:
    """§14.5 stap 5: ``approve`` met ``resp`` (Seal_v2 relay, alleen vormcontrole) of
    ``deny``/``deny_revoke``. Niet meer pending of verlopen → 409 ``approval_not_pending``."""
    device = await dev.authenticate_device(request)
    a, _key = await _visible_approval(device, approval_id)
    if body.decision == "approve":
        if body.resp is None or not svc.validate_sealed(body.resp, approval_id):
            raise HTTPException(status_code=400, detail={"error": "invalid_sealed"})
    elif body.resp is not None:
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})
    device_id = str(device["id"])
    user_id = str(a["user_id"])
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    async with connect(get_settings().db_path) as conn:
        t = svc.now()
        ok = await trust.decide(
            conn,
            a,
            device_id=device_id,
            decision=body.decision,
            resp=body.resp,
            reason=body.reason,
            t=t,
        )
        if not ok:
            raise HTTPException(status_code=409, detail={"error": "approval_not_pending"})
        base = {"approval_id": approval_id, "vault_id": a["vault_id"], "device_id": device_id}
        if body.decision == "approve":
            await audit_service.log(
                conn,
                user_id=user_id,
                event="approval_approve",
                ip=ip,
                user_agent=ua,
                detail={**base, "browser_id": a["browser_id"]},
            )
            return DeviceDecided(approval_id=approval_id, status="approved")
        reason = body.reason or "user"
        await audit_service.log(
            conn,
            user_id=user_id,
            event="approval_deny",
            ip=ip,
            user_agent=ua,
            detail={
                **base,
                "browser_id": a["browser_id"],
                "decision": body.decision,
                "reason": reason,
            },
        )
        if body.decision == "deny_revoke":
            await audit_service.log(
                conn,
                user_id=user_id,
                event="browser_revoke",
                ip=ip,
                user_agent=ua,
                detail={
                    "browser_id": a["browser_id"],
                    "vault_id": a["vault_id"],
                    "reason": "phone_deny",
                },
            )
        b = await trust.get_browser(conn, str(a["browser_id"]))
        email = await svc.user_email(conn, user_id)
    label = str(b["label"]) if b else "onbekend"
    text = (
        f"Een verzoek om je kluis te ontgrendelen vanaf de browser '{label}' is op je telefoon "
        "geweigerd. Die browsersessie is uitgelogd."
    )
    if body.decision == "deny_revoke":
        text += " De browser is bovendien niet langer vertrouwd."
    if body.reason and body.reason != "user":
        text += f" Reden: {body.reason}."
    await browser_mail(
        user_id=user_id,
        email=email,
        event="approval_deny",
        subject="HorseSafe: verzoek geweigerd",
        text=text + f" Browser: {trust.clean_ua(a['ua'], trust.UA_MAIL_MAX) or 'onbekend'}.",
        ip=a["ip"],  # het IP van de browser die het verzoek deed, niet van de telefoon
        user_agent=ua,
    )
    return DeviceDecided(approval_id=approval_id, status="denied")


@router.get("/keys/{key_id}/sealed", response_model=DeviceSealed)
async def device_key_sealed(key_id: str, request: Request) -> DeviceSealed:
    """Alleen een actieve sleutel van dit (bevestigde) toestel; anders 404."""
    device = await dev.authenticate_device(request)
    row = None
    if dev.device_state(device) == "active":
        async with connect(get_settings().db_path) as conn:
            row = await dev.device_key_sealed(conn, str(device["id"]), key_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return DeviceSealed(key_id=row["id"], vault_id=row["vault_id"], sealed=row["sealed"])
