from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from ..config import get_settings
from ..db.connection import connect
from ..models.share import (
    KeypairRewrap,
    KeypairSet,
    PubkeyResponse,
    ShareCreate,
    ShareInboxItem,
)
from ..services import audit_service, jwt_service, share_service

router = APIRouter()


def _user(request: Request) -> str:
    """JWT + MFA-pass vereist (zelfde regime als vault-routes)."""
    payload = jwt_service.require_auth(request)
    if not bool(payload.get("mfa", False)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "mfa_required"},
        )
    return str(payload["sub"])


# ─────────────── Keypair management ───────────────


@router.post("/keypair")
async def set_keypair(body: KeypairSet, request: Request) -> dict[str, bool]:
    """Eerste-keer keypair-set (of replace). Vereist JWT+MFA."""
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        await share_service.set_keypair(conn, user_id, body.pubkey, body.encrypted_privkey)
        await audit_service.log(
            conn,
            user_id=user_id,
            event="keypair_generated",
            ip=request.client.host if request.client else None,
        )
    return {"ok": True}


@router.post("/keypair/rewrap")
async def rewrap_keypair(body: KeypairRewrap, request: Request) -> dict[str, bool]:
    """Bij pw-change: vervang encrypted_privkey (pubkey blijft hetzelfde)."""
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        await share_service.rewrap_privkey(conn, user_id, body.encrypted_privkey)
    return {"ok": True}


@router.get("/keypair")
async def get_keypair(request: Request) -> dict[str, str | None]:
    """Geef eigen keypair terug (encrypted_privkey + pubkey) voor browser-decryptie."""
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        pubkey, encrypted_privkey = await share_service.get_keypair(conn, user_id)
    return {"pubkey": pubkey, "encrypted_privkey": encrypted_privkey}


# ─────────────── Pubkey-lookup ───────────────


@router.get("/users/by-email/{email}/pubkey", response_model=PubkeyResponse)
async def lookup_pubkey(email: str, request: Request) -> PubkeyResponse:
    """Zoek pubkey van een andere user op e-mail (voor share-encryptie)."""
    _user(request)  # vereist auth
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        result = await share_service.lookup_pubkey_by_email(conn, email)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "user_or_keypair_not_found"},
            )
        target_user_id, pubkey = result
    return PubkeyResponse(user_id=target_user_id, email=email, pubkey=pubkey)


# ─────────────── Shares ───────────────


@router.post("/shares", status_code=status.HTTP_201_CREATED)
async def create_share(body: ShareCreate, request: Request) -> dict[str, str]:
    """Stuur encrypted-share-payload naar ontvanger."""
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        lookup = await share_service.lookup_pubkey_by_email(conn, body.to_email)
        if lookup is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "recipient_not_found_or_no_keypair"},
            )
        to_user_id, _ = lookup
        if to_user_id == user_id:
            raise HTTPException(status_code=400, detail={"error": "cannot_share_to_self"})
        share_id = await share_service.create_share(
            conn,
            from_user_id=user_id,
            to_user_id=to_user_id,
            encrypted_payload=body.encrypted_payload,
            title_hint=body.title_hint,
        )
        await audit_service.log(
            conn,
            user_id=user_id,
            event="share_create",
            ip=request.client.host if request.client else None,
            detail={"share_id": share_id, "to_user": to_user_id},
        )
    return {"id": share_id}


@router.get("/shares/inbox", response_model=list[ShareInboxItem])
async def inbox(request: Request) -> list[ShareInboxItem]:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        rows = await share_service.list_inbox(conn, user_id)
        return [ShareInboxItem(**r) for r in rows]  # type: ignore[arg-type]


@router.get("/shares/sent")
async def sent(request: Request) -> list[dict[str, object]]:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        return await share_service.list_sent(conn, user_id)


@router.post("/shares/{share_id}/accept")
async def accept_share(share_id: str, request: Request) -> dict[str, bool]:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        ok = await share_service.accept_share(conn, share_id, user_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "share_not_found"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event="share_accept",
            ip=request.client.host if request.client else None,
            detail={"share_id": share_id},
        )
    return {"ok": True}


@router.post("/shares/{share_id}/decline")
async def decline_share(share_id: str, request: Request) -> dict[str, bool]:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        ok = await share_service.decline_share(conn, share_id, user_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "share_not_found"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event="share_decline",
            ip=request.client.host if request.client else None,
            detail={"share_id": share_id},
        )
    return {"ok": True}
