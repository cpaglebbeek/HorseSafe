from __future__ import annotations

from fastapi import (
    APIRouter,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)

from ..config import get_settings
from ..db.connection import connect
from ..models.vault import VaultPublic
from ..services import audit_service, jwt_service, storage_service

router = APIRouter()


def _user(request: Request) -> str:
    """Vereis JWT + (indien user TOTP heeft) mfa_passed=true.

    Fase 3: vault-routes weigeren toegang zonder voltooide MFA voor accounts met TOTP.
    """
    payload = jwt_service.require_auth(request)
    if not bool(payload.get("mfa", False)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "mfa_required"},
        )
    return str(payload["sub"])


@router.get("", response_model=list[VaultPublic])
async def list_vaults(request: Request) -> list[VaultPublic]:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        rows = await storage_service.list_vaults(conn, user_id)
        return [VaultPublic(**r) for r in rows]  # type: ignore[arg-type]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=VaultPublic)
async def create_vault(
    request: Request,
    name: str = Form(...),
    blob: UploadFile = File(...),
) -> VaultPublic:
    user_id = _user(request)
    settings = get_settings()
    data = await blob.read()
    if len(data) > settings.vault_max_bytes:
        raise HTTPException(status_code=413, detail={"error": "blob_too_large"})
    async with connect(settings.db_path) as conn:
        try:
            meta = await storage_service.create_vault(conn, user_id, name, data)
        except ValueError as e:
            raise HTTPException(status_code=409, detail={"error": str(e)}) from e
        await audit_service.log(
            conn,
            user_id=user_id,
            event="vault_create",
            ip=request.client.host if request.client else None,
            detail={"vault_id": meta["id"], "size": len(data)},
        )
        return VaultPublic(**meta)  # type: ignore[arg-type]


@router.get("/{vault_id}")
async def read_vault(vault_id: str, request: Request) -> Response:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        result = await storage_service.read_vault_blob(conn, user_id, vault_id)
        if result is None:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        blob, etag = result
        await audit_service.log(
            conn,
            user_id=user_id,
            event="vault_read",
            ip=request.client.host if request.client else None,
            detail={"vault_id": vault_id},
        )
        return Response(
            content=blob,
            media_type="application/octet-stream",
            headers={"ETag": etag, "Cache-Control": "no-store"},
        )


@router.put("/{vault_id}", response_model=VaultPublic)
async def update_vault(
    vault_id: str,
    request: Request,
    if_match: str = Header(..., alias="If-Match"),
    blob: UploadFile = File(...),
) -> VaultPublic:
    user_id = _user(request)
    settings = get_settings()
    data = await blob.read()
    async with connect(settings.db_path) as conn:
        try:
            result = await storage_service.update_vault_blob(
                conn, user_id, vault_id, data, if_match
            )
        except ValueError as e:
            raise HTTPException(status_code=413, detail={"error": str(e)}) from e
        if result is None:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        if result.get("_conflict"):
            await audit_service.log(
                conn,
                user_id=user_id,
                event="vault_etag_conflict",
                ip=request.client.host if request.client else None,
                detail={"vault_id": vault_id},
            )
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail={
                    "error": "etag_mismatch",
                    "current_etag": result["current_etag"],
                },
            )
        await audit_service.log(
            conn,
            user_id=user_id,
            event="vault_update",
            ip=request.client.host if request.client else None,
            detail={"vault_id": vault_id, "size": len(data)},
        )
        # Strip private keys uit response
        clean = {
            k: v
            for k, v in result.items()
            if not k.startswith("_") and k != "blob_path" and k != "user_id"
        }
        return VaultPublic(**clean)  # type: ignore[arg-type]


@router.delete("/{vault_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault(vault_id: str, request: Request) -> Response:
    user_id = _user(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        ok = await storage_service.delete_vault(conn, user_id, vault_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event="vault_delete",
            ip=request.client.host if request.client else None,
            detail={"vault_id": vault_id},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─────────────── Import/Export audit-stamps (v0.0.5-Shamir) ───────────────
# Server doet GEEN parsing — alle import/export is client-side.
# Deze endpoints registreren alleen het event + reden (voor plaintext-export).


_VALID_IMPORT_FORMATS = {"kdbx", "bitwarden", "csv", "xlsx"}
_VALID_EXPORT_FORMATS = {"kdbx", "csv", "json", "xlsx"}


@router.post("/{vault_id}/audit-import")
async def audit_import(vault_id: str, body: dict[str, object], request: Request) -> dict[str, bool]:
    user_id = _user(request)
    settings = get_settings()
    fmt = str(body.get("format", ""))
    count = int(body.get("count", 0) or 0)
    if fmt not in _VALID_IMPORT_FORMATS:
        raise HTTPException(status_code=400, detail={"error": "invalid_format"})
    async with connect(settings.db_path) as conn:
        meta = await storage_service.get_vault_meta(conn, user_id, vault_id)
        if not meta:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event=f"import_{fmt}",  # type: ignore[arg-type]
            ip=request.client.host if request.client else None,
            detail={"vault_id": vault_id, "count": count},
        )
    return {"ok": True}


@router.post("/{vault_id}/audit-export")
async def audit_export(vault_id: str, body: dict[str, str], request: Request) -> dict[str, bool]:
    user_id = _user(request)
    settings = get_settings()
    fmt = body.get("format", "")
    reason = (body.get("reason") or "").strip()
    if fmt not in _VALID_EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail={"error": "invalid_format"})
    # Plaintext-formats vereisen reden (min 10 chars); KDBX is encrypted → reden niet vereist
    if fmt in ("csv", "json", "xlsx") and len(reason) < 10:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "reason_required",
                "message": "Reden van min. 10 tekens vereist voor plaintext-export",
            },
        )
    async with connect(settings.db_path) as conn:
        meta = await storage_service.get_vault_meta(conn, user_id, vault_id)
        if not meta:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        await audit_service.log(
            conn,
            user_id=user_id,
            event=f"export_{fmt}",  # type: ignore[arg-type]
            ip=request.client.host if request.client else None,
            detail={"vault_id": vault_id},
            reason=reason if reason else None,
        )
    return {"ok": True}
