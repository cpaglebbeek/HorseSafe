from __future__ import annotations

import csv
import io
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import Response

from ..config import get_settings
from ..db.connection import connect
from ..models.admin import AdminDeleteRequest, AdminRescueRequest
from ..services import admin_service, audit_service, jwt_service, magic_link_service, mfa_service

router = APIRouter()


def _require_admin(request: Request) -> dict[str, Any]:
    payload = jwt_service.require_auth(request)
    if not bool(payload.get("admin", False)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "admin_required"},
        )
    if not bool(payload.get("mfa", False)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "mfa_required"},
        )
    return payload


@router.get("/users")
async def list_users(request: Request) -> list[dict[str, object]]:
    _require_admin(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        return await admin_service.list_users(conn)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, body: AdminDeleteRequest, request: Request) -> None:
    payload = _require_admin(request)
    if str(payload["sub"]) == user_id:
        raise HTTPException(status_code=400, detail={"error": "self_delete_forbidden"})
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        ok = await admin_service.delete_user_cascade(conn, user_id, settings.vaults_dir)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "user_not_found"})
        await audit_service.log(
            conn,
            user_id=str(payload["sub"]),
            event="admin_user_delete",
            ip=request.client.host if request.client else None,
            detail={"target_user": user_id},
            reason=body.reason,
        )


@router.post("/users/{user_id}/disable-mfa")
async def disable_user_mfa(
    user_id: str, body: AdminRescueRequest, request: Request
) -> dict[str, bool]:
    payload = _require_admin(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not await cursor.fetchone():
            raise HTTPException(status_code=404, detail={"error": "user_not_found"})
        await mfa_service.remove_user_totp(conn, user_id)
        await conn.execute("DELETE FROM users_backup_codes WHERE user_id = ?", (user_id,))
        await conn.commit()
        await audit_service.log(
            conn,
            user_id=str(payload["sub"]),
            event="admin_user_disable_mfa",
            ip=request.client.host if request.client else None,
            detail={"target_user": user_id},
            reason=body.reason,
        )
    return {"ok": True}


@router.post("/users/{user_id}/send-magic-link")
async def admin_send_magic_link(
    user_id: str, body: AdminRescueRequest, request: Request
) -> dict[str, bool]:
    payload = _require_admin(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail={"error": "user_not_found"})
        target_email = str(row["email"])
        await magic_link_service.issue_magic_link(conn, user_id, target_email)
        await audit_service.log(
            conn,
            user_id=str(payload["sub"]),
            event="admin_user_send_magic_link",
            ip=request.client.host if request.client else None,
            detail={"target_user": user_id, "target_email": target_email},
            reason=body.reason,
        )
    return {"ok": True}


@router.get("/stats")
async def stats(request: Request) -> dict[str, object]:
    payload = _require_admin(request)
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        result = await admin_service.get_stats(conn)
        await audit_service.log(
            conn,
            user_id=str(payload["sub"]),
            event="admin_stats_view",
            ip=request.client.host if request.client else None,
        )
        return result


@router.get("/audit")
async def audit(
    request: Request,
    user: str | None = None,
    event: str | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, object]]:
    payload = _require_admin(request)
    settings = get_settings()
    if limit > 500:
        limit = 500
    async with connect(settings.db_path) as conn:
        rows = await admin_service.query_audit(
            conn,
            user_id=user,
            event=event,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=limit,
            offset=offset,
        )
        await audit_service.log(
            conn,
            user_id=str(payload["sub"]),
            event="admin_audit_view",
            ip=request.client.host if request.client else None,
            detail={"filters": {"user": user, "event": event, "limit": limit, "offset": offset}},
        )
        return rows


@router.get("/audit/export")
async def audit_export_csv(
    request: Request,
    user: str | None = None,
    event: str | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
    limit: int = 10000,
) -> Response:
    """Stream audit-log als CSV. Max 10k rijen per export."""
    payload = _require_admin(request)
    settings = get_settings()
    if limit > 10000:
        limit = 10000
    async with connect(settings.db_path) as conn:
        rows = await admin_service.query_audit(
            conn,
            user_id=user,
            event=event,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=limit,
            offset=0,
        )
        await audit_service.log(
            conn,
            user_id=str(payload["sub"]),
            event="admin_audit_csv_export",
            ip=request.client.host if request.client else None,
            detail={"filters": {"user": user, "event": event, "limit": limit}, "count": len(rows)},
        )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["id", "ts", "iso_ts", "user_id", "ip", "user_agent", "event", "detail", "reason"]
    )
    for row in rows:
        ts = int(row.get("ts") or 0)
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else ""
        writer.writerow(
            [
                row.get("id"),
                ts,
                iso,
                row.get("user_id") or "",
                row.get("ip") or "",
                row.get("user_agent") or "",
                row.get("event") or "",
                row.get("detail") or "",
                row.get("reason") or "",
            ]
        )
    filename = f"audit-{time.strftime('%Y-%m-%d', time.gmtime())}.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
