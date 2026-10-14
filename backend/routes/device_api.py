"""Device-API voor de telefoon-app (v0.3.4-Miller deel 2) — docs/HARDWARE_KEYS.md §13.4 en §13.6.

Geen sessiecookie: elk request is getekend met K_dev (headers ``X-HS-Device``, ``X-HS-Ts``,
``X-HS-Nonce``, ``X-HS-Sig``); zie ``device_service.authenticate_device``. Fout → 401
``device_auth_failed`` zonder detail.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..config import get_settings
from ..db.connection import connect
from ..models.device import DeviceKeyRef, DeviceSealed, DeviceStatus
from ..services import device_service as dev

router = APIRouter()


@router.get("/status", response_model=DeviceStatus)
async def device_status(request: Request) -> DeviceStatus:
    """Ook voor een ingetrokken toestel (200, lege lijst), zodat de app lokaal kan wissen."""
    device = await dev.authenticate_device(request, allow_revoked=True)
    state = dev.device_state(device)
    keys: list[DeviceKeyRef] = []
    if state == "active":
        async with connect(get_settings().db_path) as conn:
            keys = [
                DeviceKeyRef(key_id=k["id"], vault_id=k["vault_id"], label=k["label"])
                for k in await dev.device_keys(conn, str(device["id"]))
            ]
    return DeviceStatus(device_id=str(device["id"]), state=state, keys=keys)


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
