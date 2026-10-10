"""Hardware-sleutels per vault (v0.2.0-Koblitz) — zie docs/HARDWARE_KEYS.md.

Zero-knowledge: de server ontvangt en bewaart alleen verzegelde kopieën die hij niet kan openen.
Een 'bio'-sleutel (YubiKey Bio, vingerafdruk) krijgt zijn kopie direct; een 'recovery'-sleutel
(reserve-YubiKey uit de kluis, alleen PIN) pas na een wachttijd, met melding aan de eigenaar.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status

from ..config import get_settings
from ..db.connection import connect
from ..models.vault_key import VaultKeyCreate, VaultKeyPublic, VaultKeyResealBatch, VaultKeySealed
from ..services import audit_service, storage_service
from ..services import vault_key_service as svc
from .vault import _user

router = APIRouter()


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _fmt(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d-%m-%Y %H:%M UTC")


async def _own_vault(conn, user_id: str, vault_id: str) -> None:  # type: ignore[no-untyped-def]
    if not await storage_service.get_vault_meta(conn, user_id, vault_id):
        raise HTTPException(status_code=404, detail={"error": "not_found"})


async def _own_key(conn, user_id: str, vault_id: str, key_id: str) -> dict:  # type: ignore[no-untyped-def]
    key = await svc.get_key(conn, user_id, vault_id, key_id)
    if not key:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return key


@router.get("/{vault_id}/keys", response_model=list[VaultKeyPublic])
async def list_keys(vault_id: str, request: Request) -> list[VaultKeyPublic]:
    user_id = _user(request)
    async with connect(get_settings().db_path) as conn:
        await _own_vault(conn, user_id, vault_id)
        return [VaultKeyPublic(**k) for k in await svc.list_keys(conn, user_id, vault_id)]


@router.post("/{vault_id}/keys", status_code=status.HTTP_201_CREATED, response_model=VaultKeyPublic)
async def add_key(vault_id: str, body: VaultKeyCreate, request: Request) -> VaultKeyPublic:
    user_id = _user(request)
    if not svc.validate_sealed(body.sealed):
        raise HTTPException(status_code=400, detail={"error": "invalid_sealed"})
    async with connect(get_settings().db_path) as conn:
        await _own_vault(conn, user_id, vault_id)
        try:
            key = await svc.add_key(conn, user_id, vault_id, body.model_dump())
        except ValueError as e:
            raise HTTPException(status_code=409, detail={"error": str(e)}) from e
        await audit_service.log(
            conn, user_id=user_id, event="vault_key_add", ip=_ip(request),
            detail={"vault_id": vault_id, "key_id": key["id"], "kind": body.kind},
        )
        await svc.notify_user(
            conn, user_id, "HorseSafe: nieuwe sleutel gekoppeld",
            f"Aan je kluis is een {'noodsleutel' if body.kind == 'recovery' else 'sleutel'} "
            f"'{body.label}' gekoppeld. Was jij dit niet? Verwijder hem direct via Sleutels.",
        )
        return VaultKeyPublic(**key)


@router.put("/{vault_id}/keys/sealed")
async def reseal_keys(vault_id: str, body: VaultKeyResealBatch, request: Request) -> dict[str, int]:
    user_id = _user(request)
    if not all(svc.validate_sealed(it.sealed) for it in body.items):
        raise HTTPException(status_code=400, detail={"error": "invalid_sealed"})
    async with connect(get_settings().db_path) as conn:
        await _own_vault(conn, user_id, vault_id)
        n = await svc.reseal(conn, user_id, vault_id, [it.model_dump() for it in body.items])
        await audit_service.log(
            conn, user_id=user_id, event="vault_key_reseal", ip=_ip(request),
            detail={"vault_id": vault_id, "count": n},
        )
    return {"updated": n}


@router.delete("/{vault_id}/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_key(vault_id: str, key_id: str, request: Request) -> Response:
    user_id = _user(request)
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        await svc.delete_key(conn, user_id, vault_id, key_id)
        await audit_service.log(
            conn, user_id=user_id, event="vault_key_delete", ip=_ip(request),
            detail={"vault_id": vault_id, "key_id": key_id, "kind": key["kind"]},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{vault_id}/keys/{key_id}/sealed", response_model=VaultKeySealed)
async def get_sealed(vault_id: str, key_id: str, request: Request) -> VaultKeySealed:
    """Lever de verzegelde kopie. Noodsleutel: alleen binnen het vrijgavevenster."""
    user_id = _user(request)
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        if key["kind"] == "recovery":
            state = svc.recovery_state(key)
            if state != "released":
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail={"error": "recovery_" + state, "release_at": key["release_at"]},
                )
            await audit_service.log(
                conn, user_id=user_id, event="recovery_key_used", ip=_ip(request),
                detail={"vault_id": vault_id, "key_id": key_id},
            )
            await svc.notify_user(
                conn, user_id, "HorseSafe: noodsleutel gebruikt",
                f"De noodsleutel '{key['label']}' is zojuist gebruikt om je kluis te openen. "
                "Was jij dit niet? Wijzig direct je accountwachtwoord en je vault-sleutels.",
            )
        else:
            await audit_service.log(
                conn, user_id=user_id, event="vault_key_unlock", ip=_ip(request),
                detail={"vault_id": vault_id, "key_id": key_id},
            )
        await svc.mark_used(conn, key_id)
        return VaultKeySealed(id=key_id, sealed=key["sealed"])


@router.post("/{vault_id}/keys/{key_id}/release", response_model=VaultKeyPublic)
async def request_release(vault_id: str, key_id: str, request: Request) -> VaultKeyPublic:
    """Start de wachttijd voor een noodsleutel. Een lopend verzoek wordt niet verlengd of herstart."""
    user_id = _user(request)
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        if key["kind"] != "recovery":
            raise HTTPException(status_code=400, detail={"error": "not_recovery_key"})
        if svc.recovery_state(key) not in ("waiting", "released"):
            key = await svc.request_release(conn, key)
            await audit_service.log(
                conn, user_id=user_id, event="recovery_release_requested", ip=_ip(request),
                user_agent=request.headers.get("user-agent"),
                detail={"vault_id": vault_id, "key_id": key_id, "release_at": key["release_at"]},
            )
            await svc.notify_user(
                conn, user_id, "HorseSafe: vrijgave noodsleutel aangevraagd",
                f"Er is vrijgave aangevraagd voor noodsleutel '{key['label']}'. Hij is bruikbaar vanaf "
                f"{_fmt(int(key['release_at']))}. Was jij dit niet? Log in en annuleer via Sleutels.",
            )
        key.pop("sealed", None)
        return VaultKeyPublic(**key)


@router.delete("/{vault_id}/keys/{key_id}/release", response_model=VaultKeyPublic)
async def cancel_release(vault_id: str, key_id: str, request: Request) -> VaultKeyPublic:
    user_id = _user(request)
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        if key["kind"] != "recovery":
            raise HTTPException(status_code=400, detail={"error": "not_recovery_key"})
        await svc.cancel_release(conn, key_id)
        await audit_service.log(
            conn, user_id=user_id, event="recovery_release_cancelled", ip=_ip(request),
            detail={"vault_id": vault_id, "key_id": key_id},
        )
        await svc.notify_user(
            conn, user_id, "HorseSafe: vrijgave noodsleutel geannuleerd",
            f"De vrijgave van noodsleutel '{key['label']}' is geannuleerd.",
        )
        key.pop("sealed", None)
        key.update(release_requested_at=None, release_at=None, release_until=None)
        return VaultKeyPublic(**key)
