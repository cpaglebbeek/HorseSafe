"""Telefoon koppelen (v0.3.4-Miller deel 2) — docs/HARDWARE_KEYS.md §13.3-§13.5.

Flow: web start een koppeling (SU, alleen ``k_srv``) → app claimt (publiek, met ``mac_srv``,
attestatieketens en ``sig_biosig``) → web pollt, controleert ``mac_web`` en de SAS zelf → web
bevestigt met een Seal_v2-kopie naar ``pk_c``. Pas bij bevestigen ontstaat de phone-sleutel.
Mail gaat altijd NA het sluiten van de DB-verbinding (niet-blokkerend, zoals bij vault_keys).
"""

from __future__ import annotations

import hmac
import json
from typing import Any

import aiosqlite
from fastapi import APIRouter, HTTPException, Request, Response, status

from ..config import get_settings
from ..db.connection import connect
from ..models.audit import AuditEvent
from ..models.device import (
    ClaimPublic,
    ClaimResult,
    DeviceList,
    DevicePublic,
    PairingClaim,
    PairingConfirm,
    PairingCreated,
    PairingStart,
    PairingStatus,
)
from ..models.vault_key import VaultKeyPublic
from ..services import android_attestation as aa
from ..services import audit_service, stepup_service, storage_service
from ..services import device_service as dev
from ..services import vault_key_service as svc

router = APIRouter()

ADVICE_DEVICE = (
    "Log direct in, controleer je toestellen en sleutels en verwijder wat je niet herkent."
)


class _Reject(Exception):
    """Claim geweigerd (§13.5 stap 3-7): foutcode + HTTP-status (+ reason bij attestation)."""

    def __init__(
        self,
        code: str,
        status_code: int = 400,
        reason: str | None = None,
        *,
        cancelled: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.reason = reason
        self.cancelled = cancelled  # derde mac-fout: koppeling geannuleerd

    def http(self) -> HTTPException:
        detail: dict[str, Any] = {"error": self.code}
        if self.reason is not None:
            detail["reason"] = self.reason
        return HTTPException(status_code=self.status_code, detail=detail)


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _audit(
    conn: aiosqlite.Connection,
    request: Request,
    user_id: str,
    event: AuditEvent,
    detail: dict[str, Any],
) -> None:
    # Nooit s, k_srv, MAC's, sealed of ketens in de audit (§13.8).
    await audit_service.log(
        conn,
        user_id=user_id,
        event=event,
        ip=_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail=detail,
    )


async def _mail(
    request: Request,
    user_id: str,
    email: str | None,
    event: str,
    subject: str,
    text: str,
    label: str,
) -> None:
    body = svc.notify_body(text, label=label, ip=_ip(request), advice=ADVICE_DEVICE)
    await svc.notify_user(
        email,
        subject,
        body,
        user_id=user_id,
        event=event,
        ip=_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "not_found"})


async def _own_pairing(conn: aiosqlite.Connection, user_id: str, pairing_id: str) -> dict[str, Any]:
    p = await dev.own_pairing(conn, user_id, pairing_id)
    if p is None:
        raise _not_found()
    return p


# ─────────────── Koppeling starten (web, SU) ───────────────


@router.post("/pairings", status_code=status.HTTP_201_CREATED, response_model=PairingCreated)
async def start_pairing(body: PairingStart, request: Request) -> PairingCreated:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        if not await storage_service.get_vault_meta(conn, user_id, body.vault_id):
            raise _not_found()
        stepup_service.check_stepup(payload)
        t = svc.now()
        if await dev.pairings_last_hour(conn, user_id, t) >= dev.PAIRINGS_PER_HOUR:
            raise HTTPException(status_code=429, detail={"error": "too_many_pairings"})
        # Vroeg melden (zoals /webauthn/options bij register): bevestigen zou toch weigeren.
        if await svc.count_vault_keys(conn, body.vault_id) >= settings.vault_keys_max:
            raise HTTPException(status_code=409, detail={"error": "too_many_keys"})
        pairing_id, expires_at, cancelled = await dev.create_pairing(
            conn, user_id=user_id, vault_id=body.vault_id, k_srv=body.k_srv, t=t
        )
        for old in cancelled:  # één open koppeling per gebruiker
            await _audit(
                conn,
                request,
                user_id,
                "device_pairing_cancel",
                {"pairing_id": old, "reason": "superseded"},
            )
        await _audit(
            conn,
            request,
            user_id,
            "device_pairing_start",
            {"pairing_id": pairing_id, "vault_id": body.vault_id},
        )
    return PairingCreated(pairing_id=pairing_id, expires_at=expires_at)


# ─────────────── Status en annuleren (web, S) ───────────────


@router.get("/pairings/{pairing_id}", response_model=PairingStatus)
async def pairing_status(pairing_id: str, request: Request) -> PairingStatus:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        t = svc.now()
        await dev.expire_stale_claims(conn, t, user_id=user_id)
        p = await _own_pairing(conn, user_id, pairing_id)
    # §13.3: een geannuleerde of verlopen koppeling bestaat voor het web niet meer (404, zoals een
    # onbekende); alleen pending binnen de TTL, claimed en confirmed geven een status.
    if p["status"] == "cancelled" or (p["status"] == "pending" and int(p["expires_at"]) < t):
        raise _not_found()
    claim = None
    if p["status"] in ("claimed", "confirmed") and p["claim_json"]:
        claim = ClaimPublic(**json.loads(p["claim_json"]))
    return PairingStatus(status=p["status"], expires_at=p["expires_at"], claim=claim)


@router.delete("/pairings/{pairing_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_pairing(pairing_id: str, request: Request) -> Response:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        await dev.expire_stale_claims(conn, svc.now(), user_id=user_id)
        p = await _own_pairing(conn, user_id, pairing_id)
        if p["status"] == "confirmed":
            # Een bevestigd toestel trek je in met DELETE /devices/{id}.
            raise HTTPException(status_code=409, detail={"error": "pairing_confirmed"})
        if p["status"] in ("pending", "claimed"):
            await dev.cancel_pairing(conn, p)
            await _audit(
                conn, request, user_id, "device_pairing_cancel", {"pairing_id": pairing_id}
            )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─────────────── Claim (app, publiek; §13.5) ───────────────


async def _check_claim(
    conn: aiosqlite.Connection, p: dict[str, Any], body: PairingClaim
) -> tuple[aa.AttestationResult, bytes]:
    """Stap 3-7. Geen schrijfactie behalve de mac-fouttelling (stap 3)."""
    fields = {k: getattr(body, k) for k in dev.TRANSCRIPT_FIELDS}
    t = dev.transcript(p["id"], fields)
    k_srv = dev.b64u_decode(p["k_srv"])
    # 3 — timing-safe
    if not hmac.compare_digest(dev.mac(k_srv, t), dev.b64u_decode(body.mac_srv)):
        cancelled = await dev.register_mac_failure(conn, p["id"])
        raise _Reject("pairing_mac_invalid", cancelled=cancelled)
    # 4-5
    try:
        result = await aa.verify_pair_attestation(
            k_dev_pub=body.k_dev_pub,
            k_dev_chain=body.k_dev_chain,
            k_biosig_pub=body.k_biosig_pub,
            k_biosig_chain=body.k_biosig_chain,
            att_challenge=dev.att_challenge(p["id"], k_srv),
        )
    except aa.AttestationError as e:
        raise _Reject(e.code, e.status, e.reason) from e
    # 6
    try:
        sig = dev.b64u_decode(body.sig_biosig)
    except ValueError as e:
        raise _Reject("signature_invalid") from e
    if not dev.verify_p256(body.k_biosig_pub, sig, t):
        raise _Reject("signature_invalid")
    # 7
    if await dev.active_device_count(conn, p["user_id"]) >= dev.DEVICES_MAX:
        raise _Reject("too_many_devices", 409)
    return result, t


@router.post(
    "/pairings/{pairing_id}/claim", status_code=status.HTTP_201_CREATED, response_model=ClaimResult
)
async def claim_pairing(pairing_id: str, body: PairingClaim, request: Request) -> ClaimResult:
    async with connect(get_settings().db_path) as conn:
        # 2 — geen onderscheid tussen onbekend, niet-pending en verlopen
        p = await dev.get_pairing(conn, pairing_id)
        t_now = svc.now()
        if p is None or p["status"] != "pending" or int(p["expires_at"]) < t_now:
            raise HTTPException(status_code=404, detail={"error": "pairing_not_found"})
        user_id = str(p["user_id"])
        try:
            result, t = await _check_claim(conn, p, body)
            # 8 — één transactie
            stored = await dev.store_claim(
                conn,
                p,
                body.model_dump(),
                chains={"k_dev": body.k_dev_chain, "k_biosig": body.k_biosig_chain},
                security_level=result.security_level,
                strongbox=result.strongbox,
                t=svc.now(),
            )
            if stored is None:  # intussen geclaimd, geannuleerd of verlopen
                raise _Reject("pairing_not_found", 404)
        except _Reject as e:
            detail = {"pairing_id": pairing_id, "reason": e.code}
            if e.reason is not None:
                detail["attestation_reason"] = e.reason
            await _audit(conn, request, user_id, "device_pairing_rejected", detail)
            if e.cancelled:
                await _audit(
                    conn,
                    request,
                    user_id,
                    "device_pairing_cancel",
                    {"pairing_id": pairing_id, "reason": "mac_failures"},
                )
            raise e.http() from e
        device_id, _key_id = stored
        await _audit(
            conn,
            request,
            user_id,
            "device_pairing_claim",
            {"pairing_id": pairing_id, "device_id": device_id},
        )
    return ClaimResult(device_id=device_id, sas=dev.sas(t))


# ─────────────── Bevestigen (web, S) ───────────────


@router.post(
    "/pairings/{pairing_id}/confirm",
    status_code=status.HTTP_201_CREATED,
    response_model=VaultKeyPublic,
)
async def confirm_pairing(
    pairing_id: str, body: PairingConfirm, request: Request
) -> VaultKeyPublic:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        p = await _own_pairing(conn, user_id, pairing_id)
        t = svc.now()
        # Eerst p lezen, dan opruimen: een te late bevestiging krijgt zo nog `pairing_expired`
        # (§13.5) in plaats van `pairing_not_claimed`, en het toestel is daarna toch weg.
        await dev.expire_stale_claims(conn, t, user_id=user_id)
        if p["status"] != "claimed" or not p["claim_json"]:
            raise HTTPException(status_code=409, detail={"error": "pairing_not_claimed"})
        if t > int(p["created_at"]) + dev.CONFIRM_WITHIN_SECONDS:
            raise HTTPException(status_code=409, detail={"error": "pairing_expired"})
        claim = json.loads(p["claim_json"])
        if not svc.validate_sealed(body.sealed, claim["key_id"]):
            raise HTTPException(status_code=400, detail={"error": "invalid_sealed"})
        if await svc.count_vault_keys(conn, p["vault_id"]) >= settings.vault_keys_max:
            raise HTTPException(status_code=409, detail={"error": "too_many_keys"})
        if not await dev.confirm_pairing(conn, p, claim, body.sealed, t):
            raise HTTPException(status_code=409, detail={"error": "pairing_not_claimed"})
        await _audit(
            conn,
            request,
            user_id,
            "device_pairing_confirm",
            {
                "pairing_id": pairing_id,
                "device_id": claim["device_id"],
                "key_id": claim["key_id"],
                "vault_id": p["vault_id"],
            },
        )
        keys = await svc.list_keys(conn, user_id, p["vault_id"])
        email = await svc.user_email(conn, user_id)
    key = next(k for k in keys if k["id"] == claim["key_id"])
    await _mail(
        request,
        user_id,
        email,
        "device_pairing_confirm",
        "HorseSafe: nieuw toestel gekoppeld",
        "Aan je kluis is een telefoon gekoppeld. Die kan voortaan je kluis helpen ontgrendelen.",
        claim["label"],
    )
    return VaultKeyPublic(**svc.public_key_object(key))


# ─────────────── Toestellen (web, S) ───────────────


@router.get("", response_model=DeviceList)
async def list_devices(request: Request) -> DeviceList:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        await dev.expire_stale_claims(conn, svc.now(), user_id=user_id)
        devices = await dev.list_devices(conn, user_id)
    return DeviceList(devices=[DevicePublic(**dev.device_public(d)) for d in devices])


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(device_id: str, request: Request) -> Response:
    """Defensief, geen step-up (zoals sleutel verwijderen, §12.6.8)."""
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        d = await dev.get_device(conn, device_id)
        if d is None or d["user_id"] != user_id or d["revoked_at"] is not None:
            raise _not_found()
        keys = await dev.revoke_device(conn, user_id, device_id, svc.now())
        await _audit(
            conn,
            request,
            user_id,
            "device_revoke",
            {"device_id": device_id, "keys": len(keys)},
        )
        email = await svc.user_email(conn, user_id)
    await _mail(
        request,
        user_id,
        email,
        "device_revoke",
        "HorseSafe: toestel verwijderd",
        f"Een telefoon is verwijderd; {len(keys)} verzegelde kopie(ën) voor dit toestel "
        "zijn gewist.",
        str(d["label"]),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
