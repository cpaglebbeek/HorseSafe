"""Hardware-sleutels per vault (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.6.

Zero-knowledge (P-CRYPT-01 + P-CRYPT-09): de server ontvangt en bewaart alleen kopieën die
verzegeld zijn naar gebruikershardware en die hij niet kan openen. Een kopie gaat pas terug na
een server-geverifieerde WebAuthn-assertion; een noodsleutel bovendien pas na de wachttijd.
Mail gaat altijd NA het sluiten van de DB-verbinding (mail_service.send_async).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite
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
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.background import BackgroundTask

from ..config import get_settings
from ..db.connection import connect
from ..models.audit import AuditEvent
from ..models.vault_key import (
    RekeySealed,
    UnlockRequest,
    VaultKeyCreate,
    VaultKeyList,
    VaultKeyPublic,
    VaultKeyResealBatch,
    VaultKeySealed,
)
from ..services import audit_service, mail_service, stepup_service, storage_service
from ..services import vault_key_service as svc
from ..services import webauthn_service as wa

router = APIRouter()

KIND_NL = {"bio": "sleutel", "recovery": "noodsleutel"}
ADVICE_KEYS = "Log direct in, controleer je sleutels en verwijder of blokkeer wat je niet herkent."


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _ua(request: Request) -> str | None:
    return request.headers.get("user-agent")


def _http(e: wa.WebAuthnError) -> HTTPException:
    return HTTPException(status_code=e.status, detail={"error": e.code})


async def _own_vault(conn: aiosqlite.Connection, user_id: str, vault_id: str) -> dict[str, object]:
    meta = await storage_service.get_vault_meta(conn, user_id, vault_id)
    if not meta:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return meta


async def _own_key(
    conn: aiosqlite.Connection,
    user_id: str,
    vault_id: str,
    key_id: str,
    *,
    with_sealed: bool = False,
) -> dict[str, Any]:
    key = await svc.get_key(conn, user_id, vault_id, key_id, with_sealed=with_sealed)
    if not key or key["kind"] == "phone":  # telefoonsleutels bestaan pas in Miller
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return key


def _recovery_only(key: dict[str, Any]) -> None:
    if key["kind"] != "recovery":
        raise HTTPException(status_code=400, detail={"error": "not_recovery_key"})


async def _audit(
    conn: aiosqlite.Connection,
    request: Request,
    user_id: str,
    event: AuditEvent,
    detail: dict[str, Any],
) -> None:
    await audit_service.log(
        conn,
        user_id=user_id,
        event=event,
        ip=_ip(request),
        user_agent=_ua(request),
        detail=detail,
    )


async def _mail(
    request: Request,
    user_id: str,
    email: str | None,
    event: str,
    subject: str,
    text: str,
    *,
    label: str | None,
    advice: str = ADVICE_KEYS,
) -> None:
    body = svc.notify_body(text, label=label, ip=_ip(request), advice=advice)
    await svc.notify_user(
        email, subject, body, user_id=user_id, event=event, ip=_ip(request), user_agent=_ua(request)
    )


async def _clone_suspect_mail(
    request: Request, user_id: str, email: str | None, label: str
) -> None:
    await _mail(
        request,
        user_id,
        email,
        "vault_key_clone_suspect",
        svc.CLONE_SUBJECT,
        svc.CLONE_TEXT,
        label=label,
        advice=svc.CLONE_ADVICE,
    )


# ─────────────── Lijst (§12.6.3) ───────────────


@router.get("/{vault_id}/keys", response_model=VaultKeyList)
async def list_keys(vault_id: str, request: Request) -> VaultKeyList:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        await _own_vault(conn, user_id, vault_id)
        keys = await svc.list_keys(conn, user_id, vault_id)
    return VaultKeyList(
        keys=[VaultKeyPublic(**svc.public_key_object(k)) for k in keys if k["kind"] != "phone"],
        notify_available=mail_service.is_configured(),
        stepup_until=stepup_service.stepup_until(payload),
    )


# ─────────────── Registratie (§12.6.1) ───────────────


async def _verify_registration(
    conn: Any, user_id: str, vault_id: str, body: VaultKeyCreate
) -> dict[str, Any]:
    settings = get_settings()
    # 2 — beide challenges verbruiken (ook als de eerste al faalt)
    rows: list[dict[str, Any] | None] = []
    for cid in (body.create.challenge_id, body.assert_.challenge_id):
        try:
            rows.append(await wa.consume_challenge(conn, cid, user_id))
        except wa.WebAuthnError:
            rows.append(None)
    c_row, a_row = rows
    if c_row is None or a_row is None:
        raise wa.WebAuthnError("invalid_challenge")
    for row, purpose in ((c_row, "register"), (a_row, "register_assert")):
        if (
            row["purpose"] != purpose
            or row["vault_id"] != vault_id
            or row["kind"] != body.kind
            or row["key_id"] != body.key_id
        ):
            raise wa.WebAuthnError("invalid_challenge")
    if a_row["parent_id"] != c_row["id"] or a_row["prf_salt"] != c_row["prf_salt"]:
        raise wa.WebAuthnError("invalid_challenge")

    # 3 — create-controles 1-8, daarna 9
    created = wa.verify_create(
        kind=body.kind,
        credential_id=body.create.credential_id,
        client_data_json=body.create.client_data_json,
        attestation_object=body.create.attestation_object,
        challenge_row=c_row,
    )
    if await svc.credential_exists(conn, user_id, created.credential_id):
        raise wa.WebAuthnError("credential_exists", 409)

    # 4 — assertion met de net geverifieerde publieke sleutel
    if body.assert_.credential_id != body.create.credential_id:
        raise wa.WebAuthnError("credential_mismatch")
    sign_count = wa.verify_assertion(
        credential_id=body.assert_.credential_id,
        client_data_json=body.assert_.client_data_json,
        authenticator_data=body.assert_.authenticator_data,
        signature=body.assert_.signature,
        user_handle=body.assert_.user_handle,
        challenge_row=a_row,
        cose_public_key=created.cose_public_key,
        stored_sign_count=created.sign_count,
    )

    # 5 — alleen de vorm van de verzegelde kopie
    if not svc.validate_sealed(body.sealed, body.key_id):
        raise wa.WebAuthnError("invalid_sealed")

    # 6 — opnieuw tellen
    if await svc.count_vault_keys(conn, vault_id) >= settings.vault_keys_max:
        raise wa.WebAuthnError("too_many_keys", 409)

    return {
        "id": body.key_id,
        "user_id": user_id,
        "vault_id": vault_id,
        "kind": body.kind,
        "label": body.label,
        "credential_id": created.credential_id,
        "cose_public_key": created.cose_public_key,
        "aaguid": created.aaguid,
        "att_fmt": created.att_fmt,
        "sign_count": sign_count,
        "prf_salt": c_row["prf_salt"],  # uit de challenge-rij, nooit van de client
        "public_key": body.public_key,
        "sealed": body.sealed,
    }


@router.post("/{vault_id}/keys", status_code=status.HTTP_201_CREATED, response_model=VaultKeyPublic)
async def add_key(vault_id: str, body: VaultKeyCreate, request: Request) -> VaultKeyPublic:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        # 1
        await _own_vault(conn, user_id, vault_id)
        if await svc.user_has_keys(conn, user_id):
            stepup_service.check_stepup(payload)
        # 2-7; geen schrijfactie of vault_key_add vóór stap 7
        try:
            data = await _verify_registration(conn, user_id, vault_id, body)
            try:
                await svc.insert_key(conn, data)
            except ValueError as e:
                raise wa.WebAuthnError("credential_exists", 409) from e
        except wa.WebAuthnError as e:
            await _audit(
                conn,
                request,
                user_id,
                "vault_key_add_rejected",
                {"vault_id": vault_id, "kind": body.kind, "reason": e.code},
            )
            raise _http(e) from e
        # 8
        await _audit(
            conn,
            request,
            user_id,
            "vault_key_add",
            {
                "vault_id": vault_id,
                "key_id": body.key_id,
                "kind": body.kind,
                "aaguid": data["aaguid"],
            },
        )
        key = await svc.get_key(conn, user_id, vault_id, body.key_id)
        email = await svc.user_email(conn, user_id)
    assert key is not None
    await _mail(
        request,
        user_id,
        email,
        "vault_key_add",
        "HorseSafe: nieuwe sleutel gekoppeld",
        f"Aan je kluis is een {KIND_NL[body.kind]} gekoppeld.",
        label=body.label,
    )
    return VaultKeyPublic(**svc.public_key_object(key))


# ─────────────── Ontgrendelen (§12.6.2) ───────────────


@router.post("/{vault_id}/keys/{key_id}/unlock", response_model=VaultKeySealed)
async def unlock(
    vault_id: str, key_id: str, body: UnlockRequest, request: Request
) -> VaultKeySealed:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    clone_email: str | None = None
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id, with_sealed=True)  # 1
        try:
            row = await wa.consume_challenge(conn, body.challenge_id, user_id)  # 2
            if row["purpose"] != "unlock" or row["vault_id"] != vault_id:
                raise wa.WebAuthnError("invalid_challenge")
            if body.credential_id != key["credential_id"]:  # 3
                raise wa.WebAuthnError("credential_mismatch")
            new_count = wa.verify_assertion(  # 4
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
            if e.code != "sign_count_regression":
                raise _http(e) from e
            await _audit(
                conn,
                request,
                user_id,
                "vault_key_clone_suspect",
                {"vault_id": vault_id, "key_id": key_id, "kind": key["kind"]},
            )
            clone_email = await svc.user_email(conn, user_id) or ""
            error: HTTPException | None = _http(e)
        else:
            error = None
        if error is None:
            # De assertion is geldig: teller altijd bijwerken, ook als de status hierna weigert.
            await svc.update_key(conn, key_id, sign_count=new_count)
            if key["kind"] == "recovery":  # 5
                state = svc.recovery_state(key)
                if state != "released":
                    raise HTTPException(
                        status_code=status.HTTP_423_LOCKED,
                        detail={
                            "error": f"recovery_{state}",
                            "state": state,
                            "release_at": key["release_at"],
                            "release_until": svc.release_until(key),
                        },
                    )
            elif key["status"] != "active":  # 6
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED, detail={"error": "key_blocked"}
                )
            t = svc.now()  # 7
            if key["kind"] == "recovery":
                # Eén keer bruikbaar, ook bij gelijktijdige verzoeken: atomair verbruiken.
                if not await svc.consume_release(conn, key_id, int(key["release_at"]), t):
                    raise HTTPException(
                        status_code=status.HTTP_423_LOCKED,
                        detail={
                            "error": "recovery_consumed",
                            "state": "consumed",
                            "release_at": key["release_at"],
                            "release_until": svc.release_until(key),
                        },
                    )
                await _audit(
                    conn,
                    request,
                    user_id,
                    "recovery_key_used",
                    {"vault_id": vault_id, "key_id": key_id},
                )
            else:
                await svc.update_key(conn, key_id, last_used_at=t)
                await _audit(
                    conn,
                    request,
                    user_id,
                    "vault_key_unlock",
                    {"vault_id": vault_id, "key_id": key_id},
                )
            email = await svc.user_email(conn, user_id) if key["kind"] == "recovery" else None
    if error is not None:
        await _clone_suspect_mail(request, user_id, clone_email, key["label"])
        raise error
    if key["kind"] == "recovery":
        await _mail(
            request,
            user_id,
            email,
            "recovery_key_used",
            "HorseSafe: noodsleutel gebruikt",
            "Je noodsleutel is zojuist gebruikt om je kluis te openen.",
            label=key["label"],
            advice="Wijzig direct je accountwachtwoord en het wachtwoord/de keyfile van je kluis.",
        )
    return VaultKeySealed(id=key_id, sealed=key["sealed"])


# ─────────────── Opnieuw verzegelen (§12.6.4) ───────────────


@router.put("/{vault_id}/keys/sealed")
async def reseal_keys(vault_id: str, body: VaultKeyResealBatch, request: Request) -> dict[str, int]:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        await _own_vault(conn, user_id, vault_id)
        stepup_service.check_stepup(payload)
        known = {k["id"] for k in await svc.list_keys(conn, user_id, vault_id)}
        if any(it.id not in known for it in body.items):
            raise HTTPException(status_code=400, detail={"error": "unknown_key"})
        if not all(svc.validate_sealed(it.sealed, it.id) for it in body.items):
            raise HTTPException(status_code=400, detail={"error": "invalid_sealed"})
        try:
            n = await svc.reseal(conn, user_id, vault_id, [it.model_dump() for it in body.items])
        except ValueError as e:
            raise HTTPException(status_code=400, detail={"error": "unknown_key"}) from e
        await _audit(conn, request, user_id, "vault_key_reseal", {"vault_id": vault_id, "count": n})
    return {"updated": n}


# ─────────────── Wachtwoord/keyfile wijzigen (§12.6.5) ───────────────


@router.put("/{vault_id}/rekey")
async def rekey(
    vault_id: str,
    request: Request,
    blob: UploadFile = File(...),
    sealed: str = Form(...),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    # 1
    async with connect(settings.db_path) as conn:
        meta = await _own_vault(conn, user_id, vault_id)
    stepup_service.check_stepup(payload)
    if not if_match:
        raise HTTPException(status_code=428, detail={"error": "if_match_required"})
    data = await blob.read()
    if len(data) > settings.vault_max_bytes:
        raise HTTPException(status_code=413, detail={"error": "blob_too_large"})
    # 2 — parsen
    try:
        parsed = RekeySealed.model_validate_json(sealed)
    except ValidationError as e:
        raise HTTPException(
            status_code=422,
            detail=jsonable_encoder(e.errors(include_url=False, include_context=False)),
        ) from e
    items = [it.model_dump() for it in parsed.items]
    ids = [it["id"] for it in items]

    blob_path = Path(str(meta["blob_path"]))
    async with connect(settings.db_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            current = {k["id"] for k in await svc.list_keys(conn, user_id, vault_id)}
            if len(set(ids)) != len(ids) or set(ids) != current:
                raise HTTPException(status_code=409, detail={"error": "keys_mismatch"})
            if not all(svc.validate_sealed(it["sealed"], it["id"]) for it in items):
                raise HTTPException(status_code=400, detail={"error": "invalid_sealed"})
            cur = await conn.execute(
                "SELECT etag FROM vaults WHERE id = ? AND user_id = ?", (vault_id, user_id)
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail={"error": "not_found"})
            if str(row["etag"]) != if_match:  # 3
                raise HTTPException(
                    status_code=412,
                    detail={"error": "etag_mismatch", "current_etag": str(row["etag"])},
                )
            # 4 — atomair: kopieën + vault-meta, dan blob, dan COMMIT
            t = svc.now()
            for it in items:
                await conn.execute(
                    "UPDATE vault_keys SET sealed = ?, updated_at = ? "
                    "WHERE id = ? AND vault_id = ?",
                    (it["sealed"], t, it["id"], vault_id),
                )
            new_etag = storage_service._hash_bytes(data)
            await conn.execute(
                "UPDATE vaults SET size_bytes = ?, etag = ?, updated_at = ? WHERE id = ?",
                (len(data), new_etag, t, vault_id),
            )
            try:
                storage_service._atomic_write(blob_path, data)
            except OSError as e:
                raise HTTPException(status_code=500, detail={"error": "write_failed"}) from e
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
        # 5
        await _audit(
            conn,
            request,
            user_id,
            "vault_rekey",
            {"vault_id": vault_id, "size": len(data), "keys": len(items)},
        )
        email = await svc.user_email(conn, user_id)
    # De melding gaat NA het antwoord (BackgroundTask): de rekey is gecommit, en een trage
    # SMTP-server mag het antwoord niet laten verlopen (nginx-504 → client denkt ten onrechte
    # dat het mislukte).
    mail = BackgroundTask(
        _mail,
        request,
        user_id,
        email,
        "vault_rekey",
        "HorseSafe: wachtwoord of keyfile van je kluis gewijzigd",
        f"Het wachtwoord en/of de keyfile van je kluis '{meta['name']}' is gewijzigd. "
        "Alle verzegelde kopieën voor je hardware-sleutels zijn bijgewerkt.",
        label=None,
        advice="Log direct in, controleer je kluis en je sleutels.",
    )
    vault = {
        "id": vault_id,
        "name": meta["name"],
        "size_bytes": len(data),
        "etag": new_etag,
        "created_at": meta["created_at"],
        "updated_at": t,
    }
    return JSONResponse(
        content={"vault": vault, "resealed": len(items)},
        headers={"ETag": new_etag, "Cache-Control": "no-store"},
        background=mail,
    )


# ─────────────── Noodsleutel: vrijgave (§12.6.6) ───────────────


@router.post("/{vault_id}/keys/{key_id}/release", response_model=VaultKeyPublic)
async def request_release(vault_id: str, key_id: str, request: Request) -> VaultKeyPublic:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)  # 1
        _recovery_only(key)
        state = svc.recovery_state(key)
        if state == "blocked":  # 2
            raise HTTPException(status_code=409, detail={"error": "recovery_blocked"})
        if state in ("waiting", "released"):  # 3 — niet verlengen, geen nieuwe mail
            return VaultKeyPublic(**svc.public_key_object(key))
        if not mail_service.is_configured():  # 4
            raise HTTPException(status_code=503, detail={"error": "notify_unavailable"})
        t = svc.now()  # 5
        release_at = t + settings.recovery_delay_hours * 3600
        await svc.update_key(
            conn, key_id, release_requested_at=t, release_at=release_at, release_consumed_at=None
        )
        email = await svc.user_email(conn, user_id)
    # 6 — buiten de DB-verbinding versturen en het resultaat afwachten
    body = svc.notify_body(
        f"Er is vrijgave aangevraagd voor je noodsleutel. Hij is bruikbaar vanaf "
        f"{svc.fmt_time(release_at)} tot "
        f"{svc.fmt_time(release_at + settings.recovery_window_hours * 3600)}.",
        label=key["label"],
        ip=_ip(request),
        advice="Log direct in en annuleer of blokkeer de vrijgave via Sleutels.",
    )
    ok = bool(email) and await mail_service.send_async(
        str(email), "HorseSafe: vrijgave noodsleutel aangevraagd", body
    )
    async with connect(settings.db_path) as conn:
        if not ok:
            await conn.execute(
                "UPDATE vault_keys SET release_requested_at = NULL, release_at = NULL, "
                "updated_at = ? WHERE id = ? AND release_requested_at = ?",
                (svc.now(), key_id, t),
            )
            await conn.commit()
            await _audit(
                conn, request, user_id, "notify_failed", {"event": "recovery_release_request"}
            )
            raise HTTPException(status_code=503, detail={"error": "notify_failed"})
        await _audit(
            conn,
            request,
            user_id,
            "recovery_release_request",  # 7
            {"vault_id": vault_id, "key_id": key_id, "release_at": release_at},
        )
        key = await _own_key(conn, user_id, vault_id, key_id)
    return VaultKeyPublic(**svc.public_key_object(key))


@router.delete("/{vault_id}/keys/{key_id}/release", response_model=VaultKeyPublic)
async def cancel_release(vault_id: str, key_id: str, request: Request) -> VaultKeyPublic:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        _recovery_only(key)
        if svc.recovery_state(key) not in ("waiting", "released"):
            raise HTTPException(status_code=409, detail={"error": "nothing_to_cancel"})
        await svc.update_key(conn, key_id, release_requested_at=None, release_at=None)
        await _audit(
            conn,
            request,
            user_id,
            "recovery_release_cancel",
            {"vault_id": vault_id, "key_id": key_id},
        )
        key = await _own_key(conn, user_id, vault_id, key_id)
        email = await svc.user_email(conn, user_id)
    await _mail(
        request,
        user_id,
        email,
        "recovery_release_cancel",
        "HorseSafe: vrijgave noodsleutel geannuleerd",
        "De vrijgave van je noodsleutel is geannuleerd.",
        label=key["label"],
    )
    return VaultKeyPublic(**svc.public_key_object(key))


# ─────────────── Noodsleutel: blokkeren / opheffen (§12.6.7) ───────────────


@router.post("/{vault_id}/keys/{key_id}/block", response_model=VaultKeyPublic)
async def block(vault_id: str, key_id: str, request: Request) -> VaultKeyPublic:
    """Defensief: geen step-up. Blijft staan tot expliciet opheffen met Bio-step-up (besluit 3)."""
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        _recovery_only(key)
        if key["status"] == "blocked":
            return VaultKeyPublic(**svc.public_key_object(key))
        await svc.update_key(
            conn,
            key_id,
            status="blocked",
            blocked_at=svc.now(),
            blocked_by="web",
            release_requested_at=None,
            release_at=None,
        )
        await _audit(
            conn,
            request,
            user_id,
            "recovery_block",
            {"vault_id": vault_id, "key_id": key_id, "by": "web"},
        )
        key = await _own_key(conn, user_id, vault_id, key_id)
        email = await svc.user_email(conn, user_id)
    await _mail(
        request,
        user_id,
        email,
        "recovery_block",
        "HorseSafe: noodsleutel geblokkeerd",
        "Je noodsleutel is geblokkeerd. Opheffen kan alleen met je YubiKey Bio.",
        label=key["label"],
        advice="Log in, controleer je sleutels en je account, en wijzig je accountwachtwoord.",
    )
    return VaultKeyPublic(**svc.public_key_object(key))


@router.delete("/{vault_id}/keys/{key_id}/block", response_model=VaultKeyPublic)
async def unblock(vault_id: str, key_id: str, request: Request) -> VaultKeyPublic:
    """SU met ``stepup_method == 'bio'`` — nooit met alleen wachtwoord of TOTP (besluit 3).

    De bevestigende Bio moet al gekoppeld zijn geweest vóór de blokkade: anders kan wie het
    account (wachtwoord + TOTP) overneemt eerst een eigen Bio koppelen en daarmee opheffen (R6)."""
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        _recovery_only(key)
        stepup_service.check_stepup(payload, ("bio",))
        if key["status"] != "blocked":
            raise HTTPException(status_code=409, detail={"error": "not_blocked"})
        su_key = next(
            (
                k
                for k in await svc.user_bio_keys(conn, user_id)
                if k["id"] == payload.get("stepup_key")
            ),
            None,
        )
        if (
            su_key is None
            or key["blocked_at"] is None
            or int(su_key["created_at"]) > int(key["blocked_at"])
        ):
            await _audit(
                conn,
                request,
                user_id,
                "recovery_unblock_rejected",
                {"vault_id": vault_id, "key_id": key_id, "reason": "stepup_key_too_new"},
            )
            raise HTTPException(status_code=403, detail={"error": "stepup_key_too_new"})
        await svc.update_key(conn, key_id, status="active", blocked_at=None, blocked_by=None)
        await _audit(
            conn,
            request,
            user_id,
            "recovery_unblock",
            {"vault_id": vault_id, "key_id": key_id, "stepup_method": payload.get("stepup_method")},
        )
        key = await _own_key(conn, user_id, vault_id, key_id)
        email = await svc.user_email(conn, user_id)
    await _mail(
        request,
        user_id,
        email,
        "recovery_unblock",
        "HorseSafe: blokkade noodsleutel opgeheven",
        "De blokkade van je noodsleutel is opgeheven (bevestigd met je YubiKey Bio).",
        label=key["label"],
    )
    return VaultKeyPublic(**svc.public_key_object(key))


# ─────────────── Verwijderen (§12.6.8) ───────────────


@router.delete("/{vault_id}/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_key(vault_id: str, key_id: str, request: Request) -> Response:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    async with connect(get_settings().db_path) as conn:
        key = await _own_key(conn, user_id, vault_id, key_id)
        await svc.delete_key(conn, user_id, vault_id, key_id)
        await _audit(
            conn,
            request,
            user_id,
            "vault_key_delete",
            {"vault_id": vault_id, "key_id": key_id, "kind": key["kind"]},
        )
        email = await svc.user_email(conn, user_id)
    await _mail(
        request,
        user_id,
        email,
        "vault_key_delete",
        "HorseSafe: sleutel verwijderd",
        f"Een {KIND_NL.get(key['kind'], 'sleutel')} is van je kluis verwijderd.",
        label=key["label"],
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
