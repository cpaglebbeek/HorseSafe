"""``POST /webauthn/options`` (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.6.0.

Alle challenges komen van de server; alleen hun SHA-256-hash wordt bewaard.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from ..config import get_settings
from ..db.connection import connect
from ..models.webauthn import WebAuthnOptionsRequest
from ..services import stepup_service, storage_service
from ..services import vault_key_service as svc
from ..services import webauthn_service as wa

router = APIRouter()


def _err(e: wa.WebAuthnError) -> HTTPException:
    return HTTPException(status_code=e.status, detail={"error": e.code})


@router.post("/options")
async def options(body: WebAuthnOptionsRequest, request: Request) -> dict[str, Any]:
    payload = stepup_service.session(request)
    user_id = str(payload["sub"])
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        if body.vault_id is not None and not await storage_service.get_vault_meta(
            conn, user_id, body.vault_id
        ):
            raise HTTPException(status_code=404, detail={"error": "not_found"})

        if body.purpose == "register":
            assert body.vault_id is not None and body.kind is not None
            if await svc.count_vault_keys(conn, body.vault_id) >= settings.vault_keys_max:
                raise HTTPException(status_code=409, detail={"error": "too_many_keys"})
            if await svc.user_has_keys(conn, user_id):
                stepup_service.check_stepup(payload)  # vroeg melden: niet voor niets aanraken
            try:
                await wa.purge_and_check_quota(conn, user_id, needed=2)
            except wa.WebAuthnError as e:
                raise _err(e) from e
            key_id = str(uuid.uuid4())
            prf_salt = wa.b64u_encode(secrets.token_bytes(32))
            common = {
                "user_id": user_id,
                "vault_id": body.vault_id,
                "kind": body.kind,
                "key_id": key_id,
                "prf_salt": prf_salt,
            }
            c_id, c_chal, expires = await wa.create_challenge(conn, purpose="register", **common)
            a_id, a_chal, _ = await wa.create_challenge(
                conn, purpose="register_assert", parent_id=c_id, **common
            )
            await conn.commit()
            email = await svc.user_email(conn, user_id) or ""
            exclude = await svc.user_credential_ids(conn, user_id)
            return {
                "purpose": "register",
                "key_id": key_id,
                "prf_salt": prf_salt,
                "rp": {"id": settings.webauthn_rp_id, "name": settings.webauthn_rp_name},
                "user": {
                    "id": wa.b64u_encode(user_id.encode("utf-8")),
                    "name": email,
                    "display_name": email,
                },
                "create": {"challenge_id": c_id, "challenge": c_chal},
                "assert": {"challenge_id": a_id, "challenge": a_chal},
                "pub_key_cred_params": [-8, -7],
                "exclude_credentials": exclude,
                "authenticator_selection": {
                    "authenticator_attachment": "cross-platform",
                    "resident_key": "discouraged",
                    "user_verification": "required",
                },
                "attestation": "direct",
                "hints": ["security-key"],
                "timeout_ms": settings.webauthn_timeout_ms,
                "expires_at": expires,
            }

        if body.purpose == "unlock":
            assert body.vault_id is not None
            items = []
            for k in await svc.list_keys(conn, user_id, body.vault_id):
                usable = k["status"] == "active" and (
                    k["kind"] == "bio"
                    or (k["kind"] == "recovery" and svc.recovery_state(k) == "released")
                )
                if usable:
                    items.append(
                        {
                            "key_id": k["id"],
                            "kind": k["kind"],
                            "credential_id": k["credential_id"],
                            "prf_salt": k["prf_salt"],
                        }
                    )
            if not items:
                raise HTTPException(status_code=409, detail={"error": "no_usable_keys"})
            vault_id: str | None = body.vault_id
        else:  # stepup
            items = [
                {"key_id": k["id"], "kind": k["kind"], "credential_id": k["credential_id"]}
                for k in await svc.user_bio_keys(conn, user_id)
            ]
            if not items:
                raise HTTPException(status_code=409, detail={"error": "no_bio_keys"})
            vault_id = None

        try:
            await wa.purge_and_check_quota(conn, user_id, needed=1)
        except wa.WebAuthnError as e:
            raise _err(e) from e
        cid, chal, expires = await wa.create_challenge(
            conn, user_id=user_id, purpose=body.purpose, vault_id=vault_id
        )
        await conn.commit()
    return {
        "purpose": body.purpose,
        "challenge_id": cid,
        "challenge": chal,
        "rp_id": settings.webauthn_rp_id,
        "user_verification": "required",
        "hints": ["security-key"],
        "timeout_ms": settings.webauthn_timeout_ms,
        "expires_at": expires,
        "allow_credentials": items,
    }
