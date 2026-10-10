"""Gedeelde helpers voor de Koblitz-tests (hardware-sleutels, step-up, mailer)."""

from __future__ import annotations

import json
import os
from typing import Any

import pyotp
from httpx import AsyncClient, Response

from . import seal_v2_ref as seal
from .conftest import VALID_PW
from .softauth import SoftAuthenticator, b64u
from .test_vault import FAKE_KDBX_BLOB


class Mailbox:
    """Nep-zender: verzamelt mails, of gooit als ``fail`` aan staat."""

    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []
        self.fail = False

    def send(self, to_email: str, subject: str, body: str) -> None:
        if self.fail:
            raise OSError("nep-SMTP onbereikbaar")
        self.sent.append({"to": to_email, "subject": subject, "body": body})

    def subjects(self) -> list[str]:
        return [m["subject"] for m in self.sent]


async def setup_user(client: AsyncClient, email: str = "keys@example.com") -> str:
    """Registreer + log in + maak een vault. Return vault_id."""
    await client.post(
        "/auth/register", json={"email": email, "password": VALID_PW, "ack_data_loss": True}
    )
    r = await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    assert r.status_code == 200, r.text
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("default.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def fake_sealed(kid: str) -> str:
    return json.dumps(
        {"v": 2, "kid": kid, "epk": b64u(os.urandom(32)), "iv": b64u(os.urandom(12)),
         "ct": b64u(os.urandom(80))},
        separators=(",", ":"),
    )


async def register_options(client: AsyncClient, vid: str, kind: str = "bio") -> Response:
    return await client.post(
        "/webauthn/options", json={"purpose": "register", "vault_id": vid, "kind": kind}
    )


def build_enroll_body(
    opts: dict[str, Any],
    auth: SoftAuthenticator,
    vid: str,
    *,
    kind: str = "bio",
    label: str = "YubiKey Bio",
    create_kw: dict[str, Any] | None = None,
    get_kw: dict[str, Any] | None = None,
    sealed: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Body voor POST /vault/{vid}/keys + de X25519-seed (voor openen in tests)."""
    create = auth.create(opts["create"]["challenge"], **(create_kw or {}))
    get = auth.get(opts["assert"]["challenge"], **(get_kw or {}))
    prf = os.urandom(32)  # in het echt uit de YubiKey (PRF); de server ziet het nooit
    sk, pk = seal.keypair_from_prf(prf)
    key_id = opts["key_id"]
    if sealed is None:
        sealed = seal.seal(pk, os.urandom(32), os.urandom(32), vault_id=vid, key_id=key_id)
    body = {
        "key_id": key_id,
        "kind": kind,
        "label": label,
        "create": {"challenge_id": opts["create"]["challenge_id"], **create, "transports": ["usb"]},
        "assert": {"challenge_id": opts["assert"]["challenge_id"], **get},
        "public_key": b64u(pk),
        "sealed": sealed,
    }
    return body, sk


async def enroll(
    client: AsyncClient,
    vid: str,
    auth: SoftAuthenticator,
    *,
    kind: str = "bio",
    label: str = "YubiKey Bio",
    **kw: Any,
) -> Response:
    r = await register_options(client, vid, kind)
    assert r.status_code == 200, r.text
    body, _sk = build_enroll_body(r.json(), auth, vid, kind=kind, label=label, **kw)
    return await client.post(f"/vault/{vid}/keys", json=body)


async def unlock(
    client: AsyncClient, vid: str, auth: SoftAuthenticator, key_id: str, **get_kw: Any
) -> Response:
    r = await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})
    if r.status_code != 200:
        return r
    o = r.json()
    body = {"challenge_id": o["challenge_id"], **auth.get(o["challenge"], **get_kw)}
    return await client.post(f"/vault/{vid}/keys/{key_id}/unlock", json=body)


async def stepup_bio(client: AsyncClient, auth: SoftAuthenticator, **get_kw: Any) -> Response:
    r = await client.post("/webauthn/options", json={"purpose": "stepup"})
    assert r.status_code == 200, r.text
    o = r.json()
    body = {"method": "bio", "challenge_id": o["challenge_id"], **auth.get(o["challenge"], **get_kw)}
    return await client.post("/auth/stepup", json=body)


async def enable_totp(client: AsyncClient) -> str:
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]
    r = await client.post(
        "/auth/totp/verify", json={"secret": secret, "code": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 200, r.text
    return str(secret)


async def stepup_totp(client: AsyncClient, secret: str) -> Response:
    return await client.post(
        "/auth/stepup", json={"method": "totp", "code": pyotp.TOTP(secret).now()}
    )
