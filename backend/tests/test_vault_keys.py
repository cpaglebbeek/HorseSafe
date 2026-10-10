"""v0.2.0-Koblitz — hardware-sleutels per vault (verzegelde kopieën + noodsleutel-wachttijd)."""

from __future__ import annotations

import base64
import json
import os

import pytest
from httpx import AsyncClient

from .conftest import VALID_PW
from .test_vault import FAKE_KDBX_BLOB


def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(os.urandom(n)).rstrip(b"=").decode()


def _sealed() -> str:
    return json.dumps({"v": 1, "epk": _b64(32), "iv": _b64(12), "ct": _b64(80)})


def _key(kind: str = "bio", label: str = "YubiKey Bio") -> dict[str, str]:
    return {
        "kind": kind,
        "label": label,
        "credential_id": _b64(48),
        "prf_salt": _b64(32),
        "public_key": _b64(32),
        "sealed": _sealed(),
    }


async def _setup(client: AsyncClient, email: str = "keys@example.com") -> str:
    await client.post("/auth/register", json={"email": email, "password": VALID_PW, "ack_data_loss": True})
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("default.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_keys_require_auth(client: AsyncClient) -> None:
    r = await client.get("/vault/x/keys")
    assert r.status_code == 401


async def test_bio_key_lifecycle(client: AsyncClient) -> None:
    vid = await _setup(client)
    body = _key()
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 201, r.text
    key = r.json()
    assert "sealed" not in key  # lijst/aanmaak lekt de verzegelde kopie nooit
    assert key["kind"] == "bio" and key["credential_id"] == body["credential_id"]

    r = await client.get(f"/vault/{vid}/keys")
    assert r.status_code == 200 and len(r.json()) == 1 and "sealed" not in r.json()[0]

    r = await client.get(f"/vault/{vid}/keys/{key['id']}/sealed")
    assert r.status_code == 200 and r.json()["sealed"] == body["sealed"]

    # Zelfde credential nogmaals → 409
    r = await client.post(f"/vault/{vid}/keys", json={**_key(), "credential_id": body["credential_id"]})
    assert r.status_code == 409

    # Opnieuw verzegelen (keyfile-rotatie) zonder dat de sleutel aanwezig is
    new = _sealed()
    r = await client.put(f"/vault/{vid}/keys/sealed", json={"items": [{"id": key["id"], "sealed": new}]})
    assert r.status_code == 200 and r.json()["updated"] == 1
    r = await client.get(f"/vault/{vid}/keys/{key['id']}/sealed")
    assert r.json()["sealed"] == new

    r = await client.delete(f"/vault/{vid}/keys/{key['id']}")
    assert r.status_code == 204
    r = await client.get(f"/vault/{vid}/keys")
    assert r.json() == []


@pytest.mark.parametrize(
    "patch",
    [
        {"kind": "admin"},
        {"prf_salt": "te-kort"},
        {"public_key": "x" * 44},
        {"sealed": json.dumps({"v": 2, "epk": "a", "iv": "b", "ct": "c"})},
        {"sealed": "geen json maar wel lang genoeg"},
        {"label": ""},
    ],
)
async def test_add_key_validation(client: AsyncClient, patch: dict[str, str]) -> None:
    vid = await _setup(client)
    r = await client.post(f"/vault/{vid}/keys", json={**_key(), **patch})
    assert r.status_code in (400, 422), r.text


async def test_other_user_cannot_touch_keys(client: AsyncClient) -> None:
    vid = await _setup(client, "owner@example.com")
    key = (await client.post(f"/vault/{vid}/keys", json=_key())).json()
    await client.post("/auth/logout")
    await _setup(client, "intruder@example.com")
    assert (await client.get(f"/vault/{vid}/keys")).status_code == 404
    assert (await client.get(f"/vault/{vid}/keys/{key['id']}/sealed")).status_code == 404
    assert (await client.delete(f"/vault/{vid}/keys/{key['id']}")).status_code == 404


async def test_key_limit(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HORSESAFE_VAULT_KEYS_MAX", "2")
    vid = await _setup(client)
    for _ in range(2):
        assert (await client.post(f"/vault/{vid}/keys", json=_key())).status_code == 201
    r = await client.post(f"/vault/{vid}/keys", json=_key())
    assert r.status_code == 409 and r.json()["detail"]["error"] == "too_many_keys"


async def test_recovery_key_waiting_period(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.services import vault_key_service as svc

    clock = {"t": 1_800_000_000}
    monkeypatch.setattr(svc, "now", lambda: clock["t"])
    vid = await _setup(client)
    body = _key("recovery", "Reserve-YubiKey kluis")
    key = (await client.post(f"/vault/{vid}/keys", json=body)).json()
    url = f"/vault/{vid}/keys/{key['id']}"

    # Zonder aanvraag: dicht
    r = await client.get(url + "/sealed")
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_idle"

    # Aanvraag → wachttijd 24 u
    r = await client.post(url + "/release")
    assert r.status_code == 200
    assert r.json()["release_at"] == clock["t"] + 24 * 3600
    first_release = r.json()["release_at"]

    # Herhaalde aanvraag verlengt/herstart niet
    clock["t"] += 3600
    assert (await client.post(url + "/release")).json()["release_at"] == first_release

    clock["t"] += 22 * 3600  # 23 u na aanvraag: nog dicht
    r = await client.get(url + "/sealed")
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_waiting"

    clock["t"] += 2 * 3600  # 25 u: vrijgegeven
    r = await client.get(url + "/sealed")
    assert r.status_code == 200 and r.json()["sealed"] == body["sealed"]

    clock["t"] += 24 * 3600  # venster van 24 u voorbij
    r = await client.get(url + "/sealed")
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_expired"

    # Na verlopen venster kan opnieuw worden aangevraagd (nieuwe wachttijd)
    r = await client.post(url + "/release")
    assert r.json()["release_at"] == clock["t"] + 24 * 3600


async def test_recovery_cancel(client: AsyncClient) -> None:
    vid = await _setup(client)
    key = (await client.post(f"/vault/{vid}/keys", json=_key("recovery"))).json()
    url = f"/vault/{vid}/keys/{key['id']}"
    assert (await client.post(url + "/release")).json()["release_at"] is not None
    r = await client.delete(url + "/release")
    assert r.status_code == 200 and r.json()["release_at"] is None
    assert (await client.get(url + "/sealed")).status_code == 423


async def test_release_only_for_recovery(client: AsyncClient) -> None:
    vid = await _setup(client)
    key = (await client.post(f"/vault/{vid}/keys", json=_key("bio"))).json()
    r = await client.post(f"/vault/{vid}/keys/{key['id']}/release")
    assert r.status_code == 400


async def test_keys_audited(client: AsyncClient) -> None:
    from backend.config import get_settings
    from backend.db.connection import connect

    vid = await _setup(client)
    key = (await client.post(f"/vault/{vid}/keys", json=_key())).json()
    await client.get(f"/vault/{vid}/keys/{key['id']}/sealed")
    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute("SELECT event, detail FROM audit_log WHERE event LIKE 'vault_key_%'")
        rows = [dict(r) for r in await cur.fetchall()]
    assert [r["event"] for r in rows] == ["vault_key_add", "vault_key_unlock"]
    assert all("sealed" not in (r["detail"] or "") for r in rows)
