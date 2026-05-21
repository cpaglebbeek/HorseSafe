from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW

FAKE_BLOB = b"\x03\xd9\xa2\x9a" + b"FAKE_KDBX" * 50


async def _setup_with_vault(client: AsyncClient, email: str = "ie@example.com") -> str:
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("v.kdbx", FAKE_BLOB, "application/octet-stream")},
    )
    return r.json()["id"]


async def test_audit_import_kdbx(client: AsyncClient) -> None:
    vid = await _setup_with_vault(client, "imp-kdbx@example.com")
    r = await client.post(f"/vault/{vid}/audit-import", json={"format": "kdbx", "count": 42})
    assert r.status_code == 200


async def test_audit_import_invalid_format(client: AsyncClient) -> None:
    vid = await _setup_with_vault(client, "imp-bad@example.com")
    r = await client.post(f"/vault/{vid}/audit-import", json={"format": "1password", "count": 1})
    assert r.status_code == 400


async def test_audit_export_kdbx_no_reason(client: AsyncClient) -> None:
    """KDBX-export is encrypted → geen reden vereist."""
    vid = await _setup_with_vault(client, "exp-kdbx@example.com")
    r = await client.post(f"/vault/{vid}/audit-export", json={"format": "kdbx", "reason": ""})
    assert r.status_code == 200


async def test_audit_export_csv_requires_reason(client: AsyncClient) -> None:
    vid = await _setup_with_vault(client, "exp-csv@example.com")
    r = await client.post(
        f"/vault/{vid}/audit-export", json={"format": "csv", "reason": "too short"}
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "reason_required"


async def test_audit_export_csv_with_reason(client: AsyncClient) -> None:
    vid = await _setup_with_vault(client, "exp-csv-ok@example.com")
    r = await client.post(
        f"/vault/{vid}/audit-export",
        json={"format": "csv", "reason": "Backup voor migratie naar 1Password"},
    )
    assert r.status_code == 200


async def test_audit_export_other_user_vault_404(client: AsyncClient) -> None:
    """User mag geen audit-event aanmaken op andermans vault."""
    vid = await _setup_with_vault(client, "exp-user1@example.com")
    await client.post("/auth/logout")
    await client.post(
        "/auth/register",
        json={"email": "exp-user2@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": "exp-user2@example.com", "password": VALID_PW})
    r = await client.post(
        f"/vault/{vid}/audit-export",
        json={"format": "csv", "reason": "Probeer andermans vault"},
    )
    assert r.status_code == 404
