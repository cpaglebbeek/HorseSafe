from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW


async def test_me_unauthenticated(client: AsyncClient) -> None:
    r = await client.get("/auth/me")
    assert r.status_code == 401


async def test_me_after_login(client: AsyncClient) -> None:
    await client.post(
        "/auth/register",
        json={"email": "me@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": "me@example.com", "password": VALID_PW})

    r = await client.get("/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "me@example.com"
    assert body["is_admin"] is False
    assert body["has_totp"] is False
    assert body["backup_codes_remaining"] == 0
    assert body["mfa_pass"] is True  # geen TOTP → direct mfa_pass
