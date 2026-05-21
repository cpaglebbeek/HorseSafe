from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW


async def _setup(client: AsyncClient, email: str = "pwchange@example.com") -> None:
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})


async def test_pw_change_unauthenticated(client: AsyncClient) -> None:
    r = await client.post("/auth/password", json={"old_password": "x", "new_password": "y"})
    assert r.status_code == 401


async def test_pw_change_happy(client: AsyncClient) -> None:
    await _setup(client, "ok@example.com")
    new_pw = "NewStrongPw5678!"
    r = await client.post(
        "/auth/password",
        json={"old_password": VALID_PW, "new_password": new_pw},
    )
    assert r.status_code == 200
    # Oude pw werkt niet meer
    await client.post("/auth/logout")
    r = await client.post("/auth/login", json={"email": "ok@example.com", "password": VALID_PW})
    assert r.status_code == 401
    # Nieuwe pw werkt
    r = await client.post("/auth/login", json={"email": "ok@example.com", "password": new_pw})
    assert r.status_code == 200


async def test_pw_change_wrong_old(client: AsyncClient) -> None:
    await _setup(client, "wrong@example.com")
    r = await client.post(
        "/auth/password",
        json={"old_password": "WrongOldPw1234", "new_password": "NewStrongPw5678!"},
    )
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "wrong_old_password"


async def test_pw_change_weak_new(client: AsyncClient) -> None:
    await _setup(client, "weak@example.com")
    r = await client.post(
        "/auth/password",
        json={"old_password": VALID_PW, "new_password": "short"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "password_too_short"


async def test_pw_change_missing_fields(client: AsyncClient) -> None:
    await _setup(client, "missing@example.com")
    r = await client.post("/auth/password", json={"old_password": ""})
    assert r.status_code == 400
