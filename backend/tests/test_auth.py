from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW


async def test_register_and_login_happy_path(client: AsyncClient) -> None:
    r = await client.post(
        "/auth/register",
        json={"email": "alice@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    assert r.status_code == 201, r.text
    assert r.json()["email"] == "alice@example.com"

    r = await client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": VALID_PW},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert r.json()["mfa_required"] is False
    # JWT-cookie gezet
    assert "horsesafe_session" in r.cookies


async def test_register_requires_ack(client: AsyncClient) -> None:
    r = await client.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": VALID_PW, "ack_data_loss": False},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "ack_required"


async def test_register_rejects_weak_pw(client: AsyncClient) -> None:
    r = await client.post(
        "/auth/register",
        json={"email": "carol@example.com", "password": "short", "ack_data_loss": True},
    )
    assert r.status_code == 422  # Pydantic validation


async def test_register_duplicate_email(client: AsyncClient) -> None:
    body = {"email": "dave@example.com", "password": VALID_PW, "ack_data_loss": True}
    r1 = await client.post("/auth/register", json=body)
    assert r1.status_code == 201
    r2 = await client.post("/auth/register", json=body)
    assert r2.status_code == 409
    assert r2.json()["detail"]["error"] == "email_in_use"


async def test_login_wrong_password(client: AsyncClient) -> None:
    await client.post(
        "/auth/register",
        json={"email": "eve@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    r = await client.post(
        "/auth/login",
        json={"email": "eve@example.com", "password": "WrongPass99!!"},
    )
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "invalid_credentials"


async def test_login_unknown_email_timing_safe(client: AsyncClient) -> None:
    r = await client.post(
        "/auth/login",
        json={"email": "ghost@example.com", "password": VALID_PW},
    )
    assert r.status_code == 401


async def test_logout(client: AsyncClient) -> None:
    await client.post(
        "/auth/register",
        json={"email": "frank@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post(
        "/auth/login",
        json={"email": "frank@example.com", "password": VALID_PW},
    )
    r = await client.post("/auth/logout")
    assert r.status_code == 200
    assert r.json()["ok"] is True


async def test_logout_requires_auth(client: AsyncClient) -> None:
    r = await client.post("/auth/logout")
    assert r.status_code == 401


async def test_throttle_after_failed_logins(client: AsyncClient) -> None:
    """Na 5 mislukte pogingen wordt verdere login geblokkeerd.

    In v0.0.1 zijn er twee onafhankelijke beschermingslagen:
    - IP-rate-limit middleware (429 Too Many Requests)
    - Account-throttle in DB (423 Locked)
    Beide vuren op ~5 pogingen in 15 min — welke eerst raakt is OK voor de gebruiker.
    """
    await client.post(
        "/auth/register",
        json={"email": "grace@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    # 5 mislukte pogingen
    for _ in range(5):
        await client.post(
            "/auth/login",
            json={"email": "grace@example.com", "password": "WrongOne123!"},
        )
    # 6e poging = geblokkeerd (door welke laag dan ook)
    r = await client.post(
        "/auth/login",
        json={"email": "grace@example.com", "password": VALID_PW},
    )
    assert r.status_code in (423, 429)
    if r.status_code == 423:
        assert r.json()["detail"]["error"] == "throttled"
    else:
        assert r.json()["error"] == "rate_limited"
