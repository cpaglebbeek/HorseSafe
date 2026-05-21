from __future__ import annotations

import pyotp
from httpx import AsyncClient

from .conftest import VALID_PW


async def _register_and_login(client: AsyncClient, email: str = "totp-user@example.com") -> None:
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})


async def test_totp_setup_returns_secret_and_uri(client: AsyncClient) -> None:
    await _register_and_login(client)
    r = await client.post("/auth/totp/setup")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "secret" in body
    assert len(body["secret"]) >= 16  # base32 secret
    assert body["otpauth_url"].startswith("otpauth://totp/")
    assert "HorseSafe" in body["otpauth_url"]


async def test_totp_setup_requires_auth(client: AsyncClient) -> None:
    r = await client.post("/auth/totp/setup")
    assert r.status_code == 401


async def test_totp_verify_setup_flow_happy_path(client: AsyncClient) -> None:
    await _register_and_login(client, "alice-totp@example.com")
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]
    valid_code = pyotp.TOTP(secret).now()

    r = await client.post(
        "/auth/totp/verify",
        json={"secret": secret, "code": valid_code},
    )
    assert r.status_code == 200, r.text
    assert r.json()["mfa_passed"] is True

    # Login opnieuw → mfa_required: true want TOTP is nu gekoppeld
    await client.post("/auth/logout")
    r = await client.post(
        "/auth/login",
        json={"email": "alice-totp@example.com", "password": VALID_PW},
    )
    assert r.status_code == 200
    assert r.json()["mfa_required"] is True


async def test_totp_verify_invalid_code(client: AsyncClient) -> None:
    await _register_and_login(client, "bob-totp@example.com")
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]

    r = await client.post(
        "/auth/totp/verify",
        json={"secret": secret, "code": "000000"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_code"


async def test_totp_challenge_flow(client: AsyncClient) -> None:
    # 1. Register + setup + verify (koppel TOTP)
    await _register_and_login(client, "carol-totp@example.com")
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await client.post("/auth/totp/verify", json={"secret": secret, "code": code})

    # 2. Logout + login opnieuw
    await client.post("/auth/logout")
    await client.post(
        "/auth/login",
        json={"email": "carol-totp@example.com", "password": VALID_PW},
    )

    # 3. /vault zonder MFA-verify → 403
    r = await client.get("/vault")
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "mfa_required"

    # 4. Challenge verify
    code2 = pyotp.TOTP(secret).now()
    r = await client.post("/auth/totp/verify", json={"code": code2})
    assert r.status_code == 200
    assert r.json()["mfa_passed"] is True

    # 5. /vault nu wel toegankelijk
    r = await client.get("/vault")
    assert r.status_code == 200


async def test_totp_disable(client: AsyncClient) -> None:
    await _register_and_login(client, "dave-totp@example.com")
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await client.post("/auth/totp/verify", json={"secret": secret, "code": code})

    code2 = pyotp.TOTP(secret).now()
    r = await client.post("/auth/totp/disable", json={"code": code2})
    assert r.status_code == 200

    # Na disable: login geeft mfa_required: false
    await client.post("/auth/logout")
    r = await client.post(
        "/auth/login",
        json={"email": "dave-totp@example.com", "password": VALID_PW},
    )
    assert r.json()["mfa_required"] is False


async def test_vault_blocks_without_mfa_when_totp_enabled(client: AsyncClient) -> None:
    """Cross-check: account met TOTP kan vault niet bereiken zonder challenge."""
    await _register_and_login(client, "eve-totp@example.com")
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await client.post("/auth/totp/verify", json={"secret": secret, "code": code})
    await client.post("/auth/logout")
    await client.post(
        "/auth/login",
        json={"email": "eve-totp@example.com", "password": VALID_PW},
    )
    # Geen TOTP-verify
    r = await client.get("/vault")
    assert r.status_code == 403
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("v.kdbx", b"\x03\xd9\xa2\x9axxxxx", "application/octet-stream")},
    )
    assert r.status_code == 403
