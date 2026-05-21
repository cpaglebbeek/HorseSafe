from __future__ import annotations

import pyotp
from httpx import AsyncClient

from .conftest import VALID_PW


async def _register_login_totp(client: AsyncClient, email: str) -> str:
    """Register + login + setup-TOTP. Returnt secret."""
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    r = await client.post("/auth/totp/setup")
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await client.post("/auth/totp/verify", json={"secret": secret, "code": code})
    return secret


async def test_generate_backup_codes(client: AsyncClient) -> None:
    await _register_login_totp(client, "bc-gen@example.com")
    r = await client.post("/auth/backup-codes/generate")
    assert r.status_code == 200
    codes = r.json()["codes"]
    assert len(codes) == 10
    # Format: XXXXX-XXXXX
    for c in codes:
        assert len(c) == 11
        assert c[5] == "-"


async def test_me_reflects_backup_codes(client: AsyncClient) -> None:
    await _register_login_totp(client, "bc-me@example.com")
    r = await client.get("/auth/me")
    assert r.json()["backup_codes_remaining"] == 0

    await client.post("/auth/backup-codes/generate")
    r = await client.get("/auth/me")
    assert r.json()["backup_codes_remaining"] == 10


async def test_consume_backup_code_as_mfa(client: AsyncClient) -> None:
    await _register_login_totp(client, "bc-consume@example.com")
    gen = await client.post("/auth/backup-codes/generate")
    codes = gen.json()["codes"]

    # Logout + re-login → mfa_required
    await client.post("/auth/logout")
    await client.post(
        "/auth/login",
        json={"email": "bc-consume@example.com", "password": VALID_PW},
    )

    # /vault zonder MFA → 403
    r = await client.get("/vault")
    assert r.status_code == 403

    # Verifieer backup-code → mfa upgraded
    r = await client.post("/auth/backup-codes/verify", json={"code": codes[0]})
    assert r.status_code == 200
    assert r.json()["mfa_passed"] is True

    # Vault toegankelijk
    r = await client.get("/vault")
    assert r.status_code == 200

    # Code is single-use → tweede gebruik faalt (na opnieuw inloggen)
    await client.post("/auth/logout")
    await client.post(
        "/auth/login",
        json={"email": "bc-consume@example.com", "password": VALID_PW},
    )
    r = await client.post("/auth/backup-codes/verify", json={"code": codes[0]})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_code"

    # Andere code werkt wel
    r = await client.post("/auth/backup-codes/verify", json={"code": codes[1]})
    assert r.status_code == 200


async def test_invalid_backup_code(client: AsyncClient) -> None:
    await _register_login_totp(client, "bc-invalid@example.com")
    await client.post("/auth/backup-codes/generate")
    await client.post("/auth/logout")
    await client.post(
        "/auth/login",
        json={"email": "bc-invalid@example.com", "password": VALID_PW},
    )
    r = await client.post("/auth/backup-codes/verify", json={"code": "ZZZZZ-ZZZZZ"})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_code"


async def test_regenerate_invalidates_old(client: AsyncClient) -> None:
    await _register_login_totp(client, "bc-regen@example.com")
    old = await client.post("/auth/backup-codes/generate")
    old_codes = old.json()["codes"]

    # Regenereer
    await client.post("/auth/backup-codes/generate")

    # Logout + re-login + try old code
    await client.post("/auth/logout")
    await client.post(
        "/auth/login",
        json={"email": "bc-regen@example.com", "password": VALID_PW},
    )
    r = await client.post("/auth/backup-codes/verify", json={"code": old_codes[0]})
    assert r.status_code == 400
