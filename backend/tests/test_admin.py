from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW


async def _make_admin(client: AsyncClient, email: str) -> str:
    """Helper: registreer + login + promoot tot admin via directe DB-update.

    Returnt user_id.
    """
    r = await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    user_id = r.json()["user_id"]
    # Promoot via directe DB (test-fixture pad)
    import backend.config as cfg
    from backend.db.connection import connect

    async with connect(cfg.get_settings().db_path) as conn:
        await conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
        await conn.commit()
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    return user_id


async def _register_normal_user(client: AsyncClient, email: str) -> str:
    r = await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    return r.json()["user_id"]


async def test_admin_route_requires_admin_claim(client: AsyncClient) -> None:
    """Niet-admin krijgt 403."""
    await client.post(
        "/auth/register",
        json={"email": "normaal@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": "normaal@example.com", "password": VALID_PW})
    r = await client.get("/admin/users")
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "admin_required"


async def test_admin_unauth(client: AsyncClient) -> None:
    r = await client.get("/admin/users")
    assert r.status_code == 401


async def test_admin_list_users(client: AsyncClient) -> None:
    await _make_admin(client, "boss@example.com")
    await _register_normal_user(client, "u1@example.com")
    # Login als admin opnieuw (registreer-flow logde uit?)
    await client.post("/auth/login", json={"email": "boss@example.com", "password": VALID_PW})
    r = await client.get("/admin/users")
    assert r.status_code == 200
    users = r.json()
    emails = {u["email"] for u in users}
    assert "boss@example.com" in emails
    assert "u1@example.com" in emails
    boss = next(u for u in users if u["email"] == "boss@example.com")
    assert boss["is_admin"] == 1 or boss["is_admin"] is True


async def test_admin_stats(client: AsyncClient) -> None:
    await _make_admin(client, "stats-admin@example.com")
    await _register_normal_user(client, "u2@example.com")
    await client.post(
        "/auth/login", json={"email": "stats-admin@example.com", "password": VALID_PW}
    )
    r = await client.get("/admin/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["users_total"] >= 2
    assert "logins_24h" in body
    assert "top10_users_by_storage" in body


async def test_admin_audit_pagination(client: AsyncClient) -> None:
    await _make_admin(client, "audit-admin@example.com")
    await client.post(
        "/auth/login", json={"email": "audit-admin@example.com", "password": VALID_PW}
    )
    r = await client.get("/admin/audit?limit=5")
    assert r.status_code == 200
    rows = r.json()
    assert isinstance(rows, list)
    assert len(rows) <= 5


async def test_admin_delete_user(client: AsyncClient) -> None:
    await _make_admin(client, "del-admin@example.com")
    victim_id = await _register_normal_user(client, "victim@example.com")
    await client.post("/auth/login", json={"email": "del-admin@example.com", "password": VALID_PW})
    r = await client.request(
        "DELETE",
        f"/admin/users/{victim_id}",
        json={"reason": "Test cleanup — automated pytest run"},
    )
    assert r.status_code == 204
    # Verify gone
    r = await client.get("/admin/users")
    emails = {u["email"] for u in r.json()}
    assert "victim@example.com" not in emails


async def test_admin_self_delete_forbidden(client: AsyncClient) -> None:
    admin_id = await _make_admin(client, "selfdel@example.com")
    await client.post("/auth/login", json={"email": "selfdel@example.com", "password": VALID_PW})
    r = await client.request(
        "DELETE",
        f"/admin/users/{admin_id}",
        json={"reason": "Probeer eigen account te wissen — moet falen"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "self_delete_forbidden"


async def test_admin_disable_user_mfa(client: AsyncClient) -> None:
    """Admin kan TOTP van user uitschakelen."""
    import pyotp

    await _make_admin(client, "rescuer@example.com")
    user_id = await _register_normal_user(client, "stuck@example.com")
    # User logt in + setup TOTP
    await client.post("/auth/login", json={"email": "stuck@example.com", "password": VALID_PW})
    setup = await client.post("/auth/totp/setup")
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await client.post("/auth/totp/verify", json={"secret": secret, "code": code})

    # Admin logt in + disable user's MFA
    await client.post("/auth/login", json={"email": "rescuer@example.com", "password": VALID_PW})
    r = await client.post(
        f"/admin/users/{user_id}/disable-mfa",
        json={"reason": "User belde — telefoon kwijt + geen backup-codes"},
    )
    assert r.status_code == 200

    # User logt opnieuw in → mfa_required is False
    await client.post("/auth/logout")
    r = await client.post("/auth/login", json={"email": "stuck@example.com", "password": VALID_PW})
    assert r.json()["mfa_required"] is False
