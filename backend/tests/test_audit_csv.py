from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW


async def _make_admin(client: AsyncClient, email: str = "csv-admin@example.com") -> None:
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    import backend.config as cfg
    from backend.db.connection import connect

    async with connect(cfg.get_settings().db_path) as conn:
        await conn.execute("UPDATE users SET is_admin = 1 WHERE email = ?", (email,))
        await conn.commit()
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})


async def test_audit_csv_requires_admin(client: AsyncClient) -> None:
    await client.post(
        "/auth/register",
        json={"email": "nonadmin@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": "nonadmin@example.com", "password": VALID_PW})
    r = await client.get("/admin/audit/export")
    assert r.status_code == 403


async def test_audit_csv_streaming(client: AsyncClient) -> None:
    await _make_admin(client)
    # Genereer wat events
    for _ in range(3):
        await client.get("/admin/users")
    r = await client.get("/admin/audit/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    body = r.text
    assert "id,ts,iso_ts,user_id,ip,user_agent,event,detail,reason" in body
    assert "admin_users" in body or "login_success" in body or "register" in body


async def test_audit_csv_filter_by_event(client: AsyncClient) -> None:
    await _make_admin(client, "filter-admin@example.com")
    r = await client.get("/admin/audit/export?event=login_success")
    assert r.status_code == 200
    body = r.text
    lines = [line for line in body.splitlines() if line.strip()]
    # 1 header + N events
    assert len(lines) >= 2
    # Alle data-rijen hebben event=login_success
    for line in lines[1:]:
        assert "login_success" in line
