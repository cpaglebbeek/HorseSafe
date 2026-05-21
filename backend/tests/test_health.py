from __future__ import annotations

from httpx import AsyncClient


async def test_health_ok(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"].startswith("0.0.1")
    assert body["db"] == "ok"
    assert body["vaults_dir"] == "ok"


async def test_security_headers(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert "content-security-policy" in {k.lower() for k in r.headers}
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "strict-transport-security" in r.headers
