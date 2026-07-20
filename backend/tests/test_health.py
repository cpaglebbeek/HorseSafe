from __future__ import annotations

from httpx import AsyncClient


async def test_health_ok(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"][0].isdigit() and "." in body["version"]
    assert body["db"] == "ok"
    assert body["vaults_dir"] == "ok"


async def test_security_headers(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert "content-security-policy" in {k.lower() for k in r.headers}
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "strict-transport-security" in r.headers


async def test_openapi_docs_disabled_by_default(client: AsyncClient) -> None:
    """Productie-default docs_enabled=false → geen OpenAPI-schema/docs exposure."""
    for p in ("/openapi.json", "/docs", "/redoc"):
        r = await client.get(p)
        assert r.status_code == 404, f"{p} zou dicht moeten zijn (kreeg {r.status_code})"
