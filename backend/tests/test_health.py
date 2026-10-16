from __future__ import annotations

import pytest
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


async def test_health_koblitz(client: AsyncClient) -> None:
    body = (await client.get("/health")).json()
    assert body["version"] == "0.4.1-Montgomery"
    assert body["test_attestation"] is False
    assert not {"smtp", "mail", "keys"} & set(body)


def test_app_refuses_test_attestation_with_production_rp(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.app import create_app

    monkeypatch.setenv("HORSESAFE_TEST_ATTESTATION", "1")
    monkeypatch.delenv("HORSESAFE_WEBAUTHN_RP_ID", raising=False)  # default icthorsecloud.nl
    with pytest.raises(RuntimeError, match="TEST_ATTESTATION"):
        create_app()
    monkeypatch.setenv("HORSESAFE_WEBAUTHN_RP_ID", "localhost")
    assert create_app() is not None
