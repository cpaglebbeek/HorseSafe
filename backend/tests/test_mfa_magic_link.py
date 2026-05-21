from __future__ import annotations

import re
from typing import Any

import pytest
from httpx import AsyncClient

from .conftest import VALID_PW


@pytest.fixture(autouse=True)
def stub_email(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Vervang GmailSMTPSender door in-memory stub. Returnt sent-list."""
    import importlib

    import backend.services.magic_link_service as mls

    importlib.reload(mls)

    sent: list[dict[str, Any]] = []

    class _Stub:
        def send(self, to_email: str, subject: str, body: str) -> None:
            sent.append({"to": to_email, "subject": subject, "body": body})

    mls.set_sender(_Stub())
    return sent


async def test_magic_link_unknown_email_no_leak(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    r = await client.post("/auth/magic-link", json={"email": "noexist@example.com"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    # Geen e-mail verzonden voor onbekende user
    assert len(stub_email) == 0


async def test_magic_link_flow_happy_path(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    # 1. Register user
    email = "magic@example.com"
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )

    # 2. Vraag magic-link aan (zonder ingelogd te zijn)
    r = await client.post("/auth/magic-link", json={"email": email})
    assert r.status_code == 200
    assert len(stub_email) == 1
    assert stub_email[0]["to"] == email

    # 3. Extract token uit e-mail-body
    body = stub_email[0]["body"]
    m = re.search(r"/auth/magic-link/redeem\?t=([\w\-_]+)", body)
    assert m, f"Geen token in e-mail-body: {body[:200]}"
    token = m.group(1)

    # 4. Verzilver
    r = await client.get(f"/auth/magic-link/redeem?t={token}", follow_redirects=False)
    assert r.status_code == 302
    assert "/vault.html" in r.headers["location"]
    assert "horsesafe_session" in r.cookies or "set-cookie" in {h.lower() for h in r.headers}

    # 5. Magic-link is single-use
    r2 = await client.get(f"/auth/magic-link/redeem?t={token}", follow_redirects=False)
    assert r2.status_code == 302
    assert "error=invalid_link" in r2.headers["location"]


async def test_magic_link_grants_mfa_pass(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    """Magic-link redemption zet mfa=true cookie."""
    email = "mfagrant@example.com"
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/magic-link", json={"email": email})

    body = stub_email[0]["body"]
    m = re.search(r"\?t=([\w\-_]+)", body)
    assert m
    token = m.group(1)

    # Volg redirect → cookie wordt gezet door redeem-endpoint
    await client.get(f"/auth/magic-link/redeem?t={token}", follow_redirects=False)

    # /vault is nu direct toegankelijk (mfa=true)
    r = await client.get("/vault")
    assert r.status_code == 200
    assert r.json() == []
