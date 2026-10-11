from __future__ import annotations

import re
from typing import Any

import pyotp
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


def _links(sent: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Alleen de magic-link-mails (TOTP instellen stuurt ook een melding)."""
    return [m for m in sent if "/mfa.html#ml=" in m["body"]]


def _token(sent: list[dict[str, Any]]) -> str:
    links = _links(sent)
    assert links, "geen magic-link-mail"
    m = re.search(r"/mfa\.html#ml=([\w\-_]+)", links[-1]["body"])
    assert m
    return m.group(1)


async def _register_with_totp(client: AsyncClient, email: str) -> None:
    """Gebruiker met TOTP: na een wachtwoord-login is de sessie mfa=false."""
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    secret = (await client.post("/auth/totp/setup")).json()["secret"]
    r = await client.post(
        "/auth/totp/verify", json={"secret": secret, "code": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 200
    await client.post("/auth/logout")


async def test_magic_link_flow_happy_path(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    email = "magic@example.com"
    await _register_with_totp(client, email)

    # 1. Wachtwoord-login → mfa=false, vault dicht
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    assert (await client.get("/vault")).status_code == 403

    # 2. Vraag magic-link aan
    r = await client.post("/auth/magic-link", json={"email": email})
    assert r.status_code == 200
    assert len(_links(stub_email)) == 1
    assert _links(stub_email)[0]["to"] == email
    token = _token(stub_email)

    # 3. Verzilver in dezelfde browser (POST vanaf mfa.html) → mfa=true
    r = await client.post("/auth/magic-link/redeem", json={"t": token})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert "set-cookie" in {h.lower() for h in r.headers}
    assert (await client.get("/vault")).status_code == 200
    assert (await client.get("/auth/me")).json()["mfa_pass"] is True

    # 4. Magic-link is single-use
    r2 = await client.post("/auth/magic-link/redeem", json={"t": token})
    assert r2.status_code == 400
    assert r2.json()["detail"]["error"] == "invalid_link"


async def test_magic_link_get_is_side_effect_free_redirect(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    """Reviewronde 3: het SameSite=Strict-cookie gaat niet mee bij een klik vanuit webmail
    (cross-site). De GET (links uit oudere mails) kijkt daarom niet naar het cookie en verbruikt
    niets: hij stuurt door naar mfa.html, dat same-site POST en wél het cookie meestuurt."""
    email = "webmail@example.com"
    await _register_with_totp(client, email)
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    await client.post("/auth/magic-link", json={"email": email})
    token = _token(stub_email)

    # Cross-site klik: géén cookie mee
    session = client.cookies.get("horsesafe_session")
    assert session
    client.cookies.clear()
    r = await client.get(f"/auth/magic-link/redeem?t={token}", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].endswith(f"/mfa.html#ml={token}")
    assert "set-cookie" not in {h.lower() for h in r.headers}

    # De pagina POST daarna same-site, mét cookie → slaagt (token was niet verbruikt)
    client.cookies.set("horsesafe_session", session)
    r = await client.post("/auth/magic-link/redeem", json={"t": token})
    assert r.status_code == 200
    assert (await client.get("/vault")).status_code == 200


async def test_magic_link_without_password_session_refused_and_not_consumed(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    """Reviewronde 2: mailbox-toegang alleen geeft geen sessie (en dus geen S)."""
    email = "mailbox-only@example.com"
    await _register_with_totp(client, email)
    await client.post("/auth/magic-link", json={"email": email})
    token = _token(stub_email)

    # Geen cookie → geweigerd, geen sessie
    r = await client.post("/auth/magic-link/redeem", json={"t": token})
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "magic_link_login_first"
    assert "set-cookie" not in {h.lower() for h in r.headers}
    assert (await client.get("/auth/me")).status_code == 401
    assert (await client.get("/vault")).status_code == 401

    # De link is niet verbruikt: na een wachtwoord-login werkt hij alsnog
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    r = await client.post("/auth/magic-link/redeem", json={"t": token})
    assert r.status_code == 200
    assert (await client.get("/vault")).status_code == 200


async def test_magic_link_session_of_other_user_refused(
    client: AsyncClient, stub_email: list[dict[str, Any]]
) -> None:
    await _register_with_totp(client, "slachtoffer@example.com")
    await _register_with_totp(client, "aanvaller@example.com")
    await client.post("/auth/magic-link", json={"email": "slachtoffer@example.com"})
    token = _token(stub_email)

    await client.post("/auth/login", json={"email": "aanvaller@example.com", "password": VALID_PW})
    r = await client.post("/auth/magic-link/redeem", json={"t": token})
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "magic_link_login_first"
    me = (await client.get("/auth/me")).json()
    assert me["email"] == "aanvaller@example.com"
    assert me["mfa_pass"] is False
