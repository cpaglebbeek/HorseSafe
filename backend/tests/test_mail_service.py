"""v0.2.0-Koblitz — generieke SMTP-mailer (§12.11, besluit 4)."""

from __future__ import annotations

import logging
import re
import threading
from typing import Any

import pytest
from httpx import AsyncClient

from .conftest import VALID_PW


class FakeSMTP:
    """Nep-``smtplib.SMTP``: registreert de aanroepen."""

    instances: list[FakeSMTP] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.calls: list[str] = []
        self.messages: list[Any] = []
        self.starttls_context: Any = None
        self.login_args: tuple[str, str] | None = None
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *_: object) -> None:
        self.calls.append("quit")

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, context: Any = None) -> None:
        self.calls.append("starttls")
        self.starttls_context = context

    def login(self, user: str, password: str) -> None:
        self.calls.append("login")
        self.login_args = (user, password)

    def send_message(self, msg: Any) -> None:
        self.calls.append("send_message")
        self.messages.append(msg)


@pytest.fixture
def smtp_env(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    import smtplib

    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("HORSESAFE_SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("HORSESAFE_SMTP_USER", "info@example.org")
    monkeypatch.setenv("HORSESAFE_SMTP_PASSWORD", "nep-wachtwoord")
    return FakeSMTP


def test_not_configured() -> None:
    from backend.services import mail_service

    assert mail_service.is_configured() is False
    with pytest.raises(mail_service.MailNotConfigured):
        mail_service.send("a@example.org", "x", "y")


def test_smtp_starttls_path(smtp_env: type[FakeSMTP]) -> None:
    from backend.services import mail_service

    assert mail_service.is_configured()
    mail_service.send("a@example.org", "Onderwerp", "Body")
    (s,) = smtp_env.instances
    assert (s.host, s.port, s.timeout) == ("smtp.test.invalid", 587, 15)
    assert s.calls == ["ehlo", "starttls", "ehlo", "login", "send_message", "quit"]
    assert s.starttls_context is not None and s.starttls_context.check_hostname is True
    assert s.login_args == ("info@example.org", "nep-wachtwoord")
    msg = s.messages[0]
    assert msg["From"] == "info@example.org" and msg["To"] == "a@example.org"
    assert msg["Subject"] == "Onderwerp"


def test_from_is_smtp_user_even_if_smtp_from_differs(
    smtp_env: type[FakeSMTP], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from backend.services import mail_service

    monkeypatch.setenv("HORSESAFE_SMTP_FROM", "andere@example.org")
    with caplog.at_level(logging.WARNING, logger="horsesafe.mail"):
        mail_service.warn_config()
    assert "HORSESAFE_SMTP_FROM wijkt af" in caplog.text
    assert "nep-wachtwoord" not in caplog.text
    mail_service.send("a@example.org", "x", "y")
    assert smtp_env.instances[0].messages[0]["From"] == "info@example.org"


def test_starttls_can_be_disabled(
    smtp_env: type[FakeSMTP], monkeypatch: pytest.MonkeyPatch
) -> None:
    from backend.services import mail_service

    monkeypatch.setenv("HORSESAFE_SMTP_STARTTLS", "false")
    monkeypatch.setenv("HORSESAFE_SMTP_PORT", "2525")
    mail_service.send("a@example.org", "x", "y")
    s = smtp_env.instances[0]
    assert s.port == 2525 and "starttls" not in s.calls


def test_gmail_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.services import mail_service

    monkeypatch.setenv("HORSESAFE_GMAIL_USER", "x@gmail.com")
    monkeypatch.setenv("HORSESAFE_GMAIL_APP_PASSWORD", "nep")
    assert mail_service.is_configured()
    assert isinstance(mail_service._resolve(), mail_service.GmailSMTPSender)
    monkeypatch.setenv("HORSESAFE_SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("HORSESAFE_SMTP_USER", "info@example.org")
    monkeypatch.setenv("HORSESAFE_SMTP_PASSWORD", "nep")
    assert isinstance(mail_service._resolve(), mail_service.SMTPSender)


async def test_send_async_runs_in_thread_and_swallows_errors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from backend.services import mail_service

    seen: list[str] = []

    class Sender:
        fail = False

        def send(self, to: str, subject: str, body: str) -> None:
            seen.append(threading.current_thread().name)
            if self.fail:
                raise OSError("geheim-wachtwoord-in-fout")

    s = Sender()
    mail_service.set_sender(s)
    assert await mail_service.send_async("a@example.org", "x", "y") is True
    assert seen and seen[0] != threading.main_thread().name  # niet op de event-loop-thread
    s.fail = True
    with caplog.at_level(logging.ERROR, logger="horsesafe.mail"):
        assert await mail_service.send_async("a@example.org", "x", "y") is False
    assert "geheim-wachtwoord-in-fout" not in caplog.text  # alleen het fouttype


async def test_magic_link_goes_through_smtp_mailer(
    client: AsyncClient, smtp_env: type[FakeSMTP]
) -> None:
    email = "magic-smtp@example.com"
    await client.post(
        "/auth/register", json={"email": email, "password": VALID_PW, "ack_data_loss": True}
    )
    r = await client.post("/auth/magic-link", json={"email": email})
    assert r.status_code == 200
    (s,) = smtp_env.instances
    assert "starttls" in s.calls
    msg = s.messages[0]
    assert msg["From"] == "info@example.org" and msg["To"] == email
    assert re.search(r"/mfa\.html#ml=[\w\-]+", msg.get_content())


async def test_notify_user_failure_audited(client: AsyncClient) -> None:
    from backend.config import get_settings
    from backend.db.connection import connect
    from backend.services import mail_service
    from backend.services import vault_key_service as svc

    class Broken:
        def send(self, *_a: object) -> None:
            raise OSError("weg")

    await client.post(
        "/auth/register",
        json={"email": "n@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    async with connect(get_settings().db_path) as conn:
        uid = str((await (await conn.execute("SELECT id FROM users")).fetchone())["id"])
    mail_service.set_sender(Broken())
    ok = await svc.notify_user("n@example.com", "s", "b", user_id=uid, event="vault_key_add")
    assert ok is False
    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute("SELECT detail FROM audit_log WHERE event = 'notify_failed'")
        rows = [r["detail"] for r in await cur.fetchall()]
    assert rows == ['{"event": "vault_key_add"}']
