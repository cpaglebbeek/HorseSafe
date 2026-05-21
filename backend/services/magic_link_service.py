from __future__ import annotations

import secrets
import smtplib
import ssl
import time
from email.message import EmailMessage
from typing import Protocol

import aiosqlite

from ..config import get_settings


class EmailSender(Protocol):
    """Interface voor e-mail verzending — gemockt in tests."""

    def send(self, to_email: str, subject: str, body: str) -> None: ...


class GmailSMTPSender:
    """Productie-zender via Gmail SMTP_SSL (vereist App Password)."""

    def send(self, to_email: str, subject: str, body: str) -> None:
        settings = get_settings()
        if not settings.gmail_user or not settings.gmail_app_password:
            raise RuntimeError(
                "Gmail credentials not configured (HORSESAFE_GMAIL_USER/APP_PASSWORD)"
            )
        msg = EmailMessage()
        msg["From"] = settings.gmail_user
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as s:
            s.login(settings.gmail_user, settings.gmail_app_password)
            s.send_message(msg)


# Global sender (kan gemockt worden in tests via monkeypatch).
_sender: EmailSender = GmailSMTPSender()


def set_sender(sender: EmailSender) -> None:
    global _sender
    _sender = sender


async def issue_magic_link(conn: aiosqlite.Connection, user_id: str, email: str) -> str | None:
    """Genereer + sla magic-link-token op, stuur e-mail. Return token (voor tests).

    Faalt stil (return None) als e-mail niet verzonden kan worden.
    """
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + settings.magic_link_ttl_minutes * 60
    await conn.execute(
        "INSERT INTO magic_links (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now, expires),
    )
    await conn.commit()

    link = f"{settings.public_url.rstrip('/')}/auth/magic-link/redeem?t={token}"
    body = (
        f"Hallo,\n\n"
        f"Klik op onderstaande link om in te loggen op HorseSafe. "
        f"De link is {settings.magic_link_ttl_minutes} minuten geldig "
        f"en kan eenmalig gebruikt worden.\n\n"
        f"{link}\n\n"
        f"Heb je deze e-mail niet aangevraagd? Negeer hem.\n\n"
        f"— HorseSafe (zero-knowledge wachtwoord-vault)"
    )
    try:
        _sender.send(email, "HorseSafe — inlog-link", body)
    except Exception:  # noqa: BLE001  # niet onthullen wáárom e-mail faalt
        return None
    return token


async def consume_magic_link(conn: aiosqlite.Connection, token: str) -> str | None:
    """Verzilver magic-link. Return user_id bij succes, None anders.

    Single-use + max 10 min geldig.
    """
    now = int(time.time())
    cursor = await conn.execute(
        """SELECT user_id, expires_at, redeemed_at
           FROM magic_links WHERE token = ?""",
        (token,),
    )
    row = await cursor.fetchone()
    if not row:
        return None
    if row["redeemed_at"] is not None:
        return None
    if int(row["expires_at"]) < now:
        return None
    await conn.execute(
        "UPDATE magic_links SET redeemed_at = ? WHERE token = ?",
        (now, token),
    )
    await conn.commit()
    return str(row["user_id"])
