from __future__ import annotations

import secrets
import time

import aiosqlite

from ..config import get_settings
from . import mail_service

# Compat: deze namen leefden hier vóór v0.2.0-Koblitz; de mailer zit nu in mail_service.
EmailSender = mail_service.EmailSender
GmailSMTPSender = mail_service.GmailSMTPSender

SUBJECT = "HorseSafe — inlog-link"


def set_sender(sender: mail_service.EmailSender | None) -> None:
    """Compat voor tests: delegeert naar de generieke mailer."""
    mail_service.set_sender(sender)


async def create_magic_link(conn: aiosqlite.Connection, user_id: str) -> tuple[str, str]:
    """Sla een nieuw magic-link-token op (gecommit). Return ``(token, mail-body)``.

    Versturen gebeurt los hiervan via ``send_magic_link``, buiten de DB-verbinding.
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
    return token, body


async def send_magic_link(email: str, body: str) -> bool:
    """Verstuur via de generieke mailer (niet-blokkerend). Faalt stil (``False``)."""
    return await mail_service.send_async(email, SUBJECT, body)


async def issue_magic_link(conn: aiosqlite.Connection, user_id: str, email: str) -> str | None:
    """Compat-wrapper: opslaan + versturen. Return token (voor tests) of None als mail faalt.

    Routes gebruiken liever create_magic_link + send_magic_link, zodat de mail buiten de
    DB-verbinding loopt.
    """
    token, body = await create_magic_link(conn, user_id)
    if not await send_magic_link(email, body):
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
