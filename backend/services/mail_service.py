"""Generieke SMTP-mailer (v0.2.0-Koblitz, besluit 4 — docs/HARDWARE_KEYS.md §12.11).

Eén mailer voor de magic-link en voor de meldingen over hardware-sleutels.

- Voorkeur: ``SMTPSender`` (``smtplib.SMTP`` + STARTTLS op poort 587, met timeout).
- Fallback: ``GmailSMTPSender`` (SMTP_SSL 465). Werkt niet op HC55 (poort 465 dicht); alleen
  voor bestaande installaties met ``gmail_*``-settings.
- From = SMTP-gebruiker (Hostinger-regel MAIL_FROM = SMTP_USER).

Credentials staan alleen in de omgeving (``/opt/horsesafe/.env``); deze module logt ze nooit.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol

from ..config import get_settings

logger = logging.getLogger("horsesafe.mail")


class MailNotConfigured(RuntimeError):
    """Er is geen meldkanaal geconfigureerd."""


class EmailSender(Protocol):
    """Interface voor e-mailverzending — gemockt in tests."""

    def send(self, to_email: str, subject: str, body: str) -> None: ...


def _message(from_addr: str, to_email: str, subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["Date"] = formatdate(usegmt=True)
    msg["Message-ID"] = make_msgid(domain=from_addr.rpartition("@")[2] or None)
    msg.set_content(body)
    return msg


def smtp_configured() -> bool:
    s = get_settings()
    return bool(s.smtp_host and s.smtp_user and s.smtp_password)


def gmail_configured() -> bool:
    s = get_settings()
    return bool(s.gmail_user and s.gmail_app_password)


def from_address() -> str:
    """Afzender = SMTP-gebruiker. Een afwijkende ``smtp_from`` wordt genegeerd (zie warn_config)."""
    return get_settings().smtp_user


class SMTPSender:
    """SMTP met STARTTLS (standaard poort 587), login, send_message."""

    def send(self, to_email: str, subject: str, body: str) -> None:
        s = get_settings()
        if not smtp_configured():
            raise MailNotConfigured("SMTP niet geconfigureerd")
        msg = _message(from_address(), to_email, subject, body)
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds) as smtp:
            smtp.ehlo()
            if s.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            smtp.login(s.smtp_user, s.smtp_password)
            smtp.send_message(msg)


class GmailSMTPSender:
    """Fallback via Gmail SMTP_SSL (vereist App Password). Werkt niet op HC55."""

    def send(self, to_email: str, subject: str, body: str) -> None:
        s = get_settings()
        if not gmail_configured():
            raise MailNotConfigured("Gmail niet geconfigureerd")
        msg = _message(s.gmail_user, to_email, subject, body)
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(
            "smtp.gmail.com", 465, context=ctx, timeout=s.smtp_timeout_seconds
        ) as smtp:
            smtp.login(s.gmail_user, s.gmail_app_password)
            smtp.send_message(msg)


# Expliciet gezette zender (tests). None = kies op basis van de settings.
_override: EmailSender | None = None


def set_sender(sender: EmailSender | None) -> None:
    """Zet een vaste zender (tests); ``None`` herstelt de keuze op basis van de settings."""
    global _override
    _override = sender


def _resolve() -> EmailSender | None:
    if _override is not None:
        return _override
    if smtp_configured():
        return SMTPSender()
    if gmail_configured():
        return GmailSMTPSender()
    return None


def is_configured() -> bool:
    """Is er een meldkanaal? Bepaalt ``notify_available`` en of noodsleutel-vrijgave mag."""
    return _resolve() is not None


def send(to_email: str, subject: str, body: str) -> None:
    """Synchroon versturen; gooit bij elke fout (ook ``MailNotConfigured``)."""
    sender = _resolve()
    if sender is None:
        raise MailNotConfigured("geen meldkanaal geconfigureerd")
    sender.send(to_email, subject, body)


async def send_async(to_email: str, subject: str, body: str) -> bool:
    """Versturen buiten de event-loop (``asyncio.to_thread``). ``False`` bij elke fout.

    Nooit aanroepen binnen een open DB-verbinding of transactie.
    """
    if not is_configured():
        logger.warning("Melding niet verstuurd: geen meldkanaal geconfigureerd (%s)", subject)
        return False
    try:
        await asyncio.to_thread(send, to_email, subject, body)
    except Exception as e:  # noqa: BLE001 — een melding mag nooit credentials of stacktraces lekken
        logger.error("Melding versturen mislukt (%s): %s", subject, type(e).__name__)
        return False
    return True


def warn_config() -> None:
    """Bij app-start: waarschuw als ``smtp_from`` afwijkt van ``smtp_user`` (wordt genegeerd)."""
    s = get_settings()
    if s.smtp_from and s.smtp_user and s.smtp_from.strip().lower() != s.smtp_user.strip().lower():
        logger.warning(
            "HORSESAFE_SMTP_FROM wijkt af van HORSESAFE_SMTP_USER; From = SMTP-gebruiker wordt "
            "gebruikt (MAIL_FROM moet gelijk zijn aan SMTP_USER)."
        )
    if not smtp_configured() and gmail_configured():
        logger.warning("Mailer valt terug op Gmail SMTP_SSL (poort 465); werkt niet op HC55.")
    if not smtp_configured() and not gmail_configured():
        logger.warning("Geen mailer geconfigureerd: noodsleutel-vrijgave is uitgeschakeld.")
