from __future__ import annotations

import base64
import hmac
import os
import time

import aiosqlite
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import get_settings


def _get_aes_key() -> bytes | None:
    """Decodeer 32-byte hex key uit env. None bij leeg (dev-fallback = plaintext)."""
    settings = get_settings()
    if not settings.totp_encryption_key:
        return None
    key = bytes.fromhex(settings.totp_encryption_key)
    if len(key) != 32:
        raise ValueError("totp_encryption_key must be 32 bytes (64 hex chars)")
    return key


def encrypt_secret(secret_base32: str) -> str:
    """Encrypt TOTP-secret at rest met AES-GCM (12-byte nonce || ciphertext || tag).

    Bij geen sleutel: return plaintext met 'plain:'-prefix (test/dev).
    """
    key = _get_aes_key()
    if key is None:
        return f"plain:{secret_base32}"
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, secret_base32.encode("ascii"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_secret(stored: str) -> str:
    """Decrypt stored TOTP-secret terug naar base32."""
    if stored.startswith("plain:"):
        return stored[len("plain:") :]
    key = _get_aes_key()
    if key is None:
        raise ValueError("totp_encryption_key not configured but stored secret is encrypted")
    blob = base64.urlsafe_b64decode(stored.encode("ascii"))
    nonce, ct = blob[:12], blob[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None).decode("ascii")


def generate_secret() -> str:
    """Genereer nieuw base32 TOTP-secret (RFC 6238)."""
    return pyotp.random_base32()


def provisioning_uri(secret_base32: str, account_email: str) -> str:
    """Geef otpauth://-URL terug voor QR-code-render in browser."""
    settings = get_settings()
    return pyotp.TOTP(secret_base32).provisioning_uri(
        name=account_email, issuer_name=settings.totp_issuer
    )


def verify_code(secret_base32: str, code: str, valid_window: int = 1) -> bool:
    """Verifieer 6-cijfercode binnen ±valid_window * 30s."""
    if not code.isdigit() or len(code) != 6:
        return False
    return bool(pyotp.TOTP(secret_base32).verify(code, valid_window=valid_window))


def totp_now() -> float:
    """Klok voor TOTP-tijdstappen (losse functie zodat tests hem kunnen verzetten)."""
    return time.time()


def matched_step(
    secret_base32: str, code: str, valid_window: int = 1, t: float | None = None
) -> int | None:
    """Als ``verify_code``, maar geeft de TOTP-tijdstap (``unix // 30``) die klopte, anders None.

    v0.4.0-Montgomery: nodig voor replay-bescherming (een code geldt maar één keer)."""
    if not code.isascii() or not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret_base32)
    step = int((totp_now() if t is None else t) // totp.interval)
    for off in range(-valid_window, valid_window + 1):
        if hmac.compare_digest(totp.generate_otp(step + off), code):
            return step + off
    return None


TOTP_USED_TTL = 3600  # oudere tijdstappen zijn toch buiten het venster (±30 s)


async def use_step_in_tx(conn: aiosqlite.Connection, user_id: str, step: int) -> bool:
    """Leg tijdstap ``step`` vast als gebruikt; False = al gebruikt of ouder dan de laatst
    gebruikte (RFC 6238 §5.2). Moet BINNEN een schrijftransactie (``BEGIN IMMEDIATE``) van de
    aanroeper lopen: dan is controle + INSERT atomair, ook bij parallelle verzoeken. Geen commit."""
    cur = await conn.execute("SELECT MAX(step) AS s FROM totp_used WHERE user_id = ?", (user_id,))
    row = await cur.fetchone()
    if row and row["s"] is not None and int(row["s"]) >= step:
        return False
    try:
        await conn.execute(
            "INSERT INTO totp_used (user_id, step, used_at) VALUES (?, ?, ?)",
            (user_id, step, int(time.time())),
        )
    except aiosqlite.IntegrityError:
        return False
    return True


async def use_step(conn: aiosqlite.Connection, user_id: str, step: int) -> bool:
    """``use_step_in_tx`` in een eigen transactie (step-up, MFA-challenge). Ruimt oude rijen op."""
    await conn.execute("BEGIN IMMEDIATE")
    try:
        await conn.execute(
            "DELETE FROM totp_used WHERE used_at < ?", (int(time.time()) - TOTP_USED_TTL,)
        )
        ok = await use_step_in_tx(conn, user_id, step)
        if ok:
            await conn.commit()
        else:
            await conn.rollback()
    except BaseException:
        await conn.rollback()
        raise
    return ok


async def set_user_totp(conn: aiosqlite.Connection, user_id: str, secret_base32: str) -> None:
    """Sla TOTP-secret op (encrypted at rest indien key gezet)."""
    stored = encrypt_secret(secret_base32)
    await conn.execute(
        "UPDATE users SET totp_secret = ? WHERE id = ?",
        (stored, user_id),
    )
    await conn.commit()


async def remove_user_totp(conn: aiosqlite.Connection, user_id: str) -> None:
    await conn.execute(
        "UPDATE users SET totp_secret = NULL WHERE id = ?",
        (user_id,),
    )
    await conn.commit()


async def get_user_totp(conn: aiosqlite.Connection, user_id: str) -> str | None:
    """Return decrypted base32 secret of None als user geen TOTP heeft."""
    cursor = await conn.execute(
        "SELECT totp_secret FROM users WHERE id = ?",
        (user_id,),
    )
    row = await cursor.fetchone()
    if not row or not row["totp_secret"]:
        return None
    return decrypt_secret(str(row["totp_secret"]))


async def user_has_totp(conn: aiosqlite.Connection, user_id: str) -> bool:
    cursor = await conn.execute(
        "SELECT 1 FROM users WHERE id = ? AND totp_secret IS NOT NULL",
        (user_id,),
    )
    row = await cursor.fetchone()
    return row is not None


def now_ts() -> int:
    return int(time.time())
