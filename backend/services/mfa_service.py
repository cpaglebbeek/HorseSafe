from __future__ import annotations

import base64
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
