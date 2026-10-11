from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class TotpVerify(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class TotpSetupResponse(BaseModel):
    secret: str  # base32 (alleen tijdens setup, vóór verify)
    otpauth_url: str


class MagicLinkRequest(BaseModel):
    email: EmailStr


class MagicLinkRedeem(BaseModel):
    """Body van ``POST /auth/magic-link/redeem`` (token uit het fragment van ``mfa.html``)."""

    t: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_\-]+$")
