from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class TotpVerify(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class TotpSetupResponse(BaseModel):
    secret: str  # base32 (alleen tijdens setup, vóór verify)
    otpauth_url: str


class MagicLinkRequest(BaseModel):
    email: EmailStr
