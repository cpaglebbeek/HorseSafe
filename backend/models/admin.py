from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class AdminDeleteRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


class AdminRescueRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


class BackupCodeVerify(BaseModel):
    code: str = Field(min_length=8, max_length=20)


class MeResponse(BaseModel):
    id: str
    email: EmailStr
    is_admin: bool
    has_totp: bool
    backup_codes_remaining: int
    has_keypair: bool = False
    mfa_pass: bool
    last_login_at: int | None = None
