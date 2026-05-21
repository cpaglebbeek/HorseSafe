from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class KeypairSet(BaseModel):
    """Frontend uploadt pubkey + encrypted_privkey (beide base64 JSON)."""

    pubkey: str = Field(min_length=20, max_length=2000)
    encrypted_privkey: str = Field(min_length=20, max_length=4000)


class KeypairRewrap(BaseModel):
    """Bij pw-change: nieuwe encrypted_privkey (zelfde pubkey blijft)."""

    encrypted_privkey: str = Field(min_length=20, max_length=4000)


class ShareCreate(BaseModel):
    to_email: EmailStr
    encrypted_payload: str = Field(min_length=20, max_length=200_000)
    title_hint: str | None = Field(default=None, max_length=200)


class ShareInboxItem(BaseModel):
    id: str
    from_email: EmailStr
    from_pubkey: str | None
    title_hint: str | None
    encrypted_payload: str
    created_at: int


class PubkeyResponse(BaseModel):
    user_id: str
    email: EmailStr
    pubkey: str
