from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

B64URL = r"^[A-Za-z0-9_-]+$"
B64URL_32 = r"^[A-Za-z0-9_-]{43}$"  # 32 bytes zonder padding


class VaultKeyCreate(BaseModel):
    kind: Literal["bio", "recovery"]
    label: str = Field(min_length=1, max_length=64)
    credential_id: str = Field(min_length=16, max_length=1366, pattern=B64URL)
    prf_salt: str = Field(pattern=B64URL_32)
    public_key: str = Field(pattern=B64URL_32)
    sealed: str = Field(min_length=20, max_length=16384)


class VaultKeyReseal(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    sealed: str = Field(min_length=20, max_length=16384)


class VaultKeyResealBatch(BaseModel):
    items: list[VaultKeyReseal] = Field(min_length=1, max_length=20)


class VaultKeyPublic(BaseModel):
    """Wat de browser nodig heeft om te ontgrendelen — nooit de verzegelde kopie zelf."""

    id: str
    kind: Literal["bio", "recovery"]
    label: str
    credential_id: str
    prf_salt: str
    public_key: str
    created_at: int
    updated_at: int
    last_used_at: int | None = None
    release_requested_at: int | None = None
    release_at: int | None = None
    release_until: int | None = None


class VaultKeySealed(BaseModel):
    id: str
    sealed: str
