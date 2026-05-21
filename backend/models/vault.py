from __future__ import annotations

from pydantic import BaseModel, Field


class VaultPublic(BaseModel):
    id: str
    name: str
    size_bytes: int
    etag: str
    created_at: int
    updated_at: int


class VaultCreateMeta(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[\w \-]+$")
