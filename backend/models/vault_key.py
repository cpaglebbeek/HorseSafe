"""Pydantic-modellen voor hardware-sleutels (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.

Alle binaire velden zijn base64url zonder padding ("b64u"). ``kind`` is een ``Literal`` zonder
``phone``: de Koblitz-API weigert telefoonsleutels met 422 (§12.15).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

B64URL = r"^[A-Za-z0-9_-]+$"
B64URL_32 = r"^[A-Za-z0-9_-]{43}$"  # 32 bytes zonder padding
UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

KeyKind = Literal["bio", "recovery"]
UuidStr = Annotated[str, StringConstraints(pattern=UUID_RE)]
CredentialId = Annotated[str, StringConstraints(min_length=16, max_length=1366, pattern=B64URL)]
Label = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
Sealed = Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ─────────────── WebAuthn-responses van de browser ───────────────


class AttestationResponse(_Strict):
    """Resultaat van ``navigator.credentials.create`` (registratie)."""

    challenge_id: UuidStr
    credential_id: CredentialId
    client_data_json: str = Field(min_length=1, max_length=4096, pattern=B64URL)
    attestation_object: str = Field(min_length=1, max_length=16384, pattern=B64URL)
    transports: list[Annotated[str, StringConstraints(max_length=32)]] | None = Field(
        default=None, max_length=8
    )


class AssertionResponse(_Strict):
    """Resultaat van ``navigator.credentials.get`` (register-assert, unlock, step-up)."""

    challenge_id: UuidStr
    credential_id: CredentialId
    client_data_json: str = Field(min_length=1, max_length=4096, pattern=B64URL)
    authenticator_data: str = Field(min_length=1, max_length=1024, pattern=B64URL)
    signature: str = Field(min_length=1, max_length=1024, pattern=B64URL)
    user_handle: str | None = Field(default=None, max_length=1024, pattern=B64URL)


# ─────────────── Requests ───────────────


class VaultKeyCreate(_Strict):
    """``POST /vault/{vid}/keys`` (§12.6.1).

    ``prf_salt`` komt uit de challenge-rij, niet van de client."""

    key_id: UuidStr
    kind: KeyKind
    label: Label
    create: AttestationResponse
    assert_: AssertionResponse = Field(alias="assert")
    public_key: str = Field(pattern=B64URL_32)
    sealed: Sealed

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class UnlockRequest(AssertionResponse):
    """``POST /vault/{vid}/keys/{kid}/unlock`` (§12.6.2)."""


class VaultKeyReseal(_Strict):
    id: UuidStr
    sealed: Sealed


class VaultKeyResealBatch(_Strict):
    items: list[VaultKeyReseal] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def _unique_ids(self) -> VaultKeyResealBatch:
        ids = [it.id for it in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("ids moeten uniek zijn")
        return self


class RekeySealed(_Strict):
    """Het ``sealed``-veld van ``PUT /vault/{vid}/rekey`` (JSON-string in multipart)."""

    items: list[VaultKeyReseal] = Field(max_length=50)


# ─────────────── Responses ───────────────


class RecoveryInfo(BaseModel):
    state: Literal["idle", "waiting", "released", "consumed", "expired", "blocked"]
    release_requested_at: int | None = None
    release_at: int | None = None
    release_until: int | None = None
    release_consumed_at: int | None = None
    blocked_at: int | None = None
    blocked_by: str | None = None


class VaultKeyPublic(BaseModel):
    """Het sleutelobject (§12.6.3) — nooit ``sealed``, ``cose_public_key`` of ``sign_count``."""

    id: str
    kind: KeyKind
    label: str
    status: Literal["active", "blocked"]
    credential_id: str
    prf_salt: str
    public_key: str
    aaguid: str | None = None
    authenticator: str | None = None
    created_at: int
    updated_at: int
    last_used_at: int | None = None
    recovery: RecoveryInfo | None = None


class VaultKeyList(BaseModel):
    keys: list[VaultKeyPublic]
    notify_available: bool
    stepup_until: int | None = None


class VaultKeySealed(BaseModel):
    id: str
    sealed: str
