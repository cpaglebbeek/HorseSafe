"""Pydantic-modellen voor telefoon koppelen (v0.3.4-Miller deel 2) — docs/HARDWARE_KEYS.md §13.

Alle binaire velden zijn base64url zonder padding ("b64u"). Tekstvelden van de claim gaan
letterlijk het transcript in (§13.1): daarom niet trimmen, en geen ``\\0``, andere stuurtekens,
opmaaktekens of losse surrogaten (zie ``_no_control``).
"""

from __future__ import annotations

import unicodedata
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from .vault_key import B64URL, B64URL_32, UuidStr

B64u43 = Annotated[str, StringConstraints(pattern=B64URL_32)]
SpkiB64u = Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=B64URL)]
CertB64u = Annotated[str, StringConstraints(min_length=1, max_length=4096, pattern=B64URL)]
Chain = Annotated[list[CertB64u], Field(min_length=2, max_length=6)]


# §13.5 stap 1: geweigerd zijn stuurtekens (Cc), Unicode-opmaaktekens (Cf, bv. U+202E die de
# leesrichting omdraait, of U+200B), losse surrogaten (Cs: niet als UTF-8 te coderen, anders een 500
# in transcript()) en de regel-/alineascheiders U+2028/U+2029 (Zl/Zp). Het label staat letterlijk
# in het transcript en wordt in web en app getoond; wat de gebruiker ziet moet zijn wat er staat.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _no_control(v: str) -> str:
    if any(unicodedata.category(c) in _FORBIDDEN_CATEGORIES for c in v):
        raise ValueError("stuur- of opmaaktekens zijn niet toegestaan")
    return v


NoCtrl = AfterValidator(_no_control)
ClaimLabel = Annotated[str, StringConstraints(min_length=1, max_length=64), NoCtrl]
ClaimModel = Annotated[str, StringConstraints(max_length=64), NoCtrl]
ClaimAppVersion = Annotated[str, StringConstraints(max_length=32), NoCtrl]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ─────────────── Requests ───────────────


class PairingStart(_Strict):
    """``POST /devices/pairings`` (§13.4). ``k_srv`` = HKDF(s, "HSv2 pair srv"); nooit ``s``."""

    vault_id: UuidStr
    k_srv: B64u43


class PairingClaim(_Strict):
    """``POST /devices/pairings/{id}/claim`` (§13.5 stap 1) — door de app, zonder sessie."""

    pk_c: B64u43
    k_dev_pub: SpkiB64u
    k_biosig_pub: SpkiB64u
    k_dev_chain: Chain
    k_biosig_chain: Chain
    label: ClaimLabel
    model: ClaimModel
    app_version: ClaimAppVersion
    mac_srv: B64u43
    mac_web: B64u43
    sig_biosig: Annotated[str, StringConstraints(min_length=1, max_length=120, pattern=B64URL)]


class PairingConfirm(_Strict):
    """``POST /devices/pairings/{id}/confirm`` — Seal_v2(pk_c, CK, "store", vault_id, key_id)."""

    sealed: Annotated[str, StringConstraints(min_length=1, max_length=1024)]


# ─────────────── Responses ───────────────


class PairingCreated(BaseModel):
    pairing_id: str
    expires_at: int


class ClaimPublic(BaseModel):
    """De claim zoals het web hem krijgt om ``mac_web`` en de SAS zelf te controleren."""

    device_id: str
    key_id: str
    pk_c: str
    k_dev_pub: str
    k_biosig_pub: str
    label: str
    model: str
    app_version: str
    mac_web: str
    security_level: str
    strongbox: bool


class PairingStatus(BaseModel):
    status: Literal["pending", "claimed", "confirmed", "cancelled"]
    expires_at: int
    claim: ClaimPublic | None = None


class ClaimResult(BaseModel):
    device_id: str
    sas: str


class DevicePublic(BaseModel):
    """Een toestel in ``GET /devices`` — zonder ketens en zonder publieke sleutels."""

    id: str
    label: str
    model: str | None = None
    state: Literal["pending", "active"]
    security_level: str
    strongbox: bool
    app_version: str | None = None
    created_at: int
    confirmed_at: int | None = None
    last_seen_at: int | None = None


class DeviceList(BaseModel):
    devices: list[DevicePublic]


class DeviceKeyRef(BaseModel):
    key_id: str
    vault_id: str
    label: str


class DeviceApprovalRef(BaseModel):
    """Open ontgrendelverzoek voor dit toestel (v0.4.0-Montgomery, §14.6)."""

    approval_id: str
    vault_id: str


class DeviceStatus(BaseModel):
    device_id: str
    state: Literal["pending", "active", "revoked"]
    keys: list[DeviceKeyRef]
    approvals: list[DeviceApprovalRef] = []


class DeviceSealed(BaseModel):
    key_id: str
    vault_id: str
    sealed: str
