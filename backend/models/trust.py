"""Pydantic-modellen voor vertrouwde browser + telefoonvinger (v0.4.0-Montgomery) — §14.

Veldnamen volgen het contract letterlijk (ook ``pub_B``, ``epk_L``, ``nonce_L``). Alle binaire
velden zijn b64u zonder padding. Het label gaat letterlijk ``bind_t`` in; daarom dezelfde tekenregel
als het toestellabel (§13.5.1) en niet trimmen.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .device import ClaimLabel, SpkiB64u
from .vault_key import B64URL_32, UuidStr

UUID4_LC = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
BrowserId = Annotated[str, StringConstraints(pattern=UUID4_LC)]
B64u43 = Annotated[str, StringConstraints(pattern=B64URL_32)]
SigRaw = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{86}$")]  # 64 B (r‖s)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ─────────────── Vertrouwde browsers (§14.3) ───────────────


class TrustedBrowserCreate(_Strict):
    """``POST /trusted-browsers`` (SU). ``proof`` = HMAC(k_bind, bind_t); de server kan het niet
    narekenen (geen CK) en bewaart het alleen voor de telefoon."""

    browser_id: BrowserId
    vault_id: UuidStr
    pub_B: SpkiB64u  # noqa: N815 — veldnaam uit het contract
    label: ClaimLabel
    proof: B64u43


class TrustedBrowserCreated(BaseModel):
    browser_id: str
    created_at: int


class TrustedBrowserPublic(BaseModel):
    browser_id: str
    vault_id: str
    label: str
    created_at: int
    last_used_at: int | None = None


class TrustedBrowserList(BaseModel):
    browsers: list[TrustedBrowserPublic]


# ─────────────── Inloggen op een vertrouwde browser (§14.4) ───────────────


class BrowserChallengeRequest(_Strict):
    email: Annotated[str, StringConstraints(min_length=1, max_length=320)]


class BrowserChallenge(BaseModel):
    challenge_id: str
    challenge: str
    expires_at: int


class BrowserLoginRequest(_Strict):
    """Bewust ruime vormregels: elke inhoudelijke fout wordt 401 ``browser_login_failed`` (en de
    challenge is dan al verbruikt), niet een 422 die verraadt welk veld niet klopte."""

    challenge_id: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    browser_id: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    sig: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    totp: Annotated[str, StringConstraints(min_length=1, max_length=16)]


# ─────────────── Ontgrendelverzoeken (§14.5) ───────────────


class ApprovalCreate(_Strict):
    browser_id: BrowserId


class ApprovalCreated(BaseModel):
    approval_id: str
    created_at: int


class ApprovalSubmit(_Strict):
    """``PUT /vault/{vid}/approvals/{id}``: e_L (X25519, 32 B), nonce_L (32 B), sig_req (64 B)."""

    epk_L: B64u43  # noqa: N815
    nonce_L: B64u43  # noqa: N815
    sig_req: SigRaw


class ApprovalSubmitted(BaseModel):
    expires_at: int


class DeviceDecision(_Strict):
    """``POST /device/v1/approvals/{id}`` — ``resp`` alleen (en verplicht) bij ``approve``."""

    decision: Literal["approve", "deny", "deny_revoke"]
    resp: Annotated[str, StringConstraints(min_length=1, max_length=1024)] | None = None
    reason: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,64}$")] | None = None


class ApprovalBrowser(BaseModel):
    browser_id: str
    pub_B: str  # noqa: N815
    label: str
    proof: str


class DeviceApproval(BaseModel):
    """Wat de telefoon krijgt (§14.5 stap 4). ``vault_name`` en ``expires_at`` zijn extra
    (alleen weergave); ``requested_at`` = moment waarop het verzoek ``pending`` werd."""

    approval_id: str
    vault_id: str
    vault_name: str | None = None
    key_id: str
    browser: ApprovalBrowser
    epk_L: str  # noqa: N815
    nonce_L: str  # noqa: N815
    created_at: int
    sig_req: str
    ip: str | None = None
    ua: str | None = None
    requested_at: int
    expires_at: int


class DeviceDecided(BaseModel):
    approval_id: str
    status: Literal["approved", "denied"]


WaitSeconds = Annotated[int, Field(ge=0, le=25)]
