"""Pydantic-modellen voor ``POST /webauthn/options`` en ``POST /auth/stepup`` (v0.2.0-Koblitz)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .vault_key import AssertionResponse, KeyKind, UuidStr


class WebAuthnOptionsRequest(BaseModel):
    """§12.6.0: ``vault_id`` verplicht bij register/unlock, verboden bij stepup;
    ``kind`` alleen en verplicht bij register. Afwijking → 422."""

    model_config = ConfigDict(extra="forbid")

    purpose: Literal["register", "unlock", "stepup"]
    vault_id: UuidStr | None = None
    kind: KeyKind | None = None

    @model_validator(mode="after")
    def _fields_per_purpose(self) -> WebAuthnOptionsRequest:
        if self.purpose in ("register", "unlock") and self.vault_id is None:
            raise ValueError("vault_id is verplicht bij register en unlock")
        if self.purpose == "stepup" and self.vault_id is not None:
            raise ValueError("vault_id is niet toegestaan bij stepup")
        if self.purpose == "register" and self.kind is None:
            raise ValueError("kind is verplicht bij register")
        if self.purpose != "register" and self.kind is not None:
            raise ValueError("kind is alleen toegestaan bij register")
        return self


class StepupBio(AssertionResponse):
    method: Literal["bio"]


class StepupTotp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["totp"]
    code: Annotated[str, StringConstraints(min_length=1, max_length=16)]


StepupRequest = Annotated[StepupBio | StepupTotp, Field(discriminator="method")]
