"""WebAuthn-verificatie voor hardware-sleutels (v0.2.0-Koblitz) — docs/HARDWARE_KEYS.md §12.4.

Keuze: py_webauthn (``webauthn``) doet het cryptografische zware werk (CBOR/COSE, handtekeningen,
packed-attestation, certificaatketen tegen de gevendorde Yubico-roots). Deze module doet daar
omheen zelf de controles die py_webauthn niet (of niet met een eigen foutcode) doet, in de
volgorde van het contract, zodat de eerste fout de juiste code geeft:

- challenge alleen als SHA-256-hash in de DB (nooit de challenge zelf), atomair verbruikt;
- ``crossOrigin`` afwezig of false;
- vlaggen UP/UV/BE/BS/AT met eigen foutcodes (BE=0 en BS=0: alleen device-bound sleutels);
- alleen ``packed`` met ``x5c`` (geen self-attestation, geen ``none`` behalve in tests);
- lege rootlijst = fail-closed (py_webauthn zou de keten dan stil overslaan);
- AAGUID-extensie (1.3.6.1.4.1.45724.1.1.4) in het leafcertificaat verplicht en gelijk aan de
  AAGUID in authData (py_webauthn controleert dat niet bij ``packed``);
- AAGUID-allowlist (uit FIDO MDS3) per ``kind``;
- signCount-regressie zelf (py_webauthn krijgt ``credential_current_sign_count=0``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import aiosqlite
from cryptography import x509
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers import (
    decode_credential_public_key,
    parse_attestation_object,
    parse_authenticator_data,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import AttestationFormat, AuthenticatorData

from ..config import get_settings

logger = logging.getLogger("horsesafe.webauthn")

AAGUID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
ALLOWED_ALGS = (COSEAlgorithmIdentifier.EDDSA, COSEAlgorithmIdentifier.ECDSA_SHA_256)
MAX_OPEN_CHALLENGES = 10
CHALLENGE_PURGE_AFTER = 24 * 3600


class WebAuthnError(Exception):
    """Controle mislukt. ``code`` is de foutcode uit het contract; ``status`` de HTTP-status."""

    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


# ─────────────── base64url ───────────────


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or any(c in s for c in "=+/"):
        raise ValueError("geen base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError("geen base64url") from e


def _now() -> int:
    from . import vault_key_service

    return vault_key_service.now()


# ─────────────── Allowlist en roots ───────────────


@lru_cache(maxsize=8)
def _load_allowlist(path: str, mtime: float) -> dict[str, dict[str, str]]:  # noqa: ARG001
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = raw.get("aaguids", {})
    if not isinstance(entries, dict):
        raise ValueError("aaguids.json: 'aaguids' moet een object zijn")
    return {str(k).lower(): dict(v) for k, v in entries.items()}


def allowlist() -> dict[str, dict[str, str]]:
    """AAGUID → {class, description}. Ontbrekend of kapot bestand = lege lijst (fail-closed)."""
    p = Path(get_settings().aaguid_allowlist_path)
    try:
        return _load_allowlist(str(p), p.stat().st_mtime)
    except (OSError, ValueError) as e:
        logger.error("AAGUID-allowlist niet leesbaar (%s): %s", p, type(e).__name__)
        return {}


def authenticator_description(aaguid: str | None) -> str | None:
    if not aaguid:
        return None
    entry = allowlist().get(aaguid.lower())
    return str(entry["description"]) if entry and entry.get("description") else None


@lru_cache(maxsize=8)
def _load_roots(path: str, mtime: float) -> tuple[bytes, ...]:  # noqa: ARG001
    from cryptography.hazmat.primitives.serialization import Encoding

    certs = x509.load_pem_x509_certificates(Path(path).read_bytes())
    return tuple(c.public_bytes(Encoding.PEM) for c in certs)


def attestation_roots() -> list[bytes]:
    """PEM-certificaten (roots + FIDO-intermediates van Yubico). Leeg = fail-closed."""
    p = Path(get_settings().attestation_roots_path)
    try:
        return list(_load_roots(str(p), p.stat().st_mtime))
    except (OSError, ValueError) as e:
        logger.error("Attestation-roots niet leesbaar (%s): %s", p, type(e).__name__)
        return []


# ─────────────── Challenges ───────────────


def _hash_challenge(challenge: bytes) -> str:
    return hashlib.sha256(challenge).hexdigest()


async def purge_and_check_quota(conn: aiosqlite.Connection, user_id: str, needed: int) -> None:
    """Ruim challenges ouder dan een dag op; max 10 open challenges per gebruiker (429)."""
    t = _now()
    await conn.execute(
        "DELETE FROM webauthn_challenges WHERE expires_at < ?", (t - CHALLENGE_PURGE_AFTER,)
    )
    await conn.commit()
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM webauthn_challenges "
        "WHERE user_id = ? AND used_at IS NULL AND expires_at > ?",
        (user_id, t),
    )
    row = await cur.fetchone()
    if row and int(row["n"]) + needed > MAX_OPEN_CHALLENGES:
        raise WebAuthnError("too_many_challenges", 429)


async def create_challenge(
    conn: aiosqlite.Connection,
    *,
    user_id: str,
    purpose: str,
    vault_id: str | None = None,
    kind: str | None = None,
    key_id: str | None = None,
    prf_salt: str | None = None,
    parent_id: str | None = None,
) -> tuple[str, str, int]:
    """Maak een challenge-rij. Return ``(challenge_id, challenge_b64u, expires_at)``.

    Alleen de hash wordt opgeslagen; de challenge zelf gaat één keer naar de browser.
    Caller commit.
    """
    t = _now()
    expires = t + get_settings().webauthn_challenge_ttl_seconds
    challenge = secrets.token_bytes(32)
    cid = str(uuid.uuid4())
    await conn.execute(
        """INSERT INTO webauthn_challenges
           (id, user_id, purpose, parent_id, vault_id, kind, key_id, prf_salt, challenge_hash,
            created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cid, user_id, purpose, parent_id, vault_id, kind, key_id, prf_salt,
         _hash_challenge(challenge), t, expires),
    )
    return cid, b64u_encode(challenge), expires


async def consume_challenge(
    conn: aiosqlite.Connection, challenge_id: str, user_id: str
) -> dict[str, Any]:
    """Markeer atomair als gebruikt (vóór alle andere controles) en geef de rij terug.

    Bestaat niet, al gebruikt, verlopen of van een andere gebruiker → ``invalid_challenge``.
    De caller controleert daarna purpose/vault/kind/key_id.
    """
    t = _now()
    cur = await conn.execute(
        "UPDATE webauthn_challenges SET used_at = ? "
        "WHERE id = ? AND user_id = ? AND used_at IS NULL AND expires_at > ?",
        (t, challenge_id, user_id, t),
    )
    await conn.commit()
    if cur.rowcount != 1:
        raise WebAuthnError("invalid_challenge")
    cur = await conn.execute("SELECT * FROM webauthn_challenges WHERE id = ?", (challenge_id,))
    row = await cur.fetchone()
    if row is None:  # pragma: no cover — net bijgewerkt
        raise WebAuthnError("invalid_challenge")
    return dict(row)


# ─────────────── Gedeelde controles ───────────────


def _client_data(client_data_b64u: str, expected_type: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = b64u_decode(client_data_b64u)
        cd = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise WebAuthnError("bad_client_data") from e
    if not isinstance(cd, dict) or cd.get("type") != expected_type:
        raise WebAuthnError("bad_client_data")
    if not isinstance(cd.get("challenge"), str) or not isinstance(cd.get("origin"), str):
        raise WebAuthnError("bad_client_data")
    return raw, cd


def _check_challenge(cd: dict[str, Any], challenge_row: dict[str, Any]) -> bytes:
    try:
        challenge = b64u_decode(cd["challenge"])
    except ValueError as e:
        raise WebAuthnError("invalid_challenge") from e
    if not secrets.compare_digest(_hash_challenge(challenge), str(challenge_row["challenge_hash"])):
        raise WebAuthnError("invalid_challenge")
    return challenge


def _check_origin(cd: dict[str, Any]) -> None:
    if cd["origin"] != get_settings().webauthn_origin:
        raise WebAuthnError("origin_mismatch")
    if cd.get("crossOrigin", False) is not False:
        raise WebAuthnError("origin_mismatch")


def _check_rp_and_flags(auth_data: AuthenticatorData, *, require_at: bool) -> None:
    expected = hashlib.sha256(get_settings().webauthn_rp_id.encode("utf-8")).digest()
    if not secrets.compare_digest(auth_data.rp_id_hash, expected):
        raise WebAuthnError("rp_id_mismatch")
    f = auth_data.flags
    if not f.up:
        raise WebAuthnError("up_missing")
    if not f.uv:
        raise WebAuthnError("uv_missing")
    if f.be or f.bs:
        raise WebAuthnError("not_device_bound")
    if require_at and (not f.at or auth_data.attested_credential_data is None):
        raise WebAuthnError("bad_authenticator_data")


# ─────────────── Registratie (create) ───────────────


@dataclass
class VerifiedCreate:
    credential_id: str  # b64u
    cose_public_key: str  # b64u
    aaguid: str
    att_fmt: str
    sign_count: int


def _leaf_aaguid(leaf_der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(leaf_der)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise WebAuthnError("attestation_invalid")
    except x509.ExtensionNotFound:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(AAGUID_OID).value
    except x509.ExtensionNotFound as e:
        raise WebAuthnError("attestation_invalid") from e
    value = getattr(ext, "value", b"")
    # extnValue = OCTET STRING (04 10) met de 16 AAGUID-bytes
    if len(value) != 18 or value[:2] != b"\x04\x10":
        raise WebAuthnError("attestation_invalid")
    return bytes(value[2:])


def verify_create(
    *,
    kind: str,
    credential_id: str,
    client_data_json: str,
    attestation_object: str,
    challenge_row: dict[str, Any],
) -> VerifiedCreate:
    """Controles 1-8 van §12.4 (stap 9, credential al bekend, doet de caller)."""
    settings = get_settings()
    cd_raw, cd = _client_data(client_data_json, "webauthn.create")  # 1
    challenge = _check_challenge(cd, challenge_row)  # 2
    _check_origin(cd)  # 3
    try:
        att_raw = b64u_decode(attestation_object)
        att = parse_attestation_object(att_raw)
    except Exception as e:  # noqa: BLE001 — elke parse-fout is een ongeldige attestation
        raise WebAuthnError("attestation_invalid") from e
    auth_data = att.auth_data
    _check_rp_and_flags(auth_data, require_at=True)  # 4 + 5
    acd = auth_data.attested_credential_data
    assert acd is not None
    if b64u_encode(acd.credential_id) != credential_id:
        raise WebAuthnError("credential_mismatch")
    try:  # 6
        alg = decode_credential_public_key(acd.credential_public_key).alg
    except Exception as e:  # noqa: BLE001
        raise WebAuthnError("bad_authenticator_data") from e
    if alg not in ALLOWED_ALGS:
        raise WebAuthnError("alg_not_allowed")

    # 7 — attestation
    fmt = att.fmt
    roots: list[bytes] = []
    if fmt == AttestationFormat.PACKED:
        if not att.att_stmt.x5c:
            raise WebAuthnError("attestation_invalid")  # self-attestation
        roots = attestation_roots()
        if not roots:
            raise WebAuthnError("attestation_invalid")  # fail-closed
    elif not (fmt == AttestationFormat.NONE and settings.test_attestation):
        raise WebAuthnError("attestation_invalid")
    credential = {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {"clientDataJSON": client_data_json, "attestationObject": attestation_object},
    }
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            require_user_presence=True,
            require_user_verification=True,
            supported_pub_key_algs=list(ALLOWED_ALGS),
            pem_root_certs_bytes_by_fmt={AttestationFormat.PACKED: roots} if roots else None,
        )
    except InvalidRegistrationResponse as e:
        logger.info("Attestation afgewezen: %s", e)
        raise WebAuthnError("attestation_invalid") from e
    aaguid_bytes = bytes(acd.aaguid)
    if fmt == AttestationFormat.PACKED:
        x5c = att.att_stmt.x5c
        assert x5c
        if _leaf_aaguid(bytes(x5c[0])) != aaguid_bytes:
            raise WebAuthnError("attestation_invalid")
    aaguid = str(uuid.UUID(bytes=aaguid_bytes))

    # 8 — allowlist (testuitzondering: overslaan, AAGUID wel opslaan)
    if not settings.test_attestation:
        entry = allowlist().get(aaguid)
        cls = entry.get("class") if entry else None
        if kind == "bio":
            if cls is None:
                raise WebAuthnError("authenticator_not_allowed")
            if cls != "bio":
                raise WebAuthnError("not_bio_authenticator")
        elif cls not in ("bio", "yubikey5"):
            raise WebAuthnError("authenticator_not_allowed")

    return VerifiedCreate(
        credential_id=credential_id,
        cose_public_key=b64u_encode(verified.credential_public_key),
        aaguid=aaguid,
        att_fmt=str(getattr(fmt, "value", fmt)),
        sign_count=int(verified.sign_count),
    )


# ─────────────── Assertion (get) ───────────────


def verify_assertion(
    *,
    credential_id: str,
    client_data_json: str,
    authenticator_data: str,
    signature: str,
    user_handle: str | None,
    challenge_row: dict[str, Any],
    cose_public_key: str,
    stored_sign_count: int,
) -> int:
    """Controles 1-6 van §12.4 voor een assertion. Return de nieuwe signCount.

    signCount-regressie geeft ``WebAuthnError('sign_count_regression', 409)``; de caller logt
    ``vault_key_clone_suspect`` en mailt.
    """
    settings = get_settings()
    _cd_raw, cd = _client_data(client_data_json, "webauthn.get")  # 1
    challenge = _check_challenge(cd, challenge_row)  # 2
    _check_origin(cd)  # 3
    try:
        auth_data = parse_authenticator_data(b64u_decode(authenticator_data))
    except Exception as e:  # noqa: BLE001
        raise WebAuthnError("bad_authenticator_data") from e
    _check_rp_and_flags(auth_data, require_at=False)  # 3 + 4
    response: dict[str, Any] = {
        "clientDataJSON": client_data_json,
        "authenticatorData": authenticator_data,
        "signature": signature,
    }
    if user_handle:
        response["userHandle"] = user_handle
    credential = {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": response,
    }
    try:  # 5
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=b64u_decode(cose_public_key),
            credential_current_sign_count=0,
            require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, ValueError) as e:
        logger.info("Assertion afgewezen: %s", type(e).__name__)
        raise WebAuthnError("assertion_invalid") from e
    new = int(verified.new_sign_count)
    if (stored_sign_count > 0 or new > 0) and new <= stored_sign_count:  # 6
        raise WebAuthnError("sign_count_regression", 409)
    return new
