"""Android key attestation voor telefoon koppelen (v0.3.4-Miller) — docs/HARDWARE_KEYS.md §13.5.

Controleert de attestatieketens van K_dev en K_biosig die de app bij de claim meestuurt:

- stap 4 — keten: elk certificaat getekend door het volgende, tussencertificaten zijn CA en
  geldig, het anker is een gevendorde Google hardware-attestation-root (vergeleken op publieke
  sleutel, zodat heruitgaven van dezelfde root ook passen), geen certificaat staat in de
  revocatielijst van Google (24 u schijfcache; niet ophaalbaar en geen cache → 503), en de
  leaf-sleutel is ``k_*_pub``;
- stap 5 — de key-description-extensie (OID 1.3.6.1.4.1.11129.2.1.17) van de leaf, met ``pyasn1``:
  challenge, beveiligingsniveau (TEE/StrongBox), RootOfTrust (Verified + vergrendeld),
  ``attestationApplicationId`` (package + signer-digest) en per sleutel de autorisaties.

Fouten geven ``attestation_invalid`` met een vaste ``reason`` (zie ``REASONS``). De server leert
hier niets geheims: alleen publieke sleutels en certificaten.

Waar de autorisaties staan (KeyMint): door de TEE/StrongBox afgedwongen eigenschappen
(``userAuthType``, ``rootOfTrust``) in ``hardwareEnforced``; door Keystore afgedwongen eigenschappen
(``unlockedDeviceRequired``) en ``attestationApplicationId`` in ``softwareEnforced``. Daarom:
``userAuthType`` en ``rootOfTrust`` alleen uit de afgedwongen lijst (bij software-attestation,
alleen met de testvlag, is dat ``softwareEnforced``); ``noAuthRequired``/``authTimeout`` mogen in
géén van beide staan; ``unlockedDeviceRequired`` en ``attestationApplicationId`` mogen in een van
beide staan.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import datetime as dt
import json
import logging
import os
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, tag, univ

from ..config import get_settings
from . import vault_key_service as svc

logger = logging.getLogger("horsesafe.android_attestation")

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

# SecurityLevel (KeyMint)
SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX = 0, 1, 2
LEVEL_NAMES = {
    SOFTWARE: "Software",
    TRUSTED_ENVIRONMENT: "TrustedEnvironment",
    STRONGBOX: "StrongBox",
}
# VerifiedBootState
VERIFIED = 0
# HardwareAuthenticatorType-bit voor biometrie (userAuthType)
HW_AUTH_BIOMETRIC = 2

# Tags van AuthorizationList (EXPLICIT, contextklasse)
TAG_NO_AUTH_REQUIRED = 503
TAG_USER_AUTH_TYPE = 504
TAG_AUTH_TIMEOUT = 505
TAG_UNLOCKED_DEVICE_REQUIRED = 509
TAG_ROOT_OF_TRUST = 704
TAG_ATTESTATION_APPLICATION_ID = 709

# Vaste reason-codes bij 400 attestation_invalid (§13.5 stap 4-5)
REASONS = (
    "chain_invalid",  # niet te parsen, handtekening, CA-vlag, geldigheid
    "root_untrusted",  # anker is geen gevendorde Google-root
    "revoked",  # certificaat in de revocatielijst (REVOKED of SUSPENDED)
    "key_mismatch",  # leaf-sleutel != k_*_pub
    "key_type",  # k_*_pub is geen EC P-256
    "extension_missing",  # geen key-description in de leaf
    "extension_invalid",  # key-description niet te parsen
    "challenge_mismatch",  # attestationChallenge != att_challenge
    "security_level",  # attestation- of keyMint-niveau niet TEE/StrongBox
    "root_of_trust_missing",
    "boot_unverified",  # verifiedBootState != Verified
    "device_unlocked",  # deviceLocked != true
    "app_id_missing",  # geen attestationApplicationId
    "package_mismatch",
    "signer_mismatch",
    "no_biometric",  # K_biosig: userAuthType zonder biometrie
    "no_auth_required",  # K_biosig: noAuthRequired aanwezig
    "auth_timeout",  # K_biosig: authTimeout aanwezig (niet per gebruik)
    "unlocked_device_required_missing",  # K_dev
)


class AttestationError(Exception):
    """Controle mislukt: ``code`` uit het contract; ``reason`` alleen bij attestation_invalid."""

    def __init__(self, code: str, reason: str | None = None, status: int = 400) -> None:
        super().__init__(code if reason is None else f"{code}:{reason}")
        self.code = code
        self.reason = reason
        self.status = status


def _invalid(reason: str) -> AttestationError:
    assert reason in REASONS, reason
    return AttestationError("attestation_invalid", reason)


# ─────────────── ASN.1 (pyasn1) ───────────────


class _RootOfTrust(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("verifiedBootKey", univ.OctetString()),
        namedtype.NamedType("deviceLocked", univ.Boolean()),
        namedtype.NamedType("verifiedBootState", univ.Enumerated()),
        namedtype.OptionalNamedType("verifiedBootHash", univ.OctetString()),  # vanaf versie 3
    )


class _PackageInfo(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("packageName", univ.OctetString()),
        namedtype.NamedType("version", univ.Integer()),
    )


class _AttestationApplicationId(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("packageInfos", univ.SetOf(componentType=_PackageInfo())),
        namedtype.NamedType("signatureDigests", univ.SetOf(componentType=univ.OctetString())),
    )


class _KeyDescription(univ.Sequence):  # type: ignore[misc]
    # AuthorizationList als lijst van losse getagde elementen: onbekende (nieuwere) tags breken het
    # parsen dan niet; de bekende tags worden hieronder per stuk met hun eigen type gedecodeerd.
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestationVersion", univ.Integer()),
        namedtype.NamedType("attestationSecurityLevel", univ.Enumerated()),
        namedtype.NamedType("keyMintVersion", univ.Integer()),
        namedtype.NamedType("keyMintSecurityLevel", univ.Enumerated()),
        namedtype.NamedType("attestationChallenge", univ.OctetString()),
        namedtype.NamedType("uniqueId", univ.OctetString()),
        namedtype.NamedType("softwareEnforced", univ.SequenceOf(componentType=univ.Any())),
        namedtype.NamedType("hardwareEnforced", univ.SequenceOf(componentType=univ.Any())),
    )


def _decode(data: bytes, spec: Any) -> Any:
    value, rest = der_decoder.decode(data, asn1Spec=spec)
    if rest:
        raise PyAsn1Error("restbytes na DER-waarde")
    return value


def _context_tag(tlv: bytes) -> int:
    """Tagnummer van een EXPLICIT [n]-element (contextklasse, constructed)."""
    if not tlv or tlv[0] & 0xE0 != 0xA0:
        raise PyAsn1Error("geen contextgetagd element")
    if tlv[0] & 0x1F != 0x1F:
        return tlv[0] & 0x1F
    n = 0
    for b in tlv[1:6]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            return n
    raise PyAsn1Error("tagnummer te lang")


def _explicit(n: int, inner: Any) -> Any:
    return inner.subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, n))


@dataclass(frozen=True)
class KeyDescription:
    attestation_version: int
    attestation_security_level: int
    keymint_security_level: int
    challenge: bytes
    software: dict[int, bytes]  # tag → volledige TLV
    hardware: dict[int, bytes]

    def enforced(self) -> dict[int, bytes]:
        """De lijst waarin de beveiligingsomgeving zelf afdwingt (bij software-attestation: sw)."""
        return self.software if self.attestation_security_level == SOFTWARE else self.hardware

    def has(self, n: int) -> bool:
        return n in self.software or n in self.hardware

    def get(self, lst: dict[int, bytes], n: int, inner: Any) -> Any:
        return _decode(lst[n], _explicit(n, inner))


def _auth_list(seq: Any) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    for item in seq:
        tlv = bytes(item)
        n = _context_tag(tlv)
        if n in out:
            raise PyAsn1Error(f"tag {n} dubbel")
        out[n] = tlv
    return out


def parse_key_description(cert: x509.Certificate) -> KeyDescription:
    try:
        ext = cert.extensions.get_extension_for_oid(KEY_DESCRIPTION_OID)
    except x509.ExtensionNotFound as e:
        raise _invalid("extension_missing") from e
    raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
    try:
        kd = _decode(raw, _KeyDescription())
        return KeyDescription(
            attestation_version=int(kd["attestationVersion"]),
            attestation_security_level=int(kd["attestationSecurityLevel"]),
            keymint_security_level=int(kd["keyMintSecurityLevel"]),
            challenge=bytes(kd["attestationChallenge"]),
            software=_auth_list(kd["softwareEnforced"]),
            hardware=_auth_list(kd["hardwareEnforced"]),
        )
    except (PyAsn1Error, ValueError, TypeError) as e:
        raise _invalid("extension_invalid") from e


# ─────────────── Roots en revocatielijst ───────────────


def _spki(key: Any) -> bytes:
    return bytes(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


_ROOTS_CACHE: dict[tuple[str, int], list[x509.Certificate]] = {}


def load_roots(path: Path | None = None) -> list[x509.Certificate]:
    """Gevendorde roots (fail-closed: ontbrekend of leeg bestand = geen vertrouwde root)."""
    p = Path(path or get_settings().android_attestation_roots_path)
    try:
        key = (str(p), p.stat().st_mtime_ns)
    except OSError:
        logger.error("Android-attestation-roots ontbreken: %s", p)
        return []
    if key not in _ROOTS_CACHE:
        if len(_ROOTS_CACHE) > 8:
            _ROOTS_CACHE.clear()
        _ROOTS_CACHE[key] = x509.load_pem_x509_certificates(p.read_bytes())
    return _ROOTS_CACHE[key]


def _status_cache_path() -> Path:
    s = get_settings()
    if s.android_attestation_status_cache_path is not None:
        return Path(s.android_attestation_status_cache_path)
    return Path(s.db_path).parent / "android_attestation_status.json"


def _fetch_status(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Haal de revocatielijst op (synchroon; via ``asyncio.to_thread``). Tests vervangen dit."""
    req = urllib.request.Request(url, headers={"User-Agent": "HorseSafe"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — vaste https-URL
        data = resp.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("revocatielijst te groot")
    return dict(json.loads(data))


def _entries(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict) or not isinstance(obj.get("entries"), dict):
        raise ValueError("revocatielijst zonder 'entries'")
    return {str(k).lower(): v for k, v in obj["entries"].items()}


def _read_cache(path: Path) -> tuple[int, dict[str, Any]] | None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return int(obj["fetched_at"]), _entries(obj)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_cache(path: Path, fetched_at: int, entries: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".attstatus-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": fetched_at, "entries": entries}, f)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


async def revocation_entries() -> dict[str, Any]:
    """Revocatielijst (sleutel = serienummer in kleine-letter-hex), met 24 u schijfcache.

    Verse cache → die. Anders ophalen en cachen. Ophalen mislukt → verouderde cache zolang die niet
    ouder is dan ``android_attestation_status_max_stale_seconds`` (standaard 7 dagen), anders 503
    ``attestation_status_unavailable``: een lijst van weken oud mist intussen ingetrokken sleutels.
    """
    s = get_settings()
    path = _status_cache_path()
    cached = _read_cache(path)
    t = svc.now()
    if cached and 0 <= t - cached[0] < s.android_attestation_status_ttl_seconds:
        return cached[1]
    try:
        entries = _entries(await asyncio.to_thread(_fetch_status, s.android_attestation_status_url))
    except Exception as e:  # netwerk, HTTP, JSON: allemaal "niet ophaalbaar"
        if cached and 0 <= t - cached[0] <= s.android_attestation_status_max_stale_seconds:
            logger.warning(
                "Revocatielijst niet ophaalbaar (%s); verouderde cache gebruikt", type(e)
            )
            return cached[1]
        if s.test_device_attestation:  # alleen tests (prod-guard in create_app)
            logger.warning("Revocatielijst niet ophaalbaar; testvlag: lege lijst")
            return {}
        logger.error(
            "Revocatielijst niet ophaalbaar en geen bruikbare cache (%s)", type(e).__name__
        )
        raise AttestationError("attestation_status_unavailable", status=503) from e
    try:
        _write_cache(path, t, entries)
    except OSError:
        logger.warning("Revocatielijst niet gecachet in %s", path)
    return entries


# ─────────────── Stap 4: keten ───────────────


def _b64u_decode(s: str) -> bytes:
    if any(c in s for c in "=+/"):
        raise ValueError("geen base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError("geen base64url") from e


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _valid_now(cert: x509.Certificate) -> bool:
    now = dt.datetime.now(dt.UTC)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def verify_chain(chain_b64u: list[str], roots: list[x509.Certificate]) -> list[x509.Certificate]:
    """Stap 4 (handtekeningen, CA-vlaggen, geldigheid, anker) voor één keten, leaf eerst."""
    try:
        certs = [x509.load_der_x509_certificate(_b64u_decode(c)) for c in chain_b64u]
    except ValueError as e:
        raise _invalid("chain_invalid") from e
    if len(certs) < 2:
        raise _invalid("chain_invalid")
    leaf = certs[0]
    if _is_ca(leaf):
        raise _invalid("chain_invalid")
    for child, parent in zip(certs, certs[1:], strict=False):
        if not _signed_by(child, parent):
            raise _invalid("chain_invalid")

    root_spkis = {_spki(r.public_key()) for r in roots}
    top = certs[-1]
    if _spki(top.public_key()) in root_spkis:
        # Het anker zelf (ook een heruitgave met dezelfde sleutel); geldigheid van een
        # vertrouwensanker telt niet (PKIX), die van de tussencertificaten wel.
        intermediates = certs[1:-1]
    else:
        anchor = next((r for r in roots if r.subject == top.issuer and _signed_by(top, r)), None)
        if anchor is None:
            raise _invalid("root_untrusted")
        intermediates = certs[1:]
    for c in intermediates:
        if not _is_ca(c) or not _valid_now(c):
            raise _invalid("chain_invalid")
        try:  # de key-description hoort alleen in de leaf
            c.extensions.get_extension_for_oid(KEY_DESCRIPTION_OID)
        except x509.ExtensionNotFound:
            continue
        raise _invalid("chain_invalid")
    return certs


def check_revocation(certs: list[x509.Certificate], revoked: dict[str, Any]) -> None:
    """Geen enkel certificaat van de keten in de revocatielijst (REVOKED of SUSPENDED)."""
    for c in certs:
        if format(c.serial_number, "x") in revoked:
            raise _invalid("revoked")


def load_p256_public_key(spki_b64u: str) -> ec.EllipticCurvePublicKey:
    """``k_*_pub`` (b64u van SPKI-DER) → EC P-256-sleutel; anders ``key_type``."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        key = load_der_public_key(_b64u_decode(spki_b64u))
    except ValueError as e:
        raise _invalid("key_type") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise _invalid("key_type")
    return key


# ─────────────── Stap 5: key-description ───────────────


def _norm_hex(s: str) -> str:
    return s.replace(":", "").strip().lower()


def check_key_description(kd: KeyDescription, *, att_challenge: bytes, role: str) -> None:
    """Stap 5 voor één sleutel; ``role`` is ``"k_dev"`` of ``"k_biosig"``."""
    s = get_settings()
    test = s.test_device_attestation
    if kd.challenge != att_challenge:
        raise _invalid("challenge_mismatch")
    allowed_levels = {TRUSTED_ENVIRONMENT, STRONGBOX} | ({SOFTWARE} if test else set())
    if (
        kd.attestation_security_level not in allowed_levels
        or kd.keymint_security_level not in allowed_levels
    ):
        raise _invalid("security_level")

    enforced = kd.enforced()
    try:
        if TAG_ROOT_OF_TRUST not in enforced:
            raise _invalid("root_of_trust_missing")
        rot = kd.get(enforced, TAG_ROOT_OF_TRUST, _RootOfTrust())
        if int(rot["verifiedBootState"]) != VERIFIED:
            raise _invalid("boot_unverified")
        if not bool(rot["deviceLocked"]):
            raise _invalid("device_unlocked")

        src = (
            kd.software
            if TAG_ATTESTATION_APPLICATION_ID in kd.software
            else kd.hardware if TAG_ATTESTATION_APPLICATION_ID in kd.hardware else None
        )
        if src is None:
            raise _invalid("app_id_missing")
        app_id_der = bytes(kd.get(src, TAG_ATTESTATION_APPLICATION_ID, univ.OctetString()))
        app_id = _decode(app_id_der, _AttestationApplicationId())
        packages = {bytes(p["packageName"]).decode("utf-8") for p in app_id["packageInfos"]}
        allowed_pkgs = {s.android_package} | ({s.android_package + ".debug"} if test else set())
        if len(packages) != 1 or not packages <= allowed_pkgs:
            raise _invalid("package_mismatch")
        digests = {bytes(d).hex() for d in app_id["signatureDigests"]}
        allowed_signers = {_norm_hex(x) for x in s.android_allowed_signers}
        if not test and (not digests or not digests <= allowed_signers):
            raise _invalid("signer_mismatch")

        if role == "k_biosig":
            if TAG_USER_AUTH_TYPE not in enforced:
                raise _invalid("no_biometric")
            auth_type = int(kd.get(enforced, TAG_USER_AUTH_TYPE, univ.Integer()))
            # Exact biometrie: 3 (biometrie óf PIN) zou de PIN-terugval toelaten die E2 verbiedt.
            if auth_type != HW_AUTH_BIOMETRIC:
                raise _invalid("no_biometric")
            if kd.has(TAG_NO_AUTH_REQUIRED):
                raise _invalid("no_auth_required")
            if kd.has(TAG_AUTH_TIMEOUT):
                raise _invalid("auth_timeout")
        elif role == "k_dev":
            if not kd.has(TAG_UNLOCKED_DEVICE_REQUIRED):
                raise _invalid("unlocked_device_required_missing")
        else:  # pragma: no cover — programmeerfout
            raise ValueError(role)
    except (PyAsn1Error, UnicodeDecodeError, ValueError, TypeError) as e:
        if isinstance(e, AttestationError):
            raise
        raise _invalid("extension_invalid") from e


# ─────────────── Samen: stap 4 + 5 voor beide sleutels ───────────────


@dataclass(frozen=True)
class AttestationResult:
    security_level: str  # het laagste niveau van beide sleutels: TrustedEnvironment | StrongBox
    strongbox: bool  # beide sleutels in StrongBox


async def verify_pair_attestation(
    *,
    k_dev_pub: str,
    k_dev_chain: list[str],
    k_biosig_pub: str,
    k_biosig_chain: list[str],
    att_challenge: bytes,
) -> AttestationResult:
    """§13.5 stap 4 (beide ketens) en daarna stap 5 (beide extensies); eerste fout wint."""
    dev_key = load_p256_public_key(k_dev_pub)
    bio_key = load_p256_public_key(k_biosig_pub)
    s = get_settings()
    roots = list(load_roots())
    if s.test_device_attestation:  # software-attestation (nep-app) heeft een eigen root
        roots += load_roots(s.android_attestation_test_roots_path)
    chains = [verify_chain(c, roots) for c in (k_dev_chain, k_biosig_chain)]
    revoked = await revocation_entries()  # pas na de structuurcontrole: geen netwerk voor rommel
    for certs, key in zip(chains, (dev_key, bio_key), strict=True):
        check_revocation(certs, revoked)
        if _spki(certs[0].public_key()) != _spki(key):
            raise _invalid("key_mismatch")
    kds = [parse_key_description(certs[0]) for certs in chains]
    for kd, role in zip(kds, ("k_dev", "k_biosig"), strict=True):
        check_key_description(kd, att_challenge=att_challenge, role=role)
    level = min(kd.attestation_security_level for kd in kds)
    return AttestationResult(security_level=LEVEL_NAMES[level], strongbox=level == STRONGBOX)
