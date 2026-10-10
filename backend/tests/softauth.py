"""In-test software-authenticator voor WebAuthn (v0.2.0-Koblitz).

Bouwt echte ``clientDataJSON``, ``authenticatorData``, ``attestationObject`` (``packed`` met een
test-CA en AAGUID-extensie, of ``none``) en assertion-handtekeningen, zodat de server-verificatie
(py_webauthn + eigen controles) end-to-end getest wordt. Geen enkel geheim uit productie.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

AAGUID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

# Test-AAGUIDs (willekeurig gekozen, niet in de echte allowlist)
AAGUID_BIO = uuid.UUID("11111111-2222-4333-8444-555555555551")
AAGUID_YK5 = uuid.UUID("11111111-2222-4333-8444-555555555552")
AAGUID_OTHER = uuid.UUID("11111111-2222-4333-8444-555555555553")

RP_ID = "localhost"
ORIGIN = "http://localhost:3997"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _name(cn: str, ou: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HorseSafe Test"),
    ]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


class TestCA:
    """Self-signed test-root die packed-attestation-leafs uitgeeft."""

    __test__ = False  # geen pytest-testklasse

    def __init__(self, cn: str = "HorseSafe Test FIDO Root") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(_name(cn))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )

    def pem(self) -> bytes:
        return self.cert.public_bytes(Encoding.PEM)

    def leaf(self, aaguid: bytes | None) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        b = (
            x509.CertificateBuilder()
            .subject_name(_name("HorseSafe Test Authenticator", "Authenticator Attestation"))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if aaguid is not None:
            b = b.add_extension(
                x509.UnrecognizedExtension(AAGUID_OID, b"\x04\x10" + aaguid), critical=False
            )
        cert = b.sign(self.key, hashes.SHA256())
        return key, cert.public_bytes(Encoding.DER)


def _cose(pub: Any, alg: int) -> bytes:
    if alg == -8:
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cbor2.dumps({1: 1, 3: -8, -1: 6, -2: raw})
    nums = pub.public_numbers()
    size = (pub.curve.key_size + 7) // 8
    crv = {-7: 1, -35: 2}[alg]
    return cbor2.dumps(
        {1: 2, 3: alg, -1: crv, -2: nums.x.to_bytes(size, "big"), -3: nums.y.to_bytes(size, "big")}
    )


@dataclass
class SoftAuthenticator:
    """Eén credential op een nep-YubiKey."""

    ca: TestCA
    aaguid: uuid.UUID = AAGUID_BIO
    alg: int = -7
    sign_count: int = 0
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    key: Any = None

    def __post_init__(self) -> None:
        if self.key is None:
            if self.alg == -8:
                self.key = ed25519.Ed25519PrivateKey.generate()
            elif self.alg == -35:
                self.key = ec.generate_private_key(ec.SECP384R1())
            else:
                self.key = ec.generate_private_key(ec.SECP256R1())

    @property
    def cred_id(self) -> str:
        return b64u(self.credential_id)

    def _sign(self, key: Any, data: bytes, alg: int) -> bytes:
        if alg == -8:
            return key.sign(data)
        h = hashes.SHA384() if alg == -35 else hashes.SHA256()
        return key.sign(data, ec.ECDSA(h))

    @staticmethod
    def client_data(
        typ: str, challenge: str, *, origin: str = ORIGIN, cross_origin: Any = None
    ) -> bytes:
        cd: dict[str, Any] = {"type": typ, "challenge": challenge, "origin": origin}
        if cross_origin is not None:
            cd["crossOrigin"] = cross_origin
        return json.dumps(cd, separators=(",", ":")).encode()

    @staticmethod
    def flags(*, up: bool = True, uv: bool = True, be: bool = False, bs: bool = False,
              at: bool = False) -> int:
        return (up << 0) | (uv << 2) | (be << 3) | (bs << 4) | (at << 6)

    def create(
        self,
        challenge: str,
        *,
        fmt: str = "packed",
        origin: str = ORIGIN,
        typ: str = "webauthn.create",
        cross_origin: Any = None,
        rp_id: str = RP_ID,
        up: bool = True,
        uv: bool = True,
        be: bool = False,
        bs: bool = False,
        leaf_aaguid: uuid.UUID | None | str = "same",
        bump: int = 0,
    ) -> dict[str, str]:
        """Resultaat van ``navigator.credentials.create`` in API-vorm (b64u-velden)."""
        self.sign_count += bump
        cdj = self.client_data(typ, challenge, origin=origin, cross_origin=cross_origin)
        cose = _cose(self.key.public_key(), self.alg)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self.flags(up=up, uv=uv, be=be, bs=bs, at=True)])
            + struct.pack(">I", self.sign_count)
            + self.aaguid.bytes
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + cose
        )
        to_sign = auth_data + hashlib.sha256(cdj).digest()
        if fmt == "none":
            att_stmt: dict[str, Any] = {}
        elif fmt == "packed-self":
            fmt = "packed"
            att_stmt = {"alg": self.alg, "sig": self._sign(self.key, to_sign, self.alg)}
        else:
            if leaf_aaguid == "same":
                ext = self.aaguid.bytes
            elif leaf_aaguid is None:
                ext = None
            else:
                assert isinstance(leaf_aaguid, uuid.UUID)
                ext = leaf_aaguid.bytes
            leaf_key, leaf_der = self.ca.leaf(ext)
            att_stmt = {"alg": -7, "sig": self._sign(leaf_key, to_sign, -7), "x5c": [leaf_der]}
        att_obj = cbor2.dumps({"fmt": fmt, "attStmt": att_stmt, "authData": auth_data})
        return {
            "credential_id": self.cred_id,
            "client_data_json": b64u(cdj),
            "attestation_object": b64u(att_obj),
        }

    def get(
        self,
        challenge: str,
        *,
        origin: str = ORIGIN,
        typ: str = "webauthn.get",
        cross_origin: Any = None,
        rp_id: str = RP_ID,
        up: bool = True,
        uv: bool = True,
        be: bool = False,
        bs: bool = False,
        counter: int | None = None,
        bad_signature: bool = False,
    ) -> dict[str, Any]:
        """Resultaat van ``navigator.credentials.get`` in API-vorm (zonder challenge_id)."""
        if counter is None:
            self.sign_count += 1
            counter = self.sign_count
        cdj = self.client_data(typ, challenge, origin=origin, cross_origin=cross_origin)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self.flags(up=up, uv=uv, be=be, bs=bs)])
            + struct.pack(">I", counter)
        )
        sig = self._sign(self.key, auth_data + hashlib.sha256(cdj).digest(), self.alg)
        if bad_signature:
            sig = self._sign(self.key, b"iets anders", self.alg)
        return {
            "credential_id": self.cred_id,
            "client_data_json": b64u(cdj),
            "authenticator_data": b64u(auth_data),
            "signature": b64u(sig),
            "user_handle": None,
        }


def allowlist_json() -> str:
    return json.dumps({
        "source": "test",
        "mds_no": 0,
        "fetched_at": "2026-10-10",
        "aaguids": {
            str(AAGUID_BIO): {"class": "bio", "description": "Test YubiKey Bio"},
            str(AAGUID_YK5): {"class": "yubikey5", "description": "Test YubiKey 5"},
        },
    })
