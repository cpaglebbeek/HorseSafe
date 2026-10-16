"""Nep-app voor telefoon koppelen (v0.3.4-Miller deel 2) — docs/HARDWARE_KEYS.md §13.

Gebruikt door pytest (Python-API) en door de Playwright-test ``frontend/tests/pairing.spec.ts`` (CLI).
Maakt K_dev/K_biosig (EC P-256) en ``sk_c`` (X25519), bouwt attestatieketens met een eigen test-CA en
een zelf ge-DER-de key-description-extensie (onafhankelijk van de parser in de server), het
transcript, ``mac_srv``/``mac_web``, ``sig_biosig``, en tekent device-requests (§13.6).

Testmateriaal: geen echte sleutels. De vaste test-root (``fake_device_root.pem``) heeft een
privésleutel die uit een publieke constante volgt; de server vertrouwt hem alleen met de testvlag
``HORSESAFE_TEST_DEVICE_ATTESTATION`` (die ``create_app()`` met de productie-rpId weigert).

CLI (laatste stdout-regel is JSON)::

    python -m backend.tests.fake_device claim  --api <base> --qr <hs1p:…> --label <l> --model <m> \\
        --state <file>                    → {"device_id": …, "sas": …}
    python -m backend.tests.fake_device status --api <base> --state <file>
                                          → {"state": …, "keys": […]}
    python -m backend.tests.fake_device sealed --api <base> --state <file> --key-id <kid>
                                          → {"key_id": …, "vault_id": …, "opened": true}
    python -m backend.tests.fake_device approve --api <base> --state <file> \
        [--decision approve|deny|deny_revoke] [--tamper-label] [--timeout 60]
                                          → {"approval_id": …, "decision": …, "reason": …,
                                             "status": "approved"|"denied", "label": …}
    python -m backend.tests.fake_device deny --api <base> --state <file> [--revoke]
                                          (= approve --decision deny | deny_revoke)

``approve`` (v0.4.0-Montgomery, §14.5): pollt ``/device/v1/status?wait=25`` tot er een verzoek is,
haalt het op, controleert ``sig_req`` met ``pub_B`` (vóór de "vinger"), opent de eigen store-kopie met
``sk_c``, weigert ``kh == null`` (``keyfile_required``), controleert ``proof`` met ``k_bind`` uit
``pt_ck`` (``browser_proof_invalid``) en verzegelt CK als Seal_v2 ``relay`` naar ``epk_L``. Een
mislukte controle wordt een ``deny`` met die reden. ``--tamper-label`` doet alsof de server een ander
label toonde: het koppelbewijs klopt dan niet en de nep-app weigert.

``<base>`` is de API-basis zonder ``/api``-pad van de server zelf, bv. ``http://127.0.0.1:3997``
(uvicorn direct) of ``https://icthorsecloud.nl/HorseSafe/api``. Getekend PATH = ``/api`` + endpoint.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
PACKAGE = "nl.icthorse.horsesafe"
RELEASE_SIGNER = "fbd6b151ecfd202279d9ee1999b4bfce7f7eb9095b1a0a5bf5338151a64b062e"
TEST_ROOT_PEM = Path(__file__).with_name("fake_device_root.pem")
_TEST_ROOT_SEED = b"HorseSafe fake_device test root (publiek testmateriaal)"

SOFTWARE, TEE, STRONGBOX = 0, 1, 2
VERIFIED, SELF_SIGNED, UNVERIFIED = 0, 1, 2


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def spki(key: Any) -> bytes:
    return bytes(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


# ─────────────── Minimale DER-encoder (bewust los van pyasn1 in de server) ───────────────


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: bytes, content: bytes) -> bytes:
    return tag + _len(len(content)) + content


def der_int(v: int, tag: int = 0x02) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(bytes([tag]), v.to_bytes(n, "big", signed=True))


def der_enum(v: int) -> bytes:
    return der_int(v, 0x0A)


def der_octet(b: bytes) -> bytes:
    return tlv(b"\x04", b)


def der_bool(v: bool) -> bytes:
    return tlv(b"\x01", b"\xff" if v else b"\x00")


def der_null() -> bytes:
    return b"\x05\x00"


def der_seq(*items: bytes) -> bytes:
    return tlv(b"\x30", b"".join(items))


def der_set(*items: bytes) -> bytes:
    return tlv(b"\x31", b"".join(sorted(items)))


def explicit(n: int, inner: bytes) -> bytes:
    if n < 31:
        ident = bytes([0xA0 | n])
    else:
        digits = []
        while True:
            digits.append(n & 0x7F)
            n >>= 7
            if not n:
                break
        digits.reverse()
        ident = bytes([0xBF]) + bytes([d | 0x80 for d in digits[:-1]] + [digits[-1]])
    return tlv(ident, inner)


# ─────────────── Key-description (attestation-extensie) ───────────────


@dataclass
class KeyProfile:
    """Wat de 'Keystore' van de nep-app attesteert. Standaard: een correcte TEE-sleutel."""

    role: str = "k_dev"  # "k_dev" | "k_biosig"
    attestation_level: int = TEE
    keymint_level: int = TEE
    boot_state: int = VERIFIED
    device_locked: bool = True
    packages: tuple[str, ...] = (PACKAGE,)
    signers: tuple[str, ...] = (RELEASE_SIGNER,)
    challenge: bytes | None = None  # None = de juiste att_challenge
    with_extension: bool = True
    with_root_of_trust: bool = True
    with_app_id: bool = True
    user_auth_type: int | None = None  # None = 2 bij k_biosig, afwezig bij k_dev
    no_auth_required: bool | None = None  # None = aan bij k_dev, uit bij k_biosig
    auth_timeout: int | None = None
    unlocked_device_required: bool | None = None  # None = aan bij k_dev
    extension_garbage: bool = False


def key_description(p: KeyProfile, challenge: bytes) -> bytes:
    biosig = p.role == "k_biosig"
    hw: dict[int, bytes] = {
        1: der_set(der_int(2)),  # purpose SIGN
        2: der_int(3),  # algorithm EC
        3: der_int(256),
        5: der_set(der_int(4)),  # digest SHA-256
        10: der_int(1),  # ecCurve P-256
        702: der_int(0),  # origin GENERATED
        705: der_int(150000),
        706: der_int(202609),
    }
    sw: dict[int, bytes] = {701: der_int(1_790_000_000_000)}
    uat = p.user_auth_type if p.user_auth_type is not None else (2 if biosig else None)
    nar = p.no_auth_required if p.no_auth_required is not None else not biosig
    udr = p.unlocked_device_required if p.unlocked_device_required is not None else not biosig
    enforced = sw if p.attestation_level == SOFTWARE else hw
    if uat is not None:
        enforced[504] = der_int(uat)
    if nar:
        enforced[503] = der_null()
    if p.auth_timeout is not None:
        enforced[505] = der_int(p.auth_timeout)
    if udr:
        sw[509] = der_null()
    if p.with_root_of_trust:
        enforced[704] = der_seq(
            der_octet(hashlib.sha256(b"verified boot key").digest()),
            der_bool(p.device_locked),
            der_enum(p.boot_state),
            der_octet(hashlib.sha256(b"vbmeta").digest()),
        )
    if p.with_app_id:
        app_id = der_seq(
            der_set(*(der_seq(der_octet(pkg.encode()), der_int(34)) for pkg in p.packages)),
            der_set(*(der_octet(bytes.fromhex(s)) for s in p.signers)),
        )
        sw[709] = der_octet(app_id)

    def auth_list(d: dict[int, bytes]) -> bytes:
        return der_seq(*(explicit(n, d[n]) for n in sorted(d)))

    return der_seq(
        der_int(300),
        der_enum(p.attestation_level),
        der_int(300),
        der_enum(p.keymint_level),
        der_octet(challenge),
        der_octet(b""),
        auth_list(sw),
        auth_list(hw),
    )


# ─────────────── Test-CA ───────────────


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HorseSafe Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _ca_cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: x509.Name | None,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool = True,
    days_valid: int = 3650,
) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer or _name(subject))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1 if days_valid > 0 else 10))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def test_root_key() -> ec.EllipticCurvePrivateKey:
    """Vaste test-root-sleutel uit een publieke constante (alleen testmateriaal)."""
    d = int.from_bytes(hashlib.sha256(_TEST_ROOT_SEED).digest(), "big")
    return ec.derive_private_key(d % (2**255), ec.SECP256R1())


class FakeAttestationCA:
    """Root → intermediate → leaf, zoals een Android-attestatieketen (leaf eerst)."""

    __test__ = False

    def __init__(self, *, fixed_root: bool = False, intermediate_expired: bool = False) -> None:
        if fixed_root:
            self.root_key = test_root_key()
            self.root = x509.load_pem_x509_certificate(TEST_ROOT_PEM.read_bytes())
            if spki(self.root.public_key()) != spki(self.root_key.public_key()):
                raise RuntimeError("fake_device_root.pem past niet bij de vaste test-sleutel")
        else:
            self.root_key = ec.generate_private_key(ec.SECP256R1())
            self.root = _ca_cert(
                "HorseSafe Test Attestation Root", self.root_key, None, self.root_key
            )
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.inter = _ca_cert(
            "HorseSafe Test TEE",
            self.inter_key,
            self.root.subject,
            self.root_key,
            days_valid=-2 if intermediate_expired else 3650,
        )

    def pem(self) -> bytes:
        return self.root.public_bytes(Encoding.PEM)

    def chain(
        self, pub: Any, ext: bytes | None, *, serial: int | None = None
    ) -> tuple[list[str], x509.Certificate]:
        now = dt.datetime.now(dt.UTC)
        b = (
            x509.CertificateBuilder()
            .subject_name(_name("Android Keystore Key"))
            .issuer_name(self.inter.subject)
            .public_key(pub)
            .serial_number(serial or 1)
            .not_valid_before(dt.datetime(1970, 1, 1, tzinfo=dt.UTC))
            .not_valid_after(now + dt.timedelta(days=365 * 20))
        )
        if ext is not None:
            b = b.add_extension(
                x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, ext), critical=False
            )
        leaf = b.sign(self.inter_key, hashes.SHA256())
        certs = [leaf, self.inter, self.root]
        return [b64u(c.public_bytes(Encoding.DER)) for c in certs], leaf


def make_test_root_pem() -> bytes:
    """Eenmalig gebruikt om ``fake_device_root.pem`` te maken (zie ``main``: ``make-root``)."""
    key = test_root_key()
    cert = _ca_cert("HorseSafe fake_device Test Root", key, None, key, days_valid=365 * 30)
    return cert.public_bytes(Encoding.PEM)


# ─────────────── Koppel-afleidingen (§13.1, eigen implementatie) ───────────────


def hkdf32(ikm: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info.encode()).derive(
        ikm
    )


def att_challenge(pairing_id: str, k_srv: bytes) -> bytes:
    return hashlib.sha256(b"HSv2 pair att\x00" + pairing_id.encode() + b"\x00" + k_srv).digest()


def transcript(pairing_id: str, f: dict[str, str]) -> bytes:
    parts = [
        "HSv2 pair",
        pairing_id,
        f["pk_c"],
        f["k_dev_pub"],
        f["k_biosig_pub"],
        f["label"],
        f["model"],
        f["app_version"],
    ]
    return "\x00".join(parts).encode("utf-8")


def sas(t: bytes) -> str:
    d = hashlib.sha256(b"HSv2 pair sas\x00" + t).digest()
    return f"{int.from_bytes(d[:4], 'big') % 1_000_000:06d}"


@dataclass
class WebSide:
    """De browserkant: geheim ``s`` (16 B), ``k_srv`` (naar de server) en ``k_web`` (blijft hier)."""

    s: bytes = field(default_factory=lambda: os.urandom(16))

    @property
    def k_srv(self) -> bytes:
        return hkdf32(self.s, "HSv2 pair srv")

    @property
    def k_web(self) -> bytes:
        return hkdf32(self.s, "HSv2 pair web")

    def qr(self, pairing_id: str) -> str:
        return f"hs1p:{pairing_id}.{b64u(self.s)}"

    def check_claim(self, pairing_id: str, claim: dict[str, Any]) -> str:
        """Controleer ``mac_web`` zoals het web; geeft de SAS."""
        t = transcript(pairing_id, claim)
        expect = hmac.new(self.k_web, t, hashlib.sha256).digest()
        if not hmac.compare_digest(expect, b64u_dec(claim["mac_web"])):
            raise ValueError("mac_web klopt niet")
        return sas(t)


def parse_qr(qr: str) -> tuple[str, bytes]:
    if not qr.startswith("hs1p:"):
        raise ValueError("geen hs1p-QR")
    pairing_id, s = qr[5:].split(".", 1)
    return pairing_id, b64u_dec(s)


# ─────────────── Montgomery-afleidingen (§14.2, eigen implementatie) ───────────────


def trust_k_bind(pt_ck: bytes, vault_id: str) -> bytes:
    salt = hashlib.sha256(b"HSv2 bind salt\x00" + vault_id.encode()).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"HSv2 browser bind").derive(
        pt_ck
    )


def trust_bind_t(vault_id: str, browser_id: str, pub_b: str, label: str) -> bytes:
    return "\x00".join(["HSv2 browser", vault_id, browser_id, pub_b, label]).encode("utf-8")


def trust_req_t(a: dict[str, Any]) -> bytes:
    """``req_t`` uit wat de telefoon van ``GET /device/v1/approvals/{id}`` krijgt."""
    return "\x00".join(
        [
            "HSv2 approve",
            a["approval_id"],
            a["vault_id"],
            a["browser"]["browser_id"],
            a["epk_L"],
            a["nonce_L"],
            str(a["created_at"]),
        ]
    ).encode("utf-8")


def verify_raw_p256(spki_b64u: str, sig_b64u: str, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        sig = b64u_dec(sig_b64u)
        if len(sig) != 64:
            return False
        key = serialization.load_der_public_key(b64u_dec(spki_b64u))
        assert isinstance(key, ec.EllipticCurvePublicKey)
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, AssertionError, InvalidSignature):
        return False
    return True


# ─────────────── De nep-app ───────────────


class FakeDevice:
    """Eén telefoon: sleutels, claim-body en getekende device-requests."""

    __test__ = False

    def __init__(
        self,
        ca: FakeAttestationCA,
        *,
        label: str = "Galaxy Z Fold6",
        model: str = "SM-F956B",
        app_version: str = "0.3.4-Miller",
        dev: KeyProfile | None = None,
        bio: KeyProfile | None = None,
    ) -> None:
        self.ca = ca
        self.label, self.model, self.app_version = label, model, app_version
        self.k_dev = ec.generate_private_key(ec.SECP256R1())
        self.k_biosig = ec.generate_private_key(ec.SECP256R1())
        self.sk_c = x25519.X25519PrivateKey.generate()
        self.dev_profile = dev or KeyProfile(role="k_dev")
        self.bio_profile = bio or KeyProfile(role="k_biosig")
        self.device_id: str | None = None
        self.dev_serial: int | None = None
        self.bio_serial: int | None = None

    @property
    def pk_c(self) -> str:
        return b64u(self.sk_c.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    @property
    def k_dev_pub(self) -> str:
        return b64u(spki(self.k_dev.public_key()))

    @property
    def k_biosig_pub(self) -> str:
        return b64u(spki(self.k_biosig.public_key()))

    def _chain(self, key: Any, p: KeyProfile, challenge: bytes) -> tuple[list[str], int]:
        ext = None
        if p.with_extension:
            ext = b"\x30\x03\x02\x01" if p.extension_garbage else key_description(p, challenge)
        serial = x509.random_serial_number()
        chain, _leaf = self.ca.chain(key.public_key(), ext, serial=serial)
        return chain, serial

    def claim_body(self, qr: str, **override: Any) -> tuple[str, dict[str, Any]]:
        """Body voor ``POST /devices/pairings/{id}/claim``. ``override`` vervangt velden ná het
        tekenen (om fouten te maken); ``k_srv=…`` / ``s=…`` kiest een ander geheim voor de MAC."""
        pairing_id, s = parse_qr(qr)
        s = override.pop("s", s)
        k_srv = override.pop("k_srv", hkdf32(s, "HSv2 pair srv"))
        k_web = hkdf32(s, "HSv2 pair web")
        chal = att_challenge(pairing_id, k_srv)
        dev_chain, self.dev_serial = self._chain(
            self.k_dev, self.dev_profile, self.dev_profile.challenge or chal
        )
        bio_chain, self.bio_serial = self._chain(
            self.k_biosig, self.bio_profile, self.bio_profile.challenge or chal
        )
        fields = {
            "pk_c": self.pk_c,
            "k_dev_pub": self.k_dev_pub,
            "k_biosig_pub": self.k_biosig_pub,
            "label": self.label,
            "model": self.model,
            "app_version": self.app_version,
        }
        sign_fields = {**fields, **{k: v for k, v in override.items() if k in fields}}
        t = transcript(pairing_id, override.pop("transcript_fields", sign_fields))
        body = {
            **fields,
            "k_dev_chain": dev_chain,
            "k_biosig_chain": bio_chain,
            "mac_srv": b64u(hmac.new(k_srv, t, hashlib.sha256).digest()),
            "mac_web": b64u(hmac.new(k_web, t, hashlib.sha256).digest()),
            "sig_biosig": b64u(self.k_biosig.sign(t, ec.ECDSA(hashes.SHA256()))),
        }
        body.update(override)
        return pairing_id, body

    def signed_headers(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        ts: int | None = None,
        nonce: str | None = None,
        key: ec.EllipticCurvePrivateKey | None = None,
    ) -> dict[str, str]:
        """§13.6: ``path`` is het endpoint (bv. ``/device/v1/status``); getekend wordt ``/api`` + path."""
        import time

        assert self.device_id, "eerst claimen"
        ts_s = str(int(time.time()) if ts is None else ts)
        nonce = nonce or b64u(os.urandom(16))
        msg = "\x00".join(
            [
                "HSv2 dev",
                method.upper(),
                "/api" + path,
                ts_s,
                nonce,
                b64u(hashlib.sha256(body).digest()),
            ]
        ).encode()
        sig = (key or self.k_dev).sign(msg, ec.ECDSA(hashes.SHA256()))
        return {
            "X-HS-Device": self.device_id,
            "X-HS-Ts": ts_s,
            "X-HS-Nonce": nonce,
            "X-HS-Sig": b64u(sig),
        }

    def open_sealed(self, sealed: str, vault_id: str, key_id: str) -> tuple[bytes | None, ...]:
        from . import seal_v2_ref as seal

        sk = self.sk_c.private_bytes(
            Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        return tuple(
            seal.unseal(sealed, sk, purpose="store", vault_id=vault_id, bind=key_id, kid=key_id)
        )

    def decide_body(
        self,
        approval: dict[str, Any],
        store_sealed: str,
        *,
        decision: str = "approve",
        tamper_label: bool = False,
    ) -> dict[str, Any]:
        """Wat de app doet bij een ontgrendelverzoek (§14.5 stap 4-5, §14.9). Geeft de POST-body.

        Volgorde: ``sig_req`` (vóór de vinger) → vinger (hier: ``sk_c`` uit de state) → eigen
        store-kopie openen (AAD met vault_id/key_id) → ``kh`` vereist → ``proof`` timing-safe →
        ``resp = Seal_v2(epk_L, CK, "relay", vault_id, approval_id ‖ 0 ‖ nonce_L)``."""
        from . import seal_v2_ref as seal

        a = json.loads(json.dumps(approval))  # kopie: --tamper-label wijzigt alleen lokaal
        if tamper_label:
            a["browser"]["label"] = a["browser"]["label"] + " (gewijzigd)"
        if not verify_raw_p256(a["browser"]["pub_B"], a["sig_req"], trust_req_t(a)):
            return {"decision": "deny", "reason": "sig_req_invalid"}
        if decision != "approve":
            return {"decision": decision, "reason": "user"}
        ph, kh = self.open_sealed(store_sealed, a["vault_id"], a["key_id"])
        if kh is None:
            return {"decision": "deny", "reason": "keyfile_required"}
        pt_ck = seal.plaintext(ph, kh)
        b = a["browser"]
        expect = hmac.new(
            trust_k_bind(pt_ck, a["vault_id"]),
            trust_bind_t(a["vault_id"], b["browser_id"], b["pub_B"], b["label"]),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expect, b64u_dec(b["proof"])):
            return {"decision": "deny", "reason": "browser_proof_invalid"}
        resp, _mid = seal.seal_with(
            b64u_dec(a["epk_L"]),
            ph,
            kh,
            purpose="relay",
            vault_id=a["vault_id"],
            bind=a["approval_id"] + "\x00" + a["nonce_L"],
            kid=a["approval_id"],
            ephemeral_sk=os.urandom(32),
            iv=os.urandom(12),
        )
        return {"decision": "approve", "resp": resp}

    # ── opslaan/laden voor de CLI ──
    def to_state(self) -> dict[str, Any]:
        def pem(k: Any) -> str:
            return k.private_bytes(
                Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode()

        return {
            "device_id": self.device_id,
            "k_dev": pem(self.k_dev),
            "k_biosig": pem(self.k_biosig),
            "sk_c": pem(self.sk_c),
            "label": self.label,
            "model": self.model,
            "app_version": self.app_version,
        }

    @classmethod
    def from_state(cls, st: dict[str, Any]) -> FakeDevice:
        d = cls.__new__(cls)

        def load(s: str) -> Any:
            return serialization.load_pem_private_key(s.encode(), password=None)

        d.k_dev, d.k_biosig, d.sk_c = load(st["k_dev"]), load(st["k_biosig"]), load(st["sk_c"])
        d.device_id = st["device_id"]
        d.label, d.model, d.app_version = st["label"], st["model"], st["app_version"]
        return d


def debug_profiles() -> tuple[KeyProfile, KeyProfile]:
    """Wat de testvlag toestaat: software-attestation, ``.debug``-package, willekeurige signer."""
    common = {
        "attestation_level": SOFTWARE,
        "keymint_level": SOFTWARE,
        "packages": (PACKAGE + ".debug",),
        "signers": (hashlib.sha256(b"debug-keystore (test)").hexdigest(),),
    }
    return KeyProfile(role="k_dev", **common), KeyProfile(role="k_biosig", **common)


# ─────────────── CLI (Playwright) ───────────────


def _http(method: str, url: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 — test-URL
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode("utf-8", "replace")


def _cli_claim(a: argparse.Namespace) -> dict[str, Any]:
    dev_p, bio_p = debug_profiles()
    d = FakeDevice(
        FakeAttestationCA(fixed_root=True), label=a.label, model=a.model, dev=dev_p, bio=bio_p
    )
    pairing_id, body = d.claim_body(a.qr)
    code, res = _http(
        "POST",
        f"{a.api.rstrip('/')}/devices/pairings/{pairing_id}/claim",
        json.dumps(body).encode(),
        {"Content-Type": "application/json"},
    )
    if code != 201:
        raise SystemExit(f"claim {code}: {res}")
    d.device_id = res["device_id"]
    Path(a.state).write_text(json.dumps(d.to_state()), encoding="utf-8")
    return {"device_id": res["device_id"], "sas": res["sas"]}


def _signed_get(a: argparse.Namespace, path: str) -> tuple[FakeDevice, Any]:
    d = FakeDevice.from_state(json.loads(Path(a.state).read_text(encoding="utf-8")))
    code, res = _http("GET", a.api.rstrip("/") + path, None, d.signed_headers("GET", path))
    if code != 200:
        raise SystemExit(f"GET {path} {code}: {res}")
    return d, res


def _cli_approve(a: argparse.Namespace) -> dict[str, Any]:
    """Zie de moduledocstring (``approve``/``deny``)."""
    import time

    deadline = time.monotonic() + a.timeout
    while True:
        wait = max(0, min(25, int(deadline - time.monotonic())))
        d, st = _signed_get(a, f"/device/v1/status?wait={wait}")
        if st.get("state") != "active":
            raise SystemExit(f"toestel niet actief: {st.get('state')}")
        if st.get("approvals"):
            break
        if time.monotonic() >= deadline:
            raise SystemExit("geen ontgrendelverzoek binnen de wachttijd")
    approval_id = st["approvals"][0]["approval_id"]
    _d, ap = _signed_get(a, f"/device/v1/approvals/{approval_id}")
    _d, store = _signed_get(a, f"/device/v1/keys/{ap['key_id']}/sealed")
    if store["vault_id"] != ap["vault_id"]:
        raise SystemExit("kopie hoort bij een andere kluis")
    body = d.decide_body(ap, store["sealed"], decision=a.decision, tamper_label=a.tamper_label)
    raw = json.dumps(body).encode()
    path = f"/device/v1/approvals/{approval_id}"
    headers = {"Content-Type": "application/json", **d.signed_headers("POST", path, raw)}
    code, res = _http("POST", a.api.rstrip("/") + path, raw, headers)
    if code != 200:
        raise SystemExit(f"POST {path} {code}: {res}")
    return {
        "approval_id": approval_id,
        "decision": body["decision"],
        "reason": body.get("reason"),
        "status": res["status"],
        "label": ap["browser"]["label"],
        "ip": ap.get("ip"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HorseSafe nep-app (alleen tests)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("claim")
    c.add_argument("--api", required=True)
    c.add_argument("--qr", required=True)
    c.add_argument("--label", default="Neptoestel")
    c.add_argument("--model", default="Pixel Test")
    c.add_argument("--state", required=True)
    s = sub.add_parser("status")
    s.add_argument("--api", required=True)
    s.add_argument("--state", required=True)
    k = sub.add_parser("sealed")
    k.add_argument("--api", required=True)
    k.add_argument("--state", required=True)
    k.add_argument("--key-id", required=True)
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("--api", required=True)
        p.add_argument("--state", required=True)
        p.add_argument("--timeout", type=float, default=60.0)
        p.add_argument("--tamper-label", action="store_true")
        if name == "approve":
            p.add_argument(
                "--decision", choices=("approve", "deny", "deny_revoke"), default="approve"
            )
        else:
            p.add_argument("--revoke", action="store_true", help="deny_revoke")
    sub.add_parser("make-root")
    a = ap.parse_args(argv)
    if a.cmd == "deny":
        a.decision = "deny_revoke" if a.revoke else "deny"
    if a.cmd == "claim":
        out: Any = _cli_claim(a)
    elif a.cmd == "status":
        _d, res = _signed_get(a, "/device/v1/status")
        out = {"state": res["state"], "keys": res["keys"]}
    elif a.cmd in ("approve", "deny"):
        out = _cli_approve(a)
    elif a.cmd == "sealed":
        d, res = _signed_get(a, f"/device/v1/keys/{a.key_id}/sealed")
        d.open_sealed(res["sealed"], res["vault_id"], res["key_id"])  # inhoud niet tonen
        out = {"key_id": res["key_id"], "vault_id": res["vault_id"], "opened": True}
    else:  # make-root: schrijf fake_device_root.pem (eenmalig)
        TEST_ROOT_PEM.write_bytes(make_test_root_pem())
        out = {"written": str(TEST_ROOT_PEM)}
    print(json.dumps(out))
    return 0


# Hergebruik in tests: KeyProfile-varianten
__all__ = [
    "FakeAttestationCA",
    "FakeDevice",
    "KeyProfile",
    "WebSide",
    "debug_profiles",
    "replace",
]


if __name__ == "__main__":
    sys.exit(main())
