#!/usr/bin/env python3
"""Synthetische attestation-testvectoren voor attest/AttestationVerifier (HorseSafe 0.3.0-Miller deel 1).

ALLES HIER IS NEP: een eigen test-CA ("HorseSafe TEST Root CA - NIET VERTROUWEN"), nooit een
Yubico-root. De vectoren gaan alleen in de test-sourceset (android/app/src/test/resources/attest/).
Er worden geen privésleutels weggeschreven; opnieuw genereren maakt nieuwe sleutels.

Opnieuw maken (vanaf de repo-root, met een venv die `cryptography` en `cbor2` heeft):
    python -I android/app/src/test/tools/gen_attest_vectors.py

Uitvoer:
    android/app/src/test/resources/attest/test_roots.pem   (test-root + losse test-intermediate B)
    android/app/src/test/resources/attest/foreign_root.pem (vreemde CA, niet vertrouwd)
    android/app/src/test/resources/attest/vectors.json     (positief en negatief)

Elke negatieve vector bevat precies één fout, zodat de eerste fout de verwachte Stop geeft. Het
veld `expect` is "OK" of de naam van een `flow.Stop`; `reason` is `AttestationVerifier.Reason`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent.parent / "resources" / "attest"
AAGUID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
RP_ID = "keuring.horsesafe.invalid"

# Echte AAGUID's uit backend/data/aaguids.json (de klasse komt uit die lijst; de certificaten zijn nep).
AAGUID_BIO = "9dd8d593-2213-438a-97f8-d6b813d51c27"  # bio, Fido Edition
AAGUID_YK5 = "2fc0579f-8113-47ea-b116-bb5a8db9202a"  # yubikey5, 5 Series with NFC
AAGUID_UNLISTED = "00112233-4455-6677-8899-aabbccddeeff"

NB = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
NA = dt.datetime(2125, 1, 1, tzinfo=dt.timezone.utc)

UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80


def name(cn: str, ou: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HorseSafe TEST - NIET VERTROUWEN"),
    ]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def p256():
    return ec.generate_private_key(ec.SECP256R1())


def ca_cert(subject, pub, issuer, issuer_key, pathlen):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NB)
        .not_valid_after(NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    )
    return b.sign(issuer_key, hashes.SHA256())


def leaf_cert(pub, issuer, issuer_key, *, aaguid: str | None, ca=False, not_after=NA, aaguid_raw=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(name("HorseSafe TEST Attestation", "Authenticator Attestation"))
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NB)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aaguid_raw is not None:
        b = b.add_extension(x509.UnrecognizedExtension(AAGUID_OID, aaguid_raw), critical=False)
    elif aaguid is not None:
        b = b.add_extension(
            x509.UnrecognizedExtension(AAGUID_OID, b"\x04\x10" + uuid.UUID(aaguid).bytes), critical=False
        )
    return b.sign(issuer_key, hashes.SHA256())


def der(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.DER)


def pem(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def cose_es256(key: ec.EllipticCurvePrivateKey) -> bytes:
    n = key.public_key().public_numbers()
    return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})


def cose_eddsa(key: ed25519.Ed25519PrivateKey) -> bytes:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return cbor2.dumps({1: 1, 3: -8, -1: 6, -2: raw})


def auth_data(*, flags: int, aaguid: str, cose: bytes, rp_id: str = RP_ID, cred_id: bytes = b"\x42" * 32):
    out = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
    if flags & AT:
        out += uuid.UUID(aaguid).bytes + struct.pack(">H", len(cred_id)) + cred_id + cose
    return out


def sign_es256(key, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    root_key = p256()
    root_name = name("HorseSafe TEST Root CA - NIET VERTROUWEN")
    root = ca_cert(root_name, root_key.public_key(), root_name, root_key, 1)

    inter_a_key = p256()
    inter_a_name = name("HorseSafe TEST Intermediate A (in x5c)")
    inter_a = ca_cert(inter_a_name, inter_a_key.public_key(), root_name, root_key, 0)

    # B zit alleen in test_roots.pem (zoals Yubico's FIDO-intermediates in yubico_fido_roots.pem).
    inter_b_key = p256()
    inter_b_name = name("HorseSafe TEST Intermediate B (in roots-pem)")
    inter_b = ca_cert(inter_b_name, inter_b_key.public_key(), root_name, root_key, 0)

    foreign_key = p256()
    foreign_name = name("Vreemde TEST Root CA")
    foreign = ca_cert(foreign_name, foreign_key.public_key(), foreign_name, foreign_key, 1)
    foreign_inter_key = p256()
    foreign_inter = ca_cert(
        inter_a_name, foreign_inter_key.public_key(), foreign_name, foreign_key, 0
    )  # zelfde naam als A, andere sleutel en uitgever

    cred_key = p256()
    cose = cose_es256(cred_key)
    cdh = hashlib.sha256(b"HorseSafe TEST clientData").digest()

    vectors: list[dict] = []

    def add(
        vid: str,
        expect: str,
        reason: str | None,
        *,
        flags=UP | UV | AT,
        aaguid=AAGUID_BIO,
        expected_aaguid=None,
        expected_class="BIO",
        with_token=True,
        fmt="packed",
        leaf_key=None,
        leaf=None,
        chain_tail=None,
        alg=-7,
        cose_bytes=None,
        rp_id_in_auth=RP_ID,
        bad_sig=False,
        self_attest=False,
        auth=None,
        note="",
    ):
        lk = leaf_key or p256()
        lc = leaf or leaf_cert(lk.public_key(), inter_a_name, inter_a_key, aaguid=aaguid)
        ad = auth if auth is not None else auth_data(
            flags=flags, aaguid=aaguid, cose=cose_bytes or cose, rp_id=rp_id_in_auth
        )
        data = ad + cdh
        if fmt == "none":
            sig, x5c, alg_out = b"", [], None
        elif self_attest:
            sig, x5c, alg_out = sign_es256(cred_key, data), [], -7
        else:
            if isinstance(lk, ed25519.Ed25519PrivateKey):
                sig = lk.sign(data)
            elif isinstance(lk, rsa.RSAPrivateKey):
                from cryptography.hazmat.primitives.asymmetric import padding

                sig = lk.sign(data, padding.PKCS1v15(), hashes.SHA256())
            else:
                sig = sign_es256(lk, data)
            if bad_sig:
                sig = sign_es256(lk, data + b"\x00")
            tail = [inter_a] if chain_tail is None else chain_tail
            x5c = [der(lc)] + [der(c) for c in tail]
            alg_out = alg
        vectors.append(
            {
                "id": vid,
                "note": note,
                "fmt": fmt,
                "authData": ad.hex(),
                "alg": alg_out,
                "sig": sig.hex(),
                "x5c": [c.hex() for c in x5c],
                "clientDataHash": cdh.hex(),
                "rpId": RP_ID,
                "withToken": with_token,
                "expectedAaguid": expected_aaguid or aaguid,
                "expectedClass": expected_class,
                "expect": expect,
                "reason": reason,
            }
        )

    # ── positief ──
    add("ok_bio_uv", "OK", None, note="Bio met UV-token: leaf <- A (in x5c) <- test-root")
    add(
        "ok_yk5_up_only", "OK", None, flags=UP | AT, aaguid=AAGUID_YK5, expected_class="YUBIKEY5",
        with_token=False, note="YK5 vóór setPin: alleen aanraking, UV=0 toegestaan",
    )
    lk_b = p256()
    add(
        "ok_intermediate_uit_roots_pem", "OK", None, leaf_key=lk_b,
        leaf=leaf_cert(lk_b.public_key(), inter_b_name, inter_b_key, aaguid=AAGUID_BIO), chain_tail=[],
        note="x5c bevat alleen het leaf; intermediate B komt uit de roots-pem",
    )
    ed = ed25519.Ed25519PrivateKey.generate()
    add(
        "ok_attstmt_eddsa", "OK", None, leaf_key=ed, alg=-8,
        leaf=leaf_cert(ed.public_key(), inter_a_name, inter_a_key, aaguid=AAGUID_BIO),
        note="attStmt met EdDSA (-8), credential blijft ES256",
    )

    # ── negatief ──
    add("none_attestation", "ATTEST_NOT_PACKED", "NOT_PACKED", fmt="none")
    add("self_attestation", "ATTEST_NOT_PACKED", "SELF_ATTESTATION", self_attest=True)
    add("fmt_tpm", "ATTEST_NOT_PACKED", "NOT_PACKED", fmt="tpm")
    flk = p256()
    add(
        "verkeerde_ca", "ATTEST_CHAIN_INVALID", "CHAIN", leaf_key=flk,
        leaf=leaf_cert(flk.public_key(), inter_a_name, foreign_inter_key, aaguid=AAGUID_BIO),
        chain_tail=[foreign_inter], note="leaf <- vreemde intermediate (zelfde naam als A) <- vreemde root",
    )
    add("verkeerde_handtekening", "ATTEST_CHAIN_INVALID", "SIGNATURE", bad_sig=True)
    # leaf zegt BIO, authData zegt YK5
    mk = p256()
    add(
        "aaguid_mismatch_leaf", "ATTEST_AAGUID_MISMATCH", "LEAF_AAGUID_MISMATCH", leaf_key=mk,
        aaguid=AAGUID_YK5, expected_class="YUBIKEY5",
        leaf=leaf_cert(mk.public_key(), inter_a_name, inter_a_key, aaguid=AAGUID_BIO),
    )
    add(
        "aaguid_mismatch_getinfo", "ATTEST_AAGUID_MISMATCH", "GETINFO_AAGUID_MISMATCH",
        expected_aaguid="ad08c78a-4e41-49b9-86a2-ac15b06899e2",
    )
    nk = p256()
    add(
        "leaf_zonder_aaguid", "ATTEST_AAGUID_MISMATCH", "LEAF_AAGUID_MISSING", leaf_key=nk,
        leaf=leaf_cert(nk.public_key(), inter_a_name, inter_a_key, aaguid=None),
    )
    bk = p256()
    add(
        "leaf_aaguid_slecht_gecodeerd", "ATTEST_AAGUID_MISMATCH", "LEAF_AAGUID_MISSING", leaf_key=bk,
        leaf=leaf_cert(bk.public_key(), inter_a_name, inter_a_key, aaguid=None,
                       aaguid_raw=uuid.UUID(AAGUID_BIO).bytes),
        note="extnValue zonder OCTET STRING-omhulsel",
    )
    ck = p256()
    add(
        "leaf_is_ca", "ATTEST_CHAIN_INVALID", "LEAF_IS_CA", leaf_key=ck,
        leaf=leaf_cert(ck.public_key(), inter_a_name, inter_a_key, aaguid=AAGUID_BIO, ca=True),
    )
    xk = p256()
    add(
        "leaf_verlopen", "ATTEST_CHAIN_INVALID", "CHAIN", leaf_key=xk,
        leaf=leaf_cert(xk.public_key(), inter_a_name, inter_a_key, aaguid=AAGUID_BIO,
                       not_after=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)),
    )
    add("be_1", "ATTEST_FLAGS_INVALID", "NOT_DEVICE_BOUND", flags=UP | UV | AT | BE)
    add("bs_1", "ATTEST_FLAGS_INVALID", "NOT_DEVICE_BOUND", flags=UP | UV | AT | BE | BS)
    add("uv_0_met_token", "ATTEST_FLAGS_INVALID", "UV_MISSING", flags=UP | AT)
    add("up_0", "ATTEST_FLAGS_INVALID", "UP_MISSING", flags=UV | AT)
    add("at_0", "ATTEST_FLAGS_INVALID", "AT_MISSING", flags=UP | UV)
    add("verkeerde_rp_id", "ATTEST_RP_ID_HASH", "RP_ID", rp_id_in_auth="icthorse.invalid")
    add(
        "credential_eddsa", "ATTEST_ALGORITHM", "CREDENTIAL_ALG",
        cose_bytes=cose_eddsa(ed25519.Ed25519PrivateKey.generate()), note="keuring vraagt alleen -7",
    )
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    add(
        "attstmt_rs256", "ATTEST_ALGORITHM", "ATTESTATION_ALG", leaf_key=rk, alg=-257,
        leaf=leaf_cert(rk.public_key(), inter_a_name, inter_a_key, aaguid=AAGUID_BIO),
    )
    add(
        "attstmt_alg_past_niet_bij_sleutel", "ATTEST_ALGORITHM", "ATTESTATION_ALG", alg=-8,
        note="alg zegt EdDSA, leaf-sleutel is P-256",
    )
    add(
        "authdata_afgekapt", "ATTEST_FLAGS_INVALID", "MALFORMED_AUTH_DATA",
        auth=auth_data(flags=UP | UV | AT, aaguid=AAGUID_BIO, cose=cose)[:-5],
    )
    add(
        "authdata_restbytes", "ATTEST_FLAGS_INVALID", "MALFORMED_AUTH_DATA",
        auth=auth_data(flags=UP | UV | AT, aaguid=AAGUID_BIO, cose=cose) + b"\x00",
    )
    add("aaguid_niet_op_lijst", "AAGUID_NOT_ALLOWED", "NOT_ALLOWED", aaguid=AAGUID_UNLISTED)
    add(
        "klasse_past_niet", "CLASS_MISMATCH", "CLASS_MISMATCH", aaguid=AAGUID_YK5,
        expected_class="BIO", note="YK5-sleutel bij het Bio-profiel",
    )

    (OUT / "test_roots.pem").write_bytes(pem(root) + pem(inter_b))
    (OUT / "foreign_root.pem").write_bytes(pem(foreign))
    doc = {
        "_": "SYNTHETISCH - eigen test-CA, geen Yubico. Gegenereerd door src/test/tools/gen_attest_vectors.py.",
        "rpId": RP_ID,
        "vectors": vectors,
    }
    (OUT / "vectors.json").write_text(json.dumps(doc, indent=1, ensure_ascii=True) + "\n", encoding="ascii")
    print(f"{len(vectors)} vectoren geschreven naar {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
