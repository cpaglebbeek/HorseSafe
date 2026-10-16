"""v0.4.0-Montgomery — afleidingen §14.2 tegen ``specs/testvectors/trust_v1.json``.

Met de echte serverfuncties (``trust_service``) én de eigen implementatie van de nep-app
(``fake_device``). De vectoren worden gedeeld met ``node --test`` en de JVM-tests van de app.
"""

from __future__ import annotations

import hmac
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from backend.services import trust_service as trust
from backend.services import vault_key_service as svc

from . import fake_device
from . import seal_v2_ref as seal

VECTORS = Path(__file__).resolve().parents[2] / "specs" / "testvectors" / "trust_v1.json"


def _data() -> dict[str, Any]:
    assert VECTORS.exists(), "specs/testvectors/trust_v1.json ontbreekt (gen_trust_v1.py)"
    return dict(json.loads(VECTORS.read_text(encoding="utf-8")))


DATA = _data()
APPROVAL = DATA["approval_vector"]
LOGIN = DATA["login_vector"]


def _proof_vec(name: str) -> dict[str, Any]:
    return next(v for v in DATA["proof_vectors"] if v["name"] == name)


def _opt(b: str | None) -> bytes | None:
    return seal.b64u_dec(b) if b is not None else None


def test_vectors_match_generator() -> None:
    spec = importlib.util.spec_from_file_location(
        "gen_trust_v1", VECTORS.with_name("gen_trust_v1.py")
    )
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    rendered = json.dumps(gen.build(), indent=2, ensure_ascii=False) + "\n"
    assert VECTORS.read_text(encoding="utf-8") == rendered


@pytest.mark.parametrize("v", DATA["proof_vectors"], ids=lambda v: v["name"])
def test_server_reproduces_proof(v: dict[str, Any]) -> None:
    pt = seal.plaintext(_opt(v["ph"]), _opt(v["kh"]))
    assert pt.decode() == v["pt_ck"]
    k = trust.k_bind(pt, v["vault_id"])
    assert k.hex() == v["k_bind_hex"]
    t = trust.bind_t(v["vault_id"], v["browser_id"], v["pub_b"], v["label"])
    assert t.hex() == v["bind_t_hex"]
    assert trust.b64u(trust.proof(k, t)) == v["proof"]
    # nep-app: eigen implementatie, zelfde uitkomst
    fk = fake_device.trust_k_bind(pt, v["vault_id"])
    ft = fake_device.trust_bind_t(v["vault_id"], v["browser_id"], v["pub_b"], v["label"])
    assert fk == k and ft == t


def test_login_t_and_signature() -> None:
    v = LOGIN
    t = trust.login_t(
        v["challenge_id"], seal.b64u_dec(v["challenge"]), v["browser_id"], v["email_lc"]
    )
    assert t.hex() == v["login_t_hex"]
    assert v["pub_b"] == DATA["browser_key"]["pub_b"]
    assert trust.valid_p256_spki(v["pub_b"])
    assert trust.verify_p1363_b64u(v["pub_b"], v["sig"], t)
    assert not trust.verify_p1363_b64u(v["pub_b"], v["sig"], t + b"x")
    other = trust.login_t(
        v["challenge_id"], seal.b64u_dec(v["challenge"]), v["browser_id"], "ander@example.com"
    )
    assert not trust.verify_p1363_b64u(v["pub_b"], v["sig"], other)


def test_req_t_and_sig_req() -> None:
    a = APPROVAL
    t = trust.req_t(
        a["approval_id"],
        a["vault_id"],
        a["browser_id"],
        a["epk_l"],
        seal.b64u_dec(a["nonce_l"]),
        a["created_at"],
    )
    assert t.hex() == a["req_t_hex"]
    assert trust.verify_p1363_b64u(a["pub_b"], a["sig_req"], t)
    # nep-app bouwt req_t uit de device-response (veldnamen van §14.6)
    dev_view = {
        "approval_id": a["approval_id"],
        "vault_id": a["vault_id"],
        "browser": {"browser_id": a["browser_id"], "pub_B": a["pub_b"]},
        "epk_L": a["epk_l"],
        "nonce_L": a["nonce_l"],
        "created_at": a["created_at"],
    }
    assert fake_device.trust_req_t(dev_view) == t
    assert fake_device.verify_raw_p256(a["pub_b"], a["sig_req"], t)


def test_p1363_rejects_der_and_wrong_lengths() -> None:
    a = APPROVAL
    t = bytes.fromhex(a["req_t_hex"])
    raw = seal.b64u_dec(a["sig_req"])
    assert not trust.verify_p1363(a["pub_b"], raw[:63], t)
    assert not trust.verify_p1363(a["pub_b"], raw + b"\x00", t)
    assert not trust.verify_p1363(a["pub_b"], b"\x00" * 64, t)
    assert not trust.verify_p1363_b64u(a["pub_b"], "!!", t)


def test_relay_seal_opens_and_passes_server_form_check() -> None:
    a = APPROVAL
    bind = trust.relay_bind(a["approval_id"], a["nonce_l"])
    assert bind == a["relay_bind"]
    assert svc.validate_sealed(a["resp"], a["approval_id"])
    assert seal.build_aad("relay", a["vault_id"], bind).hex() == a["relay_aad_hex"]
    ph, kh = seal.unseal(
        a["resp"],
        seal.b64u_dec(a["e_l_sk"]),
        purpose="relay",
        vault_id=a["vault_id"],
        bind=bind,
        kid=a["approval_id"],
    )
    assert (ph, kh) == (seal.b64u_dec(a["ph"]), seal.b64u_dec(a["kh"]))


NEG = {n["name"]: n for n in DATA["negative"]}


@pytest.mark.parametrize("name", ["ander vault_id", "ander label", "andere pub_b"])
def test_negative_proof(name: str) -> None:
    n = NEG[name]
    v = {**_proof_vec(n["based_on"]), **n["change"]}
    pt = seal.plaintext(_opt(v["ph"]), _opt(v["kh"]))
    t = trust.bind_t(v["vault_id"], v["browser_id"], v["pub_b"], v["label"])
    got = trust.proof(trust.k_bind(pt, v["vault_id"]), t)
    assert not hmac.compare_digest(got, seal.b64u_dec(_proof_vec(n["based_on"])["proof"]))


def test_negative_kh_null_refused_by_phone() -> None:
    """``kh = null`` → de telefoon weigert (``keyfile_required``) vóór het bewijs."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from .fake_device import FakeAttestationCA, FakeDevice

    d = FakeDevice(FakeAttestationCA())
    a = APPROVAL
    store = seal.seal(
        d.sk_c.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        seal.b64u_dec(a["ph"]),
        None,
        vault_id=a["vault_id"],
        key_id="11111111-1111-4111-8111-111111111111",
    )
    view = {
        "approval_id": a["approval_id"],
        "vault_id": a["vault_id"],
        "key_id": "11111111-1111-4111-8111-111111111111",
        "browser": {
            "browser_id": a["browser_id"],
            "pub_B": a["pub_b"],
            "label": "Chrome – laptop",
            "proof": _proof_vec("ph+kh")["proof"],
        },
        "epk_L": a["epk_l"],
        "nonce_L": a["nonce_l"],
        "created_at": a["created_at"],
        "sig_req": a["sig_req"],
    }
    assert d.decide_body(view, store) == {"decision": "deny", "reason": "keyfile_required"}


def test_negative_other_nonce_fails_open() -> None:
    a = APPROVAL
    n = NEG["andere nonce bij openen"]
    with pytest.raises(seal.UnsealFailed):
        seal.unseal(
            a["resp"],
            seal.b64u_dec(a["e_l_sk"]),
            purpose="relay",
            vault_id=a["vault_id"],
            bind=trust.relay_bind(a["approval_id"], n["change"]["nonce_l"]),
            kid=a["approval_id"],
        )


def test_negative_other_created_at() -> None:
    a = APPROVAL
    t = trust.req_t(
        a["approval_id"],
        a["vault_id"],
        a["browser_id"],
        a["epk_l"],
        seal.b64u_dec(a["nonce_l"]),
        NEG["ander created_at"]["change"]["created_at"],
    )
    assert not trust.verify_p1363_b64u(a["pub_b"], a["sig_req"], t)


def test_browser_key_matches_vector() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    d = int(DATA["browser_key"]["d_hex"], 16)
    k = ec.derive_private_key(d, ec.SECP256R1())
    spki = k.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert trust.b64u(spki) == DATA["browser_key"]["pub_b"]
