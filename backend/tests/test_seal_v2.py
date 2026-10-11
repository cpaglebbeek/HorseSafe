"""v0.2.0-Koblitz — Seal_v2 (§12.5): Python-referentie + servercontrole ``validate_sealed``.

De vectoren in ``specs/testvectors/seal_v2.json`` (gedeeld met ``node --test`` en later de JVM)
worden hier gecontroleerd (gegenereerd door ``specs/testvectors/gen_seal_v2.py``).
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from backend.services.vault_key_service import validate_sealed

from . import seal_v2_ref as seal

VECTORS = Path(__file__).resolve().parents[2] / "specs" / "testvectors" / "seal_v2.json"
VID = str(uuid.uuid4())
KID = str(uuid.uuid4())


def _keypair() -> tuple[bytes, bytes]:
    return seal.keypair_from_prf(os.urandom(32))


@pytest.mark.parametrize(
    ("ph", "kh"), [(os.urandom(32), os.urandom(32)), (os.urandom(32), None), (None, os.urandom(32))]
)
def test_roundtrip_and_server_shape(ph: bytes | None, kh: bytes | None) -> None:
    sk, pk = _keypair()
    s = seal.seal(pk, ph, kh, vault_id=VID, key_id=KID)
    assert validate_sealed(s, KID)
    assert seal.unseal(s, sk, purpose="store", vault_id=VID, bind=KID, kid=KID) == (ph, kh)


@pytest.mark.parametrize(
    "open_with",
    [{"vault_id": str(uuid.uuid4())}, {"bind": str(uuid.uuid4())}, {"purpose": "relay"}],
)
def test_aad_binding(open_with: dict[str, str]) -> None:
    sk, pk = _keypair()
    s = seal.seal(pk, os.urandom(32), os.urandom(32), vault_id=VID, key_id=KID)
    kw = {"purpose": "store", "vault_id": VID, "bind": KID, "kid": KID, **open_with}
    with pytest.raises(seal.UnsealFailed):
        seal.unseal(s, sk, **kw)


def test_tampered_ct_and_other_recipient() -> None:
    sk, pk = _keypair()
    s = json.loads(seal.seal(pk, os.urandom(32), None, vault_id=VID, key_id=KID))
    ct = bytearray(seal.b64u_dec(s["ct"]))
    ct[0] ^= 1
    bad = json.dumps({**s, "ct": seal.b64u(bytes(ct))})
    with pytest.raises(seal.UnsealFailed):
        seal.unseal(bad, sk, purpose="store", vault_id=VID, bind=KID, kid=KID)
    other_sk, _ = _keypair()
    with pytest.raises(seal.UnsealFailed):
        seal.unseal(json.dumps(s), other_sk, purpose="store", vault_id=VID, bind=KID, kid=KID)


def _valid() -> dict[str, Any]:
    _, pk = _keypair()
    return dict(json.loads(seal.seal(pk, os.urandom(32), os.urandom(32), vault_id=VID, key_id=KID)))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: {**o, "v": 1},  # v1 vervalt
        lambda o: {**o, "v": True},
        lambda o: {**o, "v": "2"},
        lambda o: {**o, "kid": str(uuid.uuid4())},
        lambda o: {**o, "extra": 1},
        lambda o: {k: v for k, v in o.items() if k != "iv"},
        lambda o: {**o, "epk": o["epk"][:-1]},
        lambda o: {**o, "iv": o["iv"] + "A"},
        lambda o: {**o, "ct": "A" * 39},
        lambda o: {**o, "ct": "A" * 401},
        lambda o: {**o, "ct": o["ct"][:-1] + "="},
        lambda o: {**o, "epk": "+" * 43},
    ],
)
def test_validate_sealed_rejects(mutate: Any) -> None:
    assert not validate_sealed(json.dumps(mutate(_valid())), KID)


def test_validate_sealed_misc() -> None:
    assert validate_sealed(json.dumps(_valid()), KID)
    assert not validate_sealed("geen json", KID)
    assert not validate_sealed("[]", KID)
    assert not validate_sealed(json.dumps(_valid()) + " " * 1100, KID)  # > 1024 tekens
    v1 = json.dumps({"v": 1, "epk": "A" * 43, "iv": "A" * 16, "ct": "A" * 80})
    assert not validate_sealed(v1, KID)


def test_vectors_match_generator() -> None:
    """``seal_v2.json`` is precies wat ``gen_seal_v2.py`` nu oplevert (geen handwerk, geen drift)."""
    import importlib.util

    gen_path = VECTORS.with_name("gen_seal_v2.py")
    spec = importlib.util.spec_from_file_location("gen_seal_v2", gen_path)
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert VECTORS.read_text(encoding="utf-8") == gen.render()
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert {v["name"] for v in data["seal_vectors"]} >= {"ph+kh", "alleen ph", "alleen kh"}
    assert {n["name"] for n in data["negative"]} >= {
        "andere vault_id",
        "andere key_id",
        "andere purpose",
        "gewijzigde ct",
    }


def test_reference_reproduces_vectors() -> None:
    assert VECTORS.exists(), "specs/testvectors/seal_v2.json ontbreekt (gen_seal_v2.py)"
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    for pv in data["prf_vectors"]:
        sk, pk = seal.keypair_from_prf(seal.b64u_dec(pv["prf"]))
        assert seal.b64u(pk) == pv["pk"]
        if "sk" in pv:
            assert seal.b64u(sk) == pv["sk"]
    by_name = {}
    for v in data["seal_vectors"]:
        ph = seal.b64u_dec(v["ph"]) if v["ph"] else None
        kh = seal.b64u_dec(v["kh"]) if v["kh"] else None
        sealed, mid = seal.seal_with(
            seal.b64u_dec(v["recipient_pk"]),
            ph,
            kh,
            purpose=v["purpose"],
            vault_id=v["vault_id"],
            bind=v["bind"],
            kid=v["kid"],
            ephemeral_sk=seal.b64u_dec(v["ephemeral_sk"]),
            iv=seal.b64u_dec(v["iv"]),
        )
        assert sealed == v["sealed"], v["name"]
        assert mid["aad"].hex() == v["aad_hex"] and mid["pt"].decode() == v["pt_utf8"]
        assert mid["k"].hex() == v["k_hex"] and seal.b64u(mid["epk"]) == v["ephemeral_pk"]
        if v["purpose"] == "store":
            assert validate_sealed(v["sealed"], v["kid"])
        assert seal.unseal(
            v["sealed"],
            seal.b64u_dec(v["recipient_sk"]),
            purpose=v["purpose"],
            vault_id=v["vault_id"],
            bind=v["bind"],
            kid=v["kid"],
        ) == (ph, kh)
        by_name[v["name"]] = v
    for n in data.get("negative", []):
        base = by_name[n["based_on"]]
        kw = {
            "purpose": base["purpose"],
            "vault_id": base["vault_id"],
            "bind": base["bind"],
            "kid": base["kid"],
        }
        sealed = base["sealed"]
        ow = dict(n.get("open_with", {}))
        if "key_id" in ow:
            kid = ow.pop("key_id")
            kw["bind"] = kid
            kw["kid"] = kid
        if "sealed" in ow:
            sealed = ow.pop("sealed")
        kw.update(ow)
        with pytest.raises(seal.UnsealFailed):
            seal.unseal(sealed, seal.b64u_dec(base["recipient_sk"]), **kw)
