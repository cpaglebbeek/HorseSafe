"""v0.3.4-Miller deel 2 — koppel-afleidingen (§13.1) tegen ``specs/testvectors/pair_v1.json``.

De vectoren worden gedeeld met ``node --test`` en de JVM-tests van de app.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from backend.services import device_service as dev

from . import fake_device

VECTORS = Path(__file__).resolve().parents[2] / "specs" / "testvectors" / "pair_v1.json"


def _data() -> dict[str, Any]:
    assert VECTORS.exists(), "specs/testvectors/pair_v1.json ontbreekt (gen_pair_v1.py)"
    return dict(json.loads(VECTORS.read_text(encoding="utf-8")))


def test_vectors_match_generator() -> None:
    """``pair_v1.json`` is precies wat ``gen_pair_v1.py`` nu oplevert (geen handwerk, geen drift)."""
    spec = importlib.util.spec_from_file_location(
        "gen_pair_v1", VECTORS.with_name("gen_pair_v1.py")
    )
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    rendered = json.dumps(gen.build(), indent=2, ensure_ascii=False) + "\n"
    assert VECTORS.read_text(encoding="utf-8") == rendered


@pytest.mark.parametrize("v", _data()["vectors"], ids=lambda v: v["name"])
def test_server_reproduces_vector(v: dict[str, Any]) -> None:
    s = dev.b64u_decode(v["s"])
    k_srv = dev.k_srv_from_secret(s)
    k_web = dev.k_web_from_secret(s)
    assert dev.b64u(k_srv) == v["k_srv"]
    assert dev.b64u(k_web) == v["k_web"]
    f = v["fields"]
    assert f"hs1p:{f['pairing_id']}.{v['s']}" == v["qr"]
    assert dev.att_challenge(f["pairing_id"], k_srv).hex() == v["att_challenge_hex"]
    t = dev.transcript(f["pairing_id"], f)
    assert t.hex() == v["transcript_hex"]
    assert dev.b64u(dev.mac(k_srv, t)) == v["mac_srv"]
    assert dev.b64u(dev.mac(k_web, t)) == v["mac_web"]
    assert dev.sas(t) == v["sas"]


@pytest.mark.parametrize("v", _data()["vectors"], ids=lambda v: v["name"])
def test_fake_app_reproduces_vector(v: dict[str, Any]) -> None:
    """De nep-app (eigen implementatie) komt op dezelfde waarden; ook de webkant (mac_web → SAS)."""
    web = fake_device.WebSide(s=fake_device.b64u_dec(v["s"]))
    f = v["fields"]
    assert web.qr(f["pairing_id"]) == v["qr"]
    assert fake_device.b64u(web.k_srv) == v["k_srv"]
    assert fake_device.att_challenge(f["pairing_id"], web.k_srv).hex() == v["att_challenge_hex"]
    assert fake_device.transcript(f["pairing_id"], f).hex() == v["transcript_hex"]
    assert web.check_claim(f["pairing_id"], {**f, "mac_web": v["mac_web"]}) == v["sas"]


def test_negative_vectors() -> None:
    data = _data()
    by_name = {v["name"]: v for v in data["vectors"]}
    for n in data["negative"]:
        base = by_name[n["based_on"]]
        f = {**base["fields"], **n["change"]}
        k_srv = dev.b64u_decode(base["k_srv"])
        k_web = dev.b64u_decode(base["k_web"])
        t = dev.transcript(f["pairing_id"], f)
        assert dev.b64u(dev.mac(k_srv, t)) != base["mac_srv"]
        assert dev.b64u(dev.mac(k_web, t)) != base["mac_web"]
        assert dev.sas(t) != base["sas"]


def test_transcript_refuses_nul() -> None:
    f = dict(_data()["vectors"][0]["fields"])
    f["label"] = "a\x00b"
    with pytest.raises(ValueError):
        dev.transcript(f["pairing_id"], f)
