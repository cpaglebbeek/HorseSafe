"""v0.3.4-Miller deel 2 — telefoon koppelen (docs/HARDWARE_KEYS.md §13), minimale tests §13.10.

De attestation wordt echt gecontroleerd: een eigen test-root (``dev_env``) met een zelf ge-DER-de
key-description in de leafs (``fake_device.py``). Alleen de testvlag-tests zetten
``HORSESAFE_TEST_DEVICE_ATTESTATION``. De revocatielijst is altijd gemockt (nooit netwerk).
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from typing import Any

import pytest
from httpx import AsyncClient, Response

from . import seal_v2_ref as seal
from .fake_device import (
    SELF_SIGNED,
    SOFTWARE,
    STRONGBOX,
    FakeAttestationCA,
    FakeDevice,
    KeyProfile,
    WebSide,
    b64u,
    debug_profiles,
)
from .hwkeys_helpers import enable_totp, fake_sealed, setup_user, stepup_totp


async def _events(prefix: str = "device_%") -> list[dict[str, Any]]:
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(
            "SELECT event, detail FROM audit_log WHERE event LIKE ? ORDER BY id", (prefix,)
        )
        return [
            {"event": r["event"], "detail": json.loads(r["detail"]) if r["detail"] else None}
            for r in await cur.fetchall()
        ]


async def _pairing_row(pid: str) -> tuple[str, str]:
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute("SELECT status, k_srv FROM pairings WHERE id = ?", (pid,))
        row = await cur.fetchone()
        return str(row["status"]), str(row["k_srv"])


async def _count(table: str) -> int:
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(f"SELECT COUNT(*) AS n FROM {table}")  # noqa: S608 — testconstante
        row = await cur.fetchone()
        return int(row["n"])


async def su_user(client: AsyncClient, email: str = "phone@example.com") -> str:
    """Gebruiker met vault, TOTP en een geldige step-up. Return vault_id."""
    vid = await setup_user(client, email)
    secret = await enable_totp(client)
    r = await stepup_totp(client, secret)
    assert r.status_code == 200, r.text
    return vid


async def start(client: AsyncClient, vid: str, web: WebSide) -> Response:
    return await client.post("/devices/pairings", json={"vault_id": vid, "k_srv": b64u(web.k_srv)})


async def started(client: AsyncClient, vid: str) -> tuple[str, WebSide]:
    web = WebSide()
    r = await start(client, vid, web)
    assert r.status_code == 201, r.text
    return r.json()["pairing_id"], web


async def claim(
    client: AsyncClient, d: FakeDevice, web: WebSide, pid: str, **override: Any
) -> Response:
    _, body = d.claim_body(web.qr(pid), **override)
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    if r.status_code == 201:
        d.device_id = r.json()["device_id"]
    return r


async def pair(
    client: AsyncClient, ca: FakeAttestationCA, vid: str, **dev_kw: Any
) -> tuple[FakeDevice, dict[str, Any], str]:
    """Volledige koppeling (claim → web controleert mac_web/SAS → confirm met echte Seal_v2)."""
    pid, web = await started(client, vid)
    d = FakeDevice(ca, **dev_kw)
    r = await claim(client, d, web, pid)
    assert r.status_code == 201, r.text
    st = (await client.get(f"/devices/pairings/{pid}")).json()
    assert st["status"] == "claimed"
    assert web.check_claim(pid, st["claim"]) == r.json()["sas"]
    c = st["claim"]
    sealed = seal.seal(
        seal.b64u_dec(c["pk_c"]), os.urandom(32), os.urandom(32), vault_id=vid, key_id=c["key_id"]
    )
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": sealed})
    assert r.status_code == 201, r.text
    return d, r.json(), pid


async def dget(client: AsyncClient, d: FakeDevice, path: str, **kw: Any) -> Response:
    return await client.get(path, headers=d.signed_headers("GET", path, **kw))


# ─────────────── Happy path ───────────────


async def test_happy_path(client: AsyncClient, dev_env: Any, mailbox: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca, label="Galaxy Z Fold6", model="SM-F956B")
    r = await claim(client, d, web, pid)
    assert r.status_code == 201, r.text
    sas = r.json()["sas"]
    assert len(sas) == 6 and sas.isdigit()

    # App ziet 'pending' tot bevestigen
    st = await dget(client, d, "/device/v1/status")
    assert st.status_code == 200 and st.json() == {
        "device_id": d.device_id,
        "state": "pending",
        "keys": [],
        "approvals": [],
    }

    # Web: claim met mac_web, eigen SAS-berekening
    s = (await client.get(f"/devices/pairings/{pid}")).json()
    c = s["claim"]
    assert s["status"] == "claimed"
    assert c["pk_c"] == d.pk_c and c["device_id"] == d.device_id
    assert c["security_level"] == "TrustedEnvironment" and c["strongbox"] is False
    assert web.check_claim(pid, c) == sas
    assert "mac_srv" not in c and "k_srv" not in json.dumps(s)

    ph, kh = os.urandom(32), os.urandom(32)
    sealed = seal.seal(seal.b64u_dec(c["pk_c"]), ph, kh, vault_id=vid, key_id=c["key_id"])
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": sealed})
    assert r.status_code == 201, r.text
    key = r.json()
    assert key["kind"] == "phone" and key["id"] == c["key_id"] and key["public_key"] == d.pk_c
    assert key["device"] == {"id": d.device_id, "label": "Galaxy Z Fold6", "model": "SM-F956B"}
    assert key["credential_id"] is None and key["prf_salt"] is None
    assert (await client.get(f"/devices/pairings/{pid}")).json()["status"] == "confirmed"

    # Sleutellijst toont de telefoon met device; nooit sealed
    lst = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert [k["id"] for k in lst] == [key["id"]] and lst[0]["device"]["id"] == d.device_id
    assert "sealed" not in lst[0]

    # Toestellenlijst: zonder ketens en sleutels
    devs = (await client.get("/devices")).json()["devices"]
    assert len(devs) == 1 and devs[0]["state"] == "active" and devs[0]["id"] == d.device_id
    assert not {"att_chains", "k_dev_pub", "k_biosig_pub"} & set(devs[0])

    # App: active + kopie ophalen en openen (alleen vorm, §13.3 stap 6)
    st = (await dget(client, d, "/device/v1/status")).json()
    assert st["state"] == "active"
    assert st["keys"] == [{"key_id": key["id"], "vault_id": vid, "label": "Galaxy Z Fold6"}]
    r = await dget(client, d, f"/device/v1/keys/{key['id']}/sealed")
    assert r.status_code == 200
    got = r.json()
    assert got["key_id"] == key["id"] and got["vault_id"] == vid
    assert d.open_sealed(got["sealed"], vid, key["id"]) == (ph, kh)

    # Unlock met een phone-sleutel blijft 404 (Montgomery)
    r = await client.post(
        f"/vault/{vid}/keys/{key['id']}/unlock",
        json={
            "challenge_id": "00000000-0000-4000-8000-000000000000",
            "credential_id": "A" * 16,
            "client_data_json": "AA",
            "authenticator_data": "AA",
            "signature": "AA",
        },
    )
    assert r.status_code == 404

    events = [e["event"] for e in await _events()]
    assert events == ["device_pairing_start", "device_pairing_claim", "device_pairing_confirm"]
    blob = json.dumps(await _events())
    for secret in (b64u(web.k_srv), b64u(web.s), sealed, c["mac_web"]):
        assert secret not in blob
    assert mailbox.subjects()[-1:] == ["HorseSafe: nieuw toestel gekoppeld"]


async def test_strongbox_reported(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(
        dev_env.ca,
        dev=KeyProfile(role="k_dev", attestation_level=STRONGBOX, keymint_level=STRONGBOX),
        bio=KeyProfile(role="k_biosig", attestation_level=STRONGBOX, keymint_level=STRONGBOX),
    )
    assert (await claim(client, d, web, pid)).status_code == 201
    c = (await client.get(f"/devices/pairings/{pid}")).json()["claim"]
    assert c["security_level"] == "StrongBox" and c["strongbox"] is True


# ─────────────── Koppeling starten ───────────────


async def test_start_requires_stepup_and_own_vault(client: AsyncClient, dev_env: Any) -> None:
    vid = await setup_user(client, "nosu@example.com")
    r = await start(client, vid, WebSide())
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    r = await start(client, "00000000-0000-4000-8000-000000000000", WebSide())
    assert r.status_code == 404
    r = await client.post("/devices/pairings", json={"vault_id": vid, "k_srv": "kort"})
    assert r.status_code == 422


async def test_one_open_pairing_and_hourly_limit(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    p1, _ = await started(client, vid)
    p2, _ = await started(client, vid)
    r = await client.get(f"/devices/pairings/{p1}")  # geannuleerd → bestaat niet meer (§13.3)
    assert r.status_code == 404 and r.json()["detail"]["error"] == "not_found"
    assert (await client.get(f"/devices/pairings/{p2}")).json()["status"] == "pending"
    for _ in range(8):
        await started(client, vid)
    r = await start(client, vid, WebSide())
    assert r.status_code == 429 and r.json()["detail"]["error"] == "too_many_pairings"


async def test_pairing_owner_only(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client, "owner@example.com")
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    assert (await claim(client, d, web, pid)).status_code == 201
    await client.post("/auth/logout")
    await setup_user(client, "other@example.com")
    assert (await client.get(f"/devices/pairings/{pid}")).status_code == 404
    assert (await client.delete(f"/devices/pairings/{pid}")).status_code == 404
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": fake_sealed("x")})
    assert r.status_code == 404 and r.json()["detail"]["error"] == "not_found"
    assert (await client.get("/devices")).json()["devices"] == []
    assert (await client.delete(f"/devices/{d.device_id}")).status_code == 404


async def test_cancel_claimed_removes_device(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    assert (await claim(client, d, web, pid)).status_code == 201
    assert await _count("devices") == 1
    assert (await client.delete(f"/devices/pairings/{pid}")).status_code == 204
    r = await client.get(f"/devices/pairings/{pid}")  # geannuleerd → 404 (§13.3)
    assert r.status_code == 404 and r.json() == {"detail": {"error": "not_found"}}
    assert await _count("devices") == 0
    assert await _pairing_row(pid) == ("cancelled", "")
    assert (await dget(client, d, "/device/v1/status")).status_code == 401
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": fake_sealed("x")})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "pairing_not_claimed"


# ─────────────── Claim: pydantic, bestaan, mac ───────────────


@pytest.mark.parametrize(
    "override",
    [
        {"label": "Fold\x00"},
        {"label": ""},
        {"model": "x" * 65},
        {"app_version": "1\n2"},
        {"label": "Fold\u202eelif.exe"},  # Cf: leesrichting omdraaien
        {"label": "Fo\u200bld"},  # Cf: zero-width space
        {"model": "SM\u2028F956B"},  # Zl
        {"model": "SM\u2029F956B"},  # Zp
        {"app_version": "0.3.4\ufeff"},  # Cf: BOM
        {"pk_c": "A" * 42},
        {"k_dev_chain": ["AAAA"]},
        {"mac_srv": "+" * 43},
        {"sig_biosig": "A" * 121},
    ],
)
async def test_claim_shape_422(client: AsyncClient, dev_env: Any, override: dict[str, Any]) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(dev_env.ca), web, pid, **override)
    assert r.status_code == 422


@pytest.mark.parametrize("field", ["label", "model", "app_version"])
async def test_claim_lone_surrogate_422(client: AsyncClient, dev_env: Any, field: str) -> None:
    """Een los surrogaat (bv. \\ud800) is geldige JSON maar geen UTF-8: 422, nooit een 500 uit
    transcript()."""
    vid = await su_user(client)
    pid, web = await started(client, vid)
    _, body = FakeDevice(dev_env.ca).claim_body(web.qr(pid))
    body[field] = "Fold\ud800"
    r = await client.post(
        f"/devices/pairings/{pid}/claim",
        content=json.dumps(body),  # ensure_ascii: het surrogaat gaat als \\ud800 over de lijn
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422
    assert (await client.get(f"/devices/pairings/{pid}")).json()["status"] == "pending"


async def test_claim_unknown_expired_double(
    client: AsyncClient, dev_env: Any, clock: dict[str, int]
) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(dev_env.ca), web, "00000000-0000-4000-8000-000000000000")
    assert r.status_code == 404 and r.json()["detail"]["error"] == "pairing_not_found"
    assert (await claim(client, FakeDevice(dev_env.ca), web, pid)).status_code == 201
    r = await claim(client, FakeDevice(dev_env.ca), web, pid)  # dubbele claim
    assert r.status_code == 404 and r.json()["detail"]["error"] == "pairing_not_found"

    # verlopen (TTL 300 s)
    pid2, web2 = await started(client, vid)
    assert (await client.get(f"/devices/pairings/{pid2}")).status_code == 200
    clock["t"] += 301
    r = await claim(client, FakeDevice(dev_env.ca), web2, pid2)
    assert r.status_code == 404 and r.json()["detail"]["error"] == "pairing_not_found"
    # ook GET: verlopen pending → 404 (§13.3)
    r = await client.get(f"/devices/pairings/{pid2}")
    assert r.status_code == 404 and r.json()["detail"]["error"] == "not_found"


async def test_mac_failures_cancel_after_three(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    for i in range(3):
        r = await claim(client, FakeDevice(dev_env.ca), web, pid, k_srv=os.urandom(32))
        assert r.status_code == 400 and r.json()["detail"]["error"] == "pairing_mac_invalid"
        r = await client.get(f"/devices/pairings/{pid}")
        if i == 2:
            assert r.status_code == 404  # geannuleerd → bestaat voor het web niet meer
            assert await _pairing_row(pid) == ("cancelled", "")
        else:
            assert r.json()["status"] == "pending"
    r = await claim(client, FakeDevice(dev_env.ca), web, pid)  # nu ook de juiste: weg
    assert r.status_code == 404
    ev = await _events()
    assert [e["detail"]["reason"] for e in ev if e["event"] == "device_pairing_rejected"] == [
        "pairing_mac_invalid"
    ] * 3
    assert ev[-1]["event"] == "device_pairing_cancel"
    assert await _count("devices") == 0


async def test_mac_covers_transcript_fields(client: AsyncClient, dev_env: Any) -> None:
    """Server verandert/ontvangt een ander label dan getekend → mac_srv klopt niet."""
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    _, body = d.claim_body(web.qr(pid))
    body["label"] = "Ander toestel"
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "pairing_mac_invalid"


# ─────────────── Claim: attestation (echte controles) ───────────────


def _bad_dev(**kw: Any) -> dict[str, Any]:
    return {"dev": KeyProfile(role="k_dev", **kw)}


def _bad_bio(**kw: Any) -> dict[str, Any]:
    return {"bio": KeyProfile(role="k_biosig", **kw)}


ATTESTATION_CASES = [
    ("challenge_mismatch", _bad_dev(challenge=b"\x00" * 32)),
    ("challenge_mismatch", _bad_bio(challenge=b"\x01" * 32)),
    ("security_level", _bad_dev(attestation_level=SOFTWARE, keymint_level=SOFTWARE)),
    ("security_level", _bad_bio(keymint_level=SOFTWARE)),
    ("boot_unverified", _bad_dev(boot_state=SELF_SIGNED)),
    ("device_unlocked", _bad_bio(device_locked=False)),
    ("root_of_trust_missing", _bad_dev(with_root_of_trust=False)),
    ("package_mismatch", _bad_dev(packages=("nl.icthorse.horsesafe.debug",))),
    ("package_mismatch", _bad_bio(packages=("com.example.evil",))),
    ("package_mismatch", _bad_dev(packages=("nl.icthorse.horsesafe", "com.example.shared"))),
    ("signer_mismatch", _bad_dev(signers=("ab" * 32,))),
    ("app_id_missing", _bad_bio(with_app_id=False)),
    ("no_biometric", _bad_bio(user_auth_type=1)),  # alleen wachtwoord/PIN
    ("no_biometric", _bad_bio(user_auth_type=3)),  # biometrie óf PIN (E2: geen PIN-terugval)
    ("no_auth_required", _bad_bio(no_auth_required=True)),
    ("auth_timeout", _bad_bio(auth_timeout=30)),
    ("unlocked_device_required_missing", _bad_dev(unlocked_device_required=False)),
    ("extension_missing", _bad_bio(with_extension=False)),
    ("extension_invalid", _bad_dev(extension_garbage=True)),
]


@pytest.mark.parametrize(("reason", "kw"), ATTESTATION_CASES, ids=[c[0] for c in ATTESTATION_CASES])
async def test_attestation_rejected(
    client: AsyncClient, dev_env: Any, reason: str, kw: dict[str, Any]
) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(dev_env.ca, **kw), web, pid)
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == {"error": "attestation_invalid", "reason": reason}
    # niets geschreven vóór stap 8; koppeling blijft pending
    assert await _count("devices") == 0
    assert (await client.get(f"/devices/pairings/{pid}")).json()["status"] == "pending"
    ev = [e for e in await _events() if e["event"] == "device_pairing_rejected"]
    assert ev[-1]["detail"] == {
        "pairing_id": pid,
        "reason": "attestation_invalid",
        "attestation_reason": reason,
    }
    assert not [e for e in await _events() if e["event"] == "device_pairing_claim"]


async def test_chain_root_untrusted(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(FakeAttestationCA()), web, pid)  # andere root
    assert r.json()["detail"] == {"error": "attestation_invalid", "reason": "root_untrusted"}


async def test_chain_invalid_variants(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    _, body = d.claim_body(web.qr(pid))
    good = body["k_dev_chain"]
    # volgorde omgedraaid → handtekeningen kloppen niet
    body["k_dev_chain"] = list(reversed(good))
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    assert r.json()["detail"]["reason"] == "chain_invalid"
    # rommel als certificaat
    body["k_dev_chain"] = ["AAAA", *good[1:]]
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    assert r.json()["detail"]["reason"] == "chain_invalid"
    # leaf ontbreekt (keten begint bij de intermediate): leaf is dan een CA
    body["k_dev_chain"] = good[1:]
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    assert r.json()["detail"]["reason"] == "chain_invalid"
    # verlopen intermediate
    from cryptography.hazmat.primitives.asymmetric import ec

    from .fake_device import _ca_cert

    old = FakeAttestationCA.__new__(FakeAttestationCA)
    old.root, old.root_key = dev_env.ca.root, dev_env.ca.root_key
    old.inter_key = ec.generate_private_key(ec.SECP256R1())
    old.inter = _ca_cert("Verlopen", old.inter_key, old.root.subject, old.root_key, days_valid=-2)
    r = await claim(client, FakeDevice(old), web, pid)
    assert r.json()["detail"]["reason"] == "chain_invalid"


async def test_chain_without_root_cert_is_accepted(client: AsyncClient, dev_env: Any) -> None:
    """Keten eindigt bij een tussencertificaat dat een vertrouwde root als uitgever heeft."""
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    _, body = d.claim_body(web.qr(pid))
    body["k_dev_chain"] = body["k_dev_chain"][:2]
    body["k_biosig_chain"] = body["k_biosig_chain"][:2]
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    assert r.status_code == 201, r.text


async def test_key_mismatch_and_type(client: AsyncClient, dev_env: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    from .fake_device import spki

    vid = await su_user(client)
    pid, web = await started(client, vid)
    other = b64u(spki(ec.generate_private_key(ec.SECP256R1()).public_key()))
    r = await claim(client, FakeDevice(dev_env.ca), web, pid, k_dev_pub=other)
    assert r.json()["detail"] == {"error": "attestation_invalid", "reason": "key_mismatch"}
    p384 = b64u(spki(ec.generate_private_key(ec.SECP384R1()).public_key()))
    r = await claim(client, FakeDevice(dev_env.ca), web, pid, k_biosig_pub=p384)
    assert r.json()["detail"] == {"error": "attestation_invalid", "reason": "key_type"}


async def test_revoked_certificate(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    inter_serial = format(dev_env.ca.inter.serial_number, "x")
    dev_env.revoked[inter_serial] = {"status": "REVOKED", "reason": "KEY_COMPROMISE"}
    r = await claim(client, FakeDevice(dev_env.ca), web, pid)
    assert r.json()["detail"] == {"error": "attestation_invalid", "reason": "revoked"}
    assert dev_env.fetches == 1


async def test_revocation_cache(client: AsyncClient, dev_env: Any, clock: dict[str, int]) -> None:
    vid = await su_user(client)
    # 1. niet ophaalbaar en geen cache → 503
    dev_env.fetch_fail = True
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(dev_env.ca), web, pid)
    assert r.status_code == 503
    assert r.json()["detail"] == {"error": "attestation_status_unavailable"}
    assert (await client.get(f"/devices/pairings/{pid}")).json()["status"] == "pending"
    # 2. ophalen lukt → cache op schijf; binnen 24 u geen nieuwe fetch
    dev_env.fetch_fail = False
    assert (await claim(client, FakeDevice(dev_env.ca), web, pid)).status_code == 201
    assert dev_env.fetches == 2 and dev_env.cache.exists()
    pid, web = await started(client, vid)
    dev_env.fetch_fail = True
    assert (await claim(client, FakeDevice(dev_env.ca), web, pid)).status_code == 201
    assert dev_env.fetches == 2
    # 3. na 24 u: opnieuw ophalen; lukt dat niet → verouderde cache (geen 503)
    from backend.services import android_attestation as aa

    clock["t"] += 24 * 3600 + 1
    dev_env.revoked["abc"] = {"status": "REVOKED"}
    assert await aa.revocation_entries() == {}  # fetch_fail staat nog aan: oude cache
    assert dev_env.fetches == 3
    dev_env.fetch_fail = False
    assert "abc" in await aa.revocation_entries()
    assert dev_env.fetches == 4
    # 4. verouderde cache is hooguit 7 dagen bruikbaar (android_attestation_status_max_stale_seconds)
    dev_env.fetch_fail = True
    clock["t"] += 7 * 24 * 3600
    assert "abc" in await aa.revocation_entries()  # precies 7 dagen: nog net
    clock["t"] += 1
    with pytest.raises(aa.AttestationError) as ei:
        await aa.revocation_entries()
    assert ei.value.code == "attestation_status_unavailable" and ei.value.status == 503


async def test_signature_invalid_and_too_many_devices(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    other = FakeDevice(dev_env.ca)
    _, body = d.claim_body(web.qr(pid))
    _, ob = other.claim_body(web.qr(pid))
    body["sig_biosig"] = ob["sig_biosig"]  # handtekening van een ander toestel
    r = await client.post(f"/devices/pairings/{pid}/claim", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "signature_invalid"

    for _ in range(5):
        await pair(client, dev_env.ca, vid)
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(dev_env.ca), web, pid)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "too_many_devices"


async def test_claim_rate_limit(client: AsyncClient, dev_env: Any) -> None:
    vid = await su_user(client)
    pid, _web = await started(client, vid)
    codes = []
    for _ in range(11):
        r = await client.post(f"/devices/pairings/{pid}/claim", json={})
        codes.append(r.status_code)
    assert codes[:10] == [422] * 10 and codes[10] == 429
    # pollen valt er niet onder
    assert (await client.get(f"/devices/pairings/{pid}")).status_code == 200


# ─────────────── Bevestigen ───────────────


async def test_unconfirmed_claim_cleaned_up_after_600s(
    client: AsyncClient, dev_env: Any, clock: dict[str, int]
) -> None:
    """Een geclaimde koppeling die nooit bevestigd wordt, blijft niet eeuwig staan (§13.3);
    hier ruimt GET /devices op."""
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    assert (await claim(client, d, web, pid)).status_code == 201
    clock["t"] += 600  # nog binnen de termijn
    assert len((await client.get("/devices")).json()["devices"]) == 1
    assert (await client.get(f"/devices/pairings/{pid}")).json()["status"] == "claimed"
    clock["t"] += 1
    assert (await client.get("/devices")).json()["devices"] == []
    assert await _count("devices") == 0
    assert await _pairing_row(pid) == ("cancelled", "")
    assert (await client.get(f"/devices/pairings/{pid}")).status_code == 404
    assert (await dget(client, d, "/device/v1/status", ts=clock["t"])).status_code == 401
    ev = await _events("device_pairing_cancel")
    assert ev[-1]["detail"] == {"pairing_id": pid, "reason": "not_confirmed"}


async def test_unconfirmed_claim_cleaned_up_by_device_request(
    client: AsyncClient, dev_env: Any, clock: dict[str, int]
) -> None:
    """Het eerstvolgende device-request van de app ruimt een te oude claim op."""
    vid = await su_user(client)
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca)
    assert (await claim(client, d, web, pid)).status_code == 201
    assert (await dget(client, d, "/device/v1/status", ts=clock["t"])).json()["state"] == "pending"
    clock["t"] += 601
    assert (await dget(client, d, "/device/v1/status", ts=clock["t"])).status_code == 401
    assert await _count("devices") == 0
    assert await _pairing_row(pid) == ("cancelled", "")


async def test_late_confirm_expired_and_cleaned_up(
    client: AsyncClient, dev_env: Any, clock: dict[str, int]
) -> None:
    """Te laat bevestigen geeft nog steeds pairing_expired (§13.5), en ruimt daarna ook op."""
    vid = await su_user(client)
    pid, web = await started(client, vid)
    assert (await claim(client, FakeDevice(dev_env.ca), web, pid)).status_code == 201
    key_id = (await client.get(f"/devices/pairings/{pid}")).json()["claim"]["key_id"]
    clock["t"] += 601
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": fake_sealed(key_id)})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "pairing_expired"
    assert await _count("devices") == 0
    assert await _pairing_row(pid) == ("cancelled", "")


async def test_confirm_checks(client: AsyncClient, dev_env: Any, clock: dict[str, int]) -> None:
    vid = await su_user(client)
    pid, web = await started(client, vid)
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": fake_sealed("x")})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "pairing_not_claimed"
    assert (await claim(client, FakeDevice(dev_env.ca), web, pid)).status_code == 201
    key_id = (await client.get(f"/devices/pairings/{pid}")).json()["claim"]["key_id"]
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": fake_sealed("x")})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_sealed"
    clock["t"] += 601
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": fake_sealed(key_id)})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "pairing_expired"
    assert await _count("vault_keys") == 0


async def test_phone_keys_count_towards_max(
    client: AsyncClient, dev_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    vid = await su_user(client)
    await pair(client, dev_env.ca, vid)
    monkeypatch.setenv("HORSESAFE_VAULT_KEYS_MAX", "1")
    r = await start(client, vid, WebSide())
    assert r.status_code == 409 and r.json()["detail"]["error"] == "too_many_keys"
    r = await client.post(
        "/webauthn/options", json={"purpose": "register", "vault_id": vid, "kind": "bio"}
    )
    assert r.status_code == 409 and r.json()["detail"]["error"] == "too_many_keys"


async def test_rekey_must_include_phone_key(client: AsyncClient, dev_env: Any) -> None:
    from .test_vault import FAKE_KDBX_BLOB

    vid = await su_user(client)
    _d, key, _ = await pair(client, dev_env.ca, vid)
    etag = (await client.get("/vault")).json()[0]["etag"]
    r = await client.put(
        f"/vault/{vid}/rekey",
        headers={"If-Match": etag},
        data={"sealed": json.dumps({"items": []})},
        files={"blob": ("v.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 409 and r.json()["detail"]["error"] == "keys_mismatch"
    items = [{"id": key["id"], "sealed": fake_sealed(key["id"])}]
    r = await client.put(
        f"/vault/{vid}/rekey",
        headers={"If-Match": etag},
        data={"sealed": json.dumps({"items": items})},
        files={"blob": ("v.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text


# ─────────────── Device-handtekening (§13.6) ───────────────


async def test_device_signature(client: AsyncClient, dev_env: Any) -> None:
    import time

    from cryptography.hazmat.primitives.asymmetric import ec

    vid = await su_user(client)
    d, key, _ = await pair(client, dev_env.ca, vid)
    path = "/device/v1/status"
    assert (await dget(client, d, path)).status_code == 200

    def failed(r: Response) -> bool:
        return r.status_code == 401 and r.json() == {"detail": {"error": "device_auth_failed"}}

    # verkeerde handtekening (andere sleutel)
    assert failed(await dget(client, d, path, key=ec.generate_private_key(ec.SECP256R1())))
    # oude / toekomstige ts
    assert failed(await dget(client, d, path, ts=int(time.time()) - 61))
    assert failed(await dget(client, d, path, ts=int(time.time()) + 61))
    assert (await dget(client, d, path, ts=int(time.time()) - 55)).status_code == 200
    # hergebruikte nonce
    h = d.signed_headers("GET", path)
    assert (await client.get(path, headers=h)).status_code == 200
    assert failed(await client.get(path, headers=h))
    # getekend voor een ander pad
    other = f"/device/v1/keys/{key['id']}/sealed"
    assert failed(await client.get(other, headers=d.signed_headers("GET", path)))
    # querystring hoort bij het pad
    assert failed(await client.get(path + "?x=1", headers=d.signed_headers("GET", path)))
    assert (
        await client.get(path + "?x=1", headers=d.signed_headers("GET", path + "?x=1"))
    ).status_code == 200
    # onbekend toestel, ontbrekende/kapotte headers
    ghost = FakeDevice(dev_env.ca)
    ghost.device_id = "00000000-0000-4000-8000-000000000000"
    assert failed(await dget(client, ghost, path))
    assert failed(await client.get(path))
    bad = {**d.signed_headers("GET", path), "X-HS-Nonce": "kort"}
    assert failed(await client.get(path, headers=bad))
    # andermans sleutel of onbekende sleutel → 404
    r = await dget(client, d, "/device/v1/keys/00000000-0000-4000-8000-000000000000/sealed")
    assert r.status_code == 404


async def test_nonces_cleaned_up(client: AsyncClient, dev_env: Any, clock: dict[str, int]) -> None:
    vid = await su_user(client)
    d, _key, _ = await pair(client, dev_env.ca, vid)
    assert (await dget(client, d, "/device/v1/status", ts=clock["t"])).status_code == 200
    assert await _count("device_nonces") == 1
    clock["t"] += 121
    assert (await dget(client, d, "/device/v1/status", ts=clock["t"])).status_code == 200
    assert await _count("device_nonces") == 1


# ─────────────── Intrekken ───────────────


async def test_revoke_deletes_vault_keys(client: AsyncClient, dev_env: Any, mailbox: Any) -> None:
    vid = await su_user(client)
    d, key, _ = await pair(client, dev_env.ca, vid)
    assert await _count("vault_keys") == 1
    assert (await client.delete(f"/devices/{d.device_id}")).status_code == 204
    assert await _count("vault_keys") == 0
    assert (await client.get(f"/vault/{vid}/keys")).json()["keys"] == []
    assert (await client.get("/devices")).json()["devices"] == []
    # app: status 200 'revoked' zonder sleutels; kopie ophalen 401
    st = await dget(client, d, "/device/v1/status")
    assert st.status_code == 200 and st.json() == {
        "device_id": d.device_id,
        "state": "revoked",
        "keys": [],
        "approvals": [],
    }
    r = await dget(client, d, f"/device/v1/keys/{key['id']}/sealed")
    assert r.status_code == 401
    assert (await client.delete(f"/devices/{d.device_id}")).status_code == 404
    ev = await _events("device_revoke")
    assert ev == [{"event": "device_revoke", "detail": {"device_id": d.device_id, "keys": 1}}]
    assert mailbox.subjects()[-1] == "HorseSafe: toestel verwijderd"
    # telefoonsleutels gaan niet via de vault-key-routes
    assert (await client.delete(f"/vault/{vid}/keys/{key['id']}")).status_code == 404


# ─────────────── Testvlag en prod-guard ───────────────


async def test_test_flag_relaxes_only_listed_checks(
    client: AsyncClient, dev_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    vid = await su_user(client)
    dev_p, bio_p = debug_profiles()
    # zonder vlag: software-attestation geweigerd
    pid, web = await started(client, vid)
    r = await claim(client, FakeDevice(dev_env.ca, dev=dev_p, bio=bio_p), web, pid)
    assert r.json()["detail"] == {"error": "attestation_invalid", "reason": "security_level"}
    monkeypatch.setenv("HORSESAFE_TEST_DEVICE_ATTESTATION", "1")
    # met vlag: software + .debug + willekeurige signer toegestaan
    r = await claim(client, FakeDevice(dev_env.ca, dev=dev_p, bio=bio_p), web, pid)
    assert r.status_code == 201, r.text
    c = (await client.get(f"/devices/pairings/{pid}")).json()["claim"]
    assert c["security_level"] == "Software"
    # de overige controles blijven
    for prof, reason in (
        (replace(bio_p, user_auth_type=1), "no_biometric"),
        (replace(bio_p, boot_state=SELF_SIGNED), "boot_unverified"),
        (replace(bio_p, packages=("com.example.evil",)), "package_mismatch"),
        (replace(bio_p, challenge=b"\x00" * 32), "challenge_mismatch"),
    ):
        pid, web = await started(client, vid)
        r = await claim(client, FakeDevice(dev_env.ca, dev=dev_p, bio=prof), web, pid)
        assert r.json()["detail"] == {"error": "attestation_invalid", "reason": reason}


async def test_test_flag_trusts_fake_device_root(
    client: AsyncClient, dev_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """De vaste nep-app-root (CLI/Playwright) geldt alleen met de testvlag."""
    vid = await su_user(client)
    dev_p, bio_p = debug_profiles()
    pid, web = await started(client, vid)
    fixed = FakeAttestationCA(fixed_root=True)
    r = await claim(client, FakeDevice(fixed, dev=dev_p, bio=bio_p), web, pid)
    assert r.json()["detail"]["reason"] == "root_untrusted"
    monkeypatch.setenv("HORSESAFE_TEST_DEVICE_ATTESTATION", "1")
    dev_env.fetch_fail = True  # testvlag: onbereikbare lijst telt als leeg
    r = await claim(client, FakeDevice(fixed, dev=dev_p, bio=bio_p), web, pid)
    assert r.status_code == 201, r.text


def test_app_refuses_test_device_attestation_with_production_rp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backend.app import create_app

    monkeypatch.setenv("HORSESAFE_TEST_DEVICE_ATTESTATION", "1")
    monkeypatch.delenv("HORSESAFE_WEBAUTHN_RP_ID", raising=False)  # default icthorsecloud.nl
    with pytest.raises(RuntimeError, match="TEST_DEVICE_ATTESTATION"):
        create_app()
    monkeypatch.setenv("HORSESAFE_WEBAUTHN_RP_ID", "localhost")
    assert create_app() is not None


async def test_health_shows_test_device_attestation(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (await client.get("/health")).json()["test_device_attestation"] is False
    monkeypatch.setenv("HORSESAFE_TEST_DEVICE_ATTESTATION", "1")
    assert (await client.get("/health")).json()["test_device_attestation"] is True


def test_vendored_google_roots() -> None:
    from backend.services import android_attestation as aa

    roots = aa.load_roots()
    assert len(roots) == 2
    names = {r.subject.rfc4514_string() for r in roots}
    assert "C=US,O=Google LLC,OU=Android,CN=Key Attestation CA1" in names
    assert any("f92009e853b6b045" in n for n in names)
