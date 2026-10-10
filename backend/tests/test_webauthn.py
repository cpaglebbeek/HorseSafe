"""v0.2.0-Koblitz — WebAuthn-opties en registratie met server-verificatie (§12.4, §12.6.0-1).

Alle attestations en assertions komen van een in-test softwareauthenticator (tests/softauth.py)
met een test-root; de testvlag ``HORSESAFE_TEST_ATTESTATION`` staat alleen aan waar nodig.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from httpx import AsyncClient

from .hwkeys_helpers import (
    build_enroll_body,
    enroll,
    fake_sealed,
    register_options,
    setup_user,
    stepup_bio,
)
from .softauth import (
    AAGUID_BIO,
    AAGUID_OTHER,
    AAGUID_YK5,
    SoftAuthenticator,
    TestCA,
    b64u_dec,
)


async def _audit_events(event_like: str = "vault_key_%") -> list[dict[str, Any]]:
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(
            "SELECT event, detail, ip FROM audit_log WHERE event LIKE ? ORDER BY id", (event_like,)
        )
        return [dict(r) for r in await cur.fetchall()]


# ─────────────── Opties ───────────────


async def test_options_require_session(client: AsyncClient, hw_env: TestCA) -> None:
    r = await client.post("/webauthn/options", json={"purpose": "stepup"})
    assert r.status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"purpose": "register", "kind": "bio"},  # vault_id ontbreekt
        {"purpose": "register", "vault_id": "VID"},  # kind ontbreekt
        {"purpose": "unlock", "vault_id": "VID", "kind": "bio"},  # kind verboden
        {"purpose": "stepup", "vault_id": "VID"},  # vault_id verboden
        {"purpose": "register", "vault_id": "VID", "kind": "phone"},  # Miller
        {"purpose": "relay"},
    ],
)
async def test_options_validation(client: AsyncClient, hw_env: TestCA, body: dict[str, Any]) -> None:
    vid = await setup_user(client)
    body = {k: (vid if v == "VID" else v) for k, v in body.items()}
    r = await client.post("/webauthn/options", json=body)
    assert r.status_code == 422, r.text


async def test_register_options_shape(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    r = await register_options(client, vid, "bio")
    assert r.status_code == 200, r.text
    o = r.json()
    assert o["purpose"] == "register"
    assert o["rp"] == {"id": "localhost", "name": "HorseSafe"}
    assert len(b64u_dec(o["prf_salt"])) == 32
    assert len(b64u_dec(o["create"]["challenge"])) == 32
    assert o["create"]["challenge"] != o["assert"]["challenge"]
    assert o["pub_key_cred_params"] == [-8, -7]
    assert o["authenticator_selection"]["authenticator_attachment"] == "cross-platform"
    assert o["authenticator_selection"]["user_verification"] == "required"
    assert o["attestation"] == "direct" and o["hints"] == ["security-key"]
    assert b64u_dec(o["user"]["id"]).decode()  # UTF-8(user_id)
    assert o["user"]["name"] == "keys@example.com"

    # De server bewaart alleen de hash van de challenge, nooit de challenge zelf
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute("SELECT * FROM webauthn_challenges ORDER BY created_at")
        rows = [dict(x) for x in await cur.fetchall()]
    assert {r["purpose"] for r in rows} == {"register", "register_assert"}
    by_id = {r["id"]: r for r in rows}
    c = by_id[o["create"]["challenge_id"]]
    assert c["challenge_hash"] == hashlib.sha256(b64u_dec(o["create"]["challenge"])).hexdigest()
    assert o["create"]["challenge"] not in json.dumps(rows)
    assert by_id[o["assert"]["challenge_id"]]["parent_id"] == c["id"]
    assert c["key_id"] == o["key_id"] and c["prf_salt"] == o["prf_salt"]


async def test_options_unknown_vault_404(client: AsyncClient, hw_env: TestCA) -> None:
    await setup_user(client)
    r = await register_options(client, "00000000-0000-4000-8000-000000000000")
    assert r.status_code == 404


async def test_unlock_options_without_keys(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    r = await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "no_usable_keys"
    r = await client.post("/webauthn/options", json={"purpose": "stepup"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "no_bio_keys"


async def test_too_many_challenges(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    for _ in range(5):
        assert (await register_options(client, vid)).status_code == 200
    r = await register_options(client, vid)
    assert r.status_code == 429 and r.json()["detail"]["error"] == "too_many_challenges"


# ─────────────── Registratie: succes ───────────────


@pytest.mark.parametrize("alg", [-7, -8])
async def test_register_bio_success(client: AsyncClient, hw_env: TestCA, alg: int) -> None:
    vid = await setup_user(client)
    auth = SoftAuthenticator(hw_env, AAGUID_BIO, alg=alg)
    r = await enroll(client, vid, auth, label="  Bio laptop  ")
    assert r.status_code == 201, r.text
    key = r.json()
    assert key["kind"] == "bio" and key["status"] == "active" and key["label"] == "Bio laptop"
    assert key["credential_id"] == auth.cred_id
    assert key["aaguid"] == str(AAGUID_BIO)
    assert key["authenticator"] == "Test YubiKey Bio"
    assert key["recovery"] is None
    for forbidden in ("sealed", "cose_public_key", "sign_count"):
        assert forbidden not in key

    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute("SELECT att_fmt, sign_count, prf_salt FROM vault_keys")
        row = dict(await cur.fetchone())  # type: ignore[arg-type]
    assert row["att_fmt"] == "packed" and row["sign_count"] == auth.sign_count
    assert row["prf_salt"] == key["prf_salt"]

    events = await _audit_events()
    assert [e["event"] for e in events] == ["vault_key_add"]
    assert json.loads(events[0]["detail"])["aaguid"] == str(AAGUID_BIO)


async def test_register_recovery_accepts_yubikey5(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env, AAGUID_YK5), kind="recovery", label="Kluis")
    assert r.status_code == 201, r.text
    rec = r.json()["recovery"]
    assert rec["state"] == "idle" and rec["release_at"] is None


async def test_register_mail_sent(client: AsyncClient, hw_env: TestCA, mailbox: Any) -> None:
    vid = await setup_user(client)
    assert (await enroll(client, vid, SoftAuthenticator(hw_env))).status_code == 201
    assert mailbox.subjects() == ["HorseSafe: nieuwe sleutel gekoppeld"]
    body = mailbox.sent[0]["body"]
    assert "YubiKey Bio" in body and "Was jij dit niet?" in body and "UTC" in body


# ─────────────── Registratie: afwijzingen (§12.14) ───────────────


REJECTS: list[tuple[str, dict[str, Any], dict[str, Any], str, int]] = [
    # (naam, create_kw, get_kw, foutcode, status)
    ("be", {"be": True}, {}, "not_device_bound", 400),
    ("bs", {"be": True, "bs": True}, {}, "not_device_bound", 400),
    ("uv", {"uv": False}, {}, "uv_missing", 400),
    ("up", {"up": False}, {}, "up_missing", 400),
    ("origin", {"origin": "https://evil.example"}, {}, "origin_mismatch", 400),
    ("cross", {"cross_origin": True}, {}, "origin_mismatch", 400),
    ("rpid", {"rp_id": "evil.example"}, {}, "rp_id_mismatch", 400),
    ("type", {"typ": "webauthn.get"}, {}, "bad_client_data", 400),
    ("none", {"fmt": "none"}, {}, "attestation_invalid", 400),
    ("self", {"fmt": "packed-self"}, {}, "attestation_invalid", 400),
    ("leaf-aaguid", {"leaf_aaguid": AAGUID_OTHER}, {}, "attestation_invalid", 400),
    ("no-leaf-aaguid", {"leaf_aaguid": None}, {}, "attestation_invalid", 400),
    ("get-uv", {}, {"uv": False}, "uv_missing", 400),
    ("get-be", {}, {"be": True}, "not_device_bound", 400),
    ("get-sig", {}, {"bad_signature": True}, "assertion_invalid", 400),
    ("get-origin", {}, {"origin": "https://evil.example"}, "origin_mismatch", 400),
]


@pytest.mark.parametrize(("name", "create_kw", "get_kw", "code", "status"), REJECTS)
async def test_register_rejected(
    client: AsyncClient,
    hw_env: TestCA,
    name: str,
    create_kw: dict[str, Any],
    get_kw: dict[str, Any],
    code: str,
    status: int,
) -> None:
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env), create_kw=create_kw, get_kw=get_kw)
    assert r.status_code == status, (name, r.text)
    assert r.json()["detail"]["error"] == code, name
    # Geen sleutel, geen vault_key_add; wel een afwijzingsregel met de foutcode
    events = await _audit_events()
    assert [e["event"] for e in events] == ["vault_key_add_rejected"]
    assert json.loads(events[0]["detail"]) == {"vault_id": vid, "kind": "bio", "reason": code}
    assert (await client.get(f"/vault/{vid}/keys")).json()["keys"] == []


async def test_register_untrusted_root(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    other_ca = TestCA("Andere root")
    r = await enroll(client, vid, SoftAuthenticator(other_ca))
    assert r.status_code == 400 and r.json()["detail"]["error"] == "attestation_invalid"


async def test_register_empty_roots_fail_closed(
    client: AsyncClient, hw_env: TestCA, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "leeg.pem"
    empty.write_text("# geen certificaten\n")
    monkeypatch.setenv("HORSESAFE_ATTESTATION_ROOTS_PATH", str(empty))
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env))
    assert r.status_code == 400 and r.json()["detail"]["error"] == "attestation_invalid"


async def test_register_alg_not_allowed(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env, alg=-35))
    assert r.status_code == 400 and r.json()["detail"]["error"] == "alg_not_allowed"


async def test_register_non_bio_as_bio(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env, AAGUID_YK5), kind="bio")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "not_bio_authenticator"
    r = await enroll(client, vid, SoftAuthenticator(hw_env, AAGUID_OTHER), kind="bio")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "authenticator_not_allowed"
    r = await enroll(client, vid, SoftAuthenticator(hw_env, AAGUID_OTHER), kind="recovery")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "authenticator_not_allowed"


async def test_register_none_with_test_flag(
    client: AsyncClient, hw_env: TestCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Testvlag: fmt=none mag en de allowlist wordt overgeslagen; AAGUID wordt wel opgeslagen."""
    monkeypatch.setenv("HORSESAFE_TEST_ATTESTATION", "1")
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env, AAGUID_OTHER), create_kw={"fmt": "none"})
    assert r.status_code == 201, r.text
    assert r.json()["aaguid"] == str(AAGUID_OTHER) and r.json()["authenticator"] is None
    # BE en UV blijven ook met de testvlag verplicht (nieuwe gebruiker: geen step-up nodig)
    await client.post("/auth/logout")
    vid2 = await setup_user(client, "tweede@example.com")
    r = await enroll(client, vid2, SoftAuthenticator(hw_env), create_kw={"fmt": "none", "be": True})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "not_device_bound"
    r = await enroll(client, vid2, SoftAuthenticator(hw_env), create_kw={"fmt": "none", "uv": False})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "uv_missing"


async def test_register_challenge_reuse_and_expiry(
    client: AsyncClient, hw_env: TestCA, clock: dict[str, int]
) -> None:
    vid = await setup_user(client)
    auth = SoftAuthenticator(hw_env)
    opts = (await register_options(client, vid)).json()
    body, _ = build_enroll_body(opts, auth, vid)
    # Verkeerde key_id t.o.v. de challenge
    r = await client.post(f"/vault/{vid}/keys", json={**body, "key_id": "00000000-0000-4000-8000-000000000001"})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"
    # Challenges zijn nu verbruikt: hetzelfde (correcte) verzoek faalt ook
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"
    # Verlopen challenge
    opts = (await register_options(client, vid)).json()
    body, _ = build_enroll_body(opts, auth, vid)
    clock["t"] += 301
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"


async def test_register_challenge_wrong_kind(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    opts = (await register_options(client, vid, "recovery")).json()
    body, _ = build_enroll_body(opts, SoftAuthenticator(hw_env), vid, kind="bio")
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"


async def test_register_sealed_kid_mismatch(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    r = await enroll(client, vid, SoftAuthenticator(hw_env),
                     sealed=fake_sealed("00000000-0000-4000-8000-000000000009"))
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_sealed"


async def test_register_credential_mismatch(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    auth = SoftAuthenticator(hw_env)
    opts = (await register_options(client, vid)).json()
    body, _ = build_enroll_body(opts, auth, vid)
    body["assert"]["credential_id"] = SoftAuthenticator(hw_env).cred_id
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "credential_mismatch"
    # credential_id in create ≠ credential in authData
    opts = (await register_options(client, vid)).json()
    body, _ = build_enroll_body(opts, auth, vid)
    other = SoftAuthenticator(hw_env).cred_id
    body["create"]["credential_id"] = other
    body["assert"]["credential_id"] = other
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "credential_mismatch"


async def test_register_phone_kind_rejected(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    opts = (await register_options(client, vid)).json()
    body, _ = build_enroll_body(opts, SoftAuthenticator(hw_env), vid)
    r = await client.post(f"/vault/{vid}/keys", json={**body, "kind": "phone"})
    assert r.status_code == 422


async def test_second_key_requires_stepup(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    # Opties melden de step-up-eis al vroeg
    r = await register_options(client, vid, "recovery")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    r = await stepup_bio(client, bio)
    assert r.status_code == 200, r.text
    r = await enroll(client, vid, SoftAuthenticator(hw_env, AAGUID_YK5), kind="recovery")
    assert r.status_code == 201, r.text
    # Zelfde credential nogmaals → 409 credential_exists
    r = await enroll(client, vid, bio)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "credential_exists"


async def test_exclude_credentials_listed(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    assert (await stepup_bio(client, bio)).status_code == 200
    o = (await register_options(client, vid, "recovery")).json()
    assert o["exclude_credentials"] == [bio.cred_id]


async def test_key_limit(client: AsyncClient, hw_env: TestCA, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HORSESAFE_VAULT_KEYS_MAX", "1")
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    assert (await stepup_bio(client, bio)).status_code == 200
    r = await register_options(client, vid)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "too_many_keys"
