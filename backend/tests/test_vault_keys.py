"""v0.2.0-Koblitz — hardware-sleutels: lijst, ontgrendelen, noodsleutel, rekey (§12.6-§12.7)."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from httpx import AsyncClient

from . import seal_v2_ref as seal
from .hwkeys_helpers import (
    build_enroll_body,
    enable_totp,
    enroll,
    fake_sealed,
    register_options,
    setup_user,
    stepup_bio,
    stepup_totp,
    unlock,
)
from .softauth import AAGUID_YK5, SoftAuthenticator, TestCA
from .test_vault import FAKE_KDBX_BLOB

H = 3600


async def _events(prefix: str = "%") -> list[dict[str, Any]]:
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(
            "SELECT event, detail, ip, user_agent FROM audit_log WHERE event LIKE ? ORDER BY id",
            (prefix,),
        )
        return [dict(r) for r in await cur.fetchall()]


async def _bio_and_recovery(
    client: AsyncClient, ca: TestCA
) -> tuple[str, SoftAuthenticator, dict[str, Any], SoftAuthenticator, dict[str, Any]]:
    vid = await setup_user(client)
    bio = SoftAuthenticator(ca)
    r = await enroll(client, vid, bio)
    assert r.status_code == 201, r.text
    bio_key = r.json()
    assert (await stepup_bio(client, bio)).status_code == 200
    rec = SoftAuthenticator(ca, AAGUID_YK5)
    r = await enroll(client, vid, rec, kind="recovery", label="Reserve-YubiKey kluis")
    assert r.status_code == 201, r.text
    return vid, bio, bio_key, rec, r.json()


# ─────────────── Auth en eigendom ───────────────


async def test_keys_require_auth(client: AsyncClient) -> None:
    assert (await client.get("/vault/x/keys")).status_code == 401


async def test_keys_require_mfa(client: AsyncClient, hw_env: TestCA) -> None:
    await setup_user(client)
    await enable_totp(client)
    await client.post("/auth/logout")
    await client.post(
        "/auth/login", json={"email": "keys@example.com", "password": "SuperStrongPw123!"}
    )
    r = await client.get("/vault/x/keys")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "mfa_required"


async def test_other_user_cannot_touch_keys(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client, "owner@example.com")
    bio = SoftAuthenticator(hw_env)
    key = (await enroll(client, vid, bio)).json()
    await client.post("/auth/logout")
    await setup_user(client, "intruder@example.com")
    url = f"/vault/{vid}/keys/{key['id']}"
    assert (await client.get(f"/vault/{vid}/keys")).status_code == 404
    assert (await client.delete(url)).status_code == 404
    assert (await client.post(url + "/block")).status_code == 404
    assert (await client.post(url + "/release")).status_code == 404
    r = await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})
    assert r.status_code == 404


# ─────────────── Lijst ───────────────


async def test_list_shape(client: AsyncClient, hw_env: TestCA, mailbox: Any) -> None:
    vid, _bio, bio_key, _rec, rec_key = await _bio_and_recovery(client, hw_env)
    r = await client.get(f"/vault/{vid}/keys")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"keys", "notify_available", "stepup_until"}
    assert body["notify_available"] is True
    assert isinstance(body["stepup_until"], int)  # net een bio-step-up gedaan
    assert [k["id"] for k in body["keys"]] == [bio_key["id"], rec_key["id"]]
    raw = json.dumps(body)
    for forbidden in ("sealed", "cose_public_key", "sign_count"):
        assert forbidden not in raw
    assert body["keys"][1]["recovery"]["state"] == "idle"
    assert body["keys"][1]["authenticator"] == "Test YubiKey 5"


async def test_list_notify_unavailable(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    body = (await client.get(f"/vault/{vid}/keys")).json()
    assert body == {"keys": [], "notify_available": False, "stepup_until": None}


# ─────────────── Ontgrendelen ───────────────


async def test_bio_unlock_returns_sealed_after_assertion(
    client: AsyncClient, hw_env: TestCA
) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    opts = (await register_options(client, vid)).json()
    ph, kh = os.urandom(32), os.urandom(32)
    prf = os.urandom(32)
    sk, pk = seal.keypair_from_prf(prf)
    sealed = seal.seal(pk, ph, kh, vault_id=vid, key_id=opts["key_id"])
    body, _ = build_enroll_body(opts, bio, vid, sealed=sealed)
    body["public_key"] = seal.b64u(pk)
    r = await client.post(f"/vault/{vid}/keys", json=body)
    assert r.status_code == 201, r.text
    kid = r.json()["id"]

    o = (await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})).json()
    assert o["allow_credentials"] == [
        {
            "key_id": kid,
            "kind": "bio",
            "credential_id": bio.cred_id,
            "prf_salt": r.json()["prf_salt"],
        }
    ]
    r = await unlock(client, vid, bio, kid)
    assert r.status_code == 200, r.text
    assert r.json() == {"id": kid, "sealed": sealed}
    # De client opent met een zelf opgebouwde AAD (zelfde vault en key) → ph/kh terug
    assert seal.unseal(
        r.json()["sealed"], sk, purpose="store", vault_id=vid, bind=kid, kid=kid
    ) == (ph, kh)
    keys = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert keys[0]["last_used_at"] is not None
    assert [e["event"] for e in await _events("vault_key_unlock")] == ["vault_key_unlock"]
    assert "sealed" not in json.dumps(await _events())


async def test_old_sealed_endpoint_gone(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    kid = (await enroll(client, vid, SoftAuthenticator(hw_env))).json()["id"]
    r = await client.get(f"/vault/{vid}/keys/{kid}/sealed")
    assert r.status_code in (404, 405)


async def test_unlock_rejections(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    kid = (await enroll(client, vid, bio)).json()["id"]
    # Verkeerde credential voor deze sleutel
    r = await unlock(client, vid, SoftAuthenticator(hw_env), kid)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "credential_mismatch"
    # Kapotte handtekening, UV ontbreekt, BE gezet
    for kw, code in (
        ({"bad_signature": True}, "assertion_invalid"),
        ({"uv": False}, "uv_missing"),
        ({"be": True}, "not_device_bound"),
        ({"origin": "https://x.example"}, "origin_mismatch"),
    ):
        r = await unlock(client, vid, bio, kid, **kw)
        assert r.status_code == 400 and r.json()["detail"]["error"] == code, kw
    # Challenge van een andere purpose
    o = (await client.post("/webauthn/options", json={"purpose": "stepup"})).json()
    body = {"challenge_id": o["challenge_id"], **bio.get(o["challenge"])}
    r = await client.post(f"/vault/{vid}/keys/{kid}/unlock", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"
    # Hergebruikte challenge
    o = (await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})).json()
    body = {"challenge_id": o["challenge_id"], **bio.get(o["challenge"])}
    assert (await client.post(f"/vault/{vid}/keys/{kid}/unlock", json=body)).status_code == 200
    r = await client.post(f"/vault/{vid}/keys/{kid}/unlock", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"


async def test_sign_count_regression(client: AsyncClient, hw_env: TestCA, mailbox: Any) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    kid = (await enroll(client, vid, bio)).json()["id"]
    assert (await unlock(client, vid, bio, kid)).status_code == 200
    r = await unlock(client, vid, bio, kid, counter=1)  # teller ging terug (kloon?)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "sign_count_regression"
    assert [e["event"] for e in await _events("vault_key_clone%")] == ["vault_key_clone_suspect"]
    assert "HorseSafe: verdachte sleutel-teller" in mailbox.subjects()


async def test_sign_count_zero_authenticator_allowed(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    opts = (await register_options(client, vid)).json()
    body, _ = build_enroll_body(opts, bio, vid, get_kw={"counter": 0})
    kid = (await client.post(f"/vault/{vid}/keys", json=body)).json()["id"]
    assert (await unlock(client, vid, bio, kid, counter=0)).status_code == 200
    assert (await unlock(client, vid, bio, kid, counter=0)).status_code == 200


# ─────────────── Noodsleutel (§12.6.6-7, §12.7) ───────────────


async def test_recovery_lifecycle(
    client: AsyncClient, hw_env: TestCA, clock: dict[str, int], mailbox: Any
) -> None:
    vid, _bio, _bk, rec, rk = await _bio_and_recovery(client, hw_env)
    url = f"/vault/{vid}/keys/{rk['id']}"

    # Zonder aanvraag: niet in de unlock-opties, en direct POST → 423 recovery_idle
    o = (await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})).json()
    assert [c["kind"] for c in o["allow_credentials"]] == ["bio"]
    body = {"challenge_id": o["challenge_id"], **rec.get(o["challenge"])}
    r = await client.post(url + "/unlock", json=body)
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_idle"

    # Aanvragen → 24 u wachten, mail + audit
    t0 = clock["t"]
    r = await client.post(url + "/release")
    assert r.status_code == 200, r.text
    assert r.json()["recovery"]["state"] == "waiting"
    assert r.json()["recovery"]["release_at"] == t0 + 24 * H
    assert r.json()["recovery"]["release_until"] == t0 + 48 * H
    assert "HorseSafe: vrijgave noodsleutel aangevraagd" in mailbox.subjects()
    n_mail = len(mailbox.sent)

    # Herhaalde aanvraag verlengt niet en mailt niet
    clock["t"] += H
    r = await client.post(url + "/release")
    assert r.json()["recovery"]["release_at"] == t0 + 24 * H and len(mailbox.sent) == n_mail

    # 23 u: nog wachten
    clock["t"] = t0 + 23 * H
    r = await unlock(client, vid, rec, rk["id"])
    assert r.status_code == 423
    d = r.json()["detail"]
    assert d["error"] == "recovery_waiting" and d["state"] == "waiting"
    assert d["release_at"] == t0 + 24 * H and d["release_until"] == t0 + 48 * H

    # 25 u: vrijgegeven, in de opties, ontgrendelen lukt
    clock["t"] = t0 + 25 * H
    o = (await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})).json()
    assert {c["kind"] for c in o["allow_credentials"]} == {"bio", "recovery"}
    r = await unlock(client, vid, rec, rk["id"])
    assert r.status_code == 200, r.text
    assert "HorseSafe: noodsleutel gebruikt" in mailbox.subjects()
    assert [e["event"] for e in await _events("recovery_key_used")] == ["recovery_key_used"]

    # Daarna: gebruikt
    r = await unlock(client, vid, rec, rk["id"])
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_consumed"

    # Nieuwe aanvraag vanuit consumed; na 49 u verlopen
    t1 = clock["t"]
    r = await client.post(url + "/release")
    assert (
        r.json()["recovery"]["state"] == "waiting"
        and r.json()["recovery"]["release_consumed_at"] is None
    )
    clock["t"] = t1 + 49 * H
    r = await unlock(client, vid, rec, rk["id"])
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_expired"
    keys = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert keys[1]["recovery"]["state"] == "expired"


async def test_release_without_mailer(client: AsyncClient, hw_env: TestCA) -> None:
    vid, _b, _bk, _r, rk = await _bio_and_recovery(client, hw_env)
    r = await client.post(f"/vault/{vid}/keys/{rk['id']}/release")
    assert r.status_code == 503 and r.json()["detail"]["error"] == "notify_unavailable"
    keys = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert keys[1]["recovery"]["state"] == "idle"


async def test_release_mail_failure_rolls_back(
    client: AsyncClient, hw_env: TestCA, mailbox: Any
) -> None:
    vid, _b, _bk, _r, rk = await _bio_and_recovery(client, hw_env)
    mailbox.fail = True
    r = await client.post(f"/vault/{vid}/keys/{rk['id']}/release")
    assert r.status_code == 503 and r.json()["detail"]["error"] == "notify_failed"
    keys = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert keys[1]["recovery"]["state"] == "idle"
    assert keys[1]["recovery"]["release_at"] is None
    ev = await _events("notify_failed")
    assert [json.loads(e["detail"]) for e in ev] == [{"event": "recovery_release_request"}]
    assert await _events("recovery_release_request") == []


async def test_cancel(client: AsyncClient, hw_env: TestCA, mailbox: Any) -> None:
    vid, _b, bk, _r, rk = await _bio_and_recovery(client, hw_env)
    url = f"/vault/{vid}/keys/{rk['id']}"
    r = await client.delete(url + "/release")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "nothing_to_cancel"
    assert (await client.post(url + "/release")).status_code == 200
    r = await client.delete(url + "/release")
    assert r.status_code == 200 and r.json()["recovery"]["state"] == "idle"
    assert "HorseSafe: vrijgave noodsleutel geannuleerd" in mailbox.subjects()
    assert [e["event"] for e in await _events("recovery_release_%")] == [
        "recovery_release_request",
        "recovery_release_cancel",
    ]
    # Alleen voor noodsleutels
    r = await client.post(f"/vault/{vid}/keys/{bk['id']}/release")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "not_recovery_key"
    r = await client.post(f"/vault/{vid}/keys/{bk['id']}/block")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "not_recovery_key"


async def test_block_and_unblock(
    client: AsyncClient, hw_env: TestCA, mailbox: Any, clock: dict[str, int]
) -> None:
    vid, bio, _bk, rec, rk = await _bio_and_recovery(client, hw_env)
    url = f"/vault/{vid}/keys/{rk['id']}"
    assert (await client.post(url + "/release")).status_code == 200

    # Blokkeren: geen step-up nodig, lopende vrijgave gewist
    await client.post("/auth/logout")
    await client.post(
        "/auth/login", json={"email": "keys@example.com", "password": "SuperStrongPw123!"}
    )
    r = await client.post(url + "/block")
    assert r.status_code == 200, r.text
    rk2 = r.json()
    assert rk2["status"] == "blocked" and rk2["recovery"]["state"] == "blocked"
    assert rk2["recovery"]["blocked_by"] == "web" and rk2["recovery"]["release_at"] is None
    n_mail = len(mailbox.sent)
    assert (await client.post(url + "/block")).status_code == 200  # idempotent, geen mail
    assert len(mailbox.sent) == n_mail

    # Geblokkeerd: geen vrijgave, geen ontgrendeling, blokkade verloopt niet
    r = await client.post(url + "/release")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "recovery_blocked"
    clock["t"] += 30 * 24 * H
    r = await unlock(client, vid, rec, rk["id"])
    assert r.status_code == 423 and r.json()["detail"]["error"] == "recovery_blocked"

    # Opheffen: zonder step-up → 403
    r = await client.delete(url + "/block")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    # Met bio-step-up → 200, state idle
    assert (await stepup_bio(client, bio)).status_code == 200
    r = await client.delete(url + "/block")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active" and r.json()["recovery"]["state"] == "idle"
    r = await client.delete(url + "/block")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "not_blocked"
    subjects = mailbox.subjects()
    assert "HorseSafe: noodsleutel geblokkeerd" in subjects
    assert "HorseSafe: blokkade noodsleutel opgeheven" in subjects
    ev = await _events("recovery_%block")
    assert [e["event"] for e in ev] == ["recovery_block", "recovery_unblock"]
    assert json.loads(ev[1]["detail"])["stepup_method"] == "bio"


async def test_unblock_with_totp_stepup_refused(client: AsyncClient, hw_env: TestCA) -> None:
    """Besluit 3: opheffen nooit met TOTP. TOTP-step-up kan alleen zonder actieve Bio."""
    vid = await setup_user(client)
    secret = await enable_totp(client)
    rec = SoftAuthenticator(hw_env, AAGUID_YK5)
    r = await enroll(client, vid, rec, kind="recovery", label="Kluis")
    assert r.status_code == 201, r.text
    url = f"/vault/{vid}/keys/{r.json()['id']}"
    assert (await client.post(url + "/block")).status_code == 200
    r = await stepup_totp(client, secret)
    assert r.status_code == 200, r.text
    r = await client.delete(url + "/block")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_bio_required"


async def test_unblock_needs_bio_from_before_block(
    client: AsyncClient, hw_env: TestCA, mailbox: Any, clock: dict[str, int]
) -> None:
    """R6 / besluit 3 (reviewbevinding 3): wie na de blokkade met TOTP-step-up een eigen Bio
    koppelt, kan daarmee de blokkade niet opheffen."""
    vid = await setup_user(client)
    secret = await enable_totp(client)
    rec = SoftAuthenticator(hw_env, AAGUID_YK5)
    r = await enroll(client, vid, rec, kind="recovery", label="Kluis")
    assert r.status_code == 201, r.text
    url = f"/vault/{vid}/keys/{r.json()['id']}"
    assert (await client.post(url + "/block")).status_code == 200
    clock["t"] += 60
    # Aanvaller: TOTP-step-up (geen Bio) → eigen, echte Bio koppelen → Bio-step-up → opheffen
    assert (await stepup_totp(client, secret)).status_code == 200
    own = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, own, label="Eigen Bio")).status_code == 201
    assert (await stepup_bio(client, own)).status_code == 200
    r = await client.delete(url + "/block")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_key_too_new"
    keys = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert next(k for k in keys if k["kind"] == "recovery")["status"] == "blocked"
    assert "HorseSafe: blokkade noodsleutel opgeheven" not in mailbox.subjects()
    ev = await _events("recovery_unblock%")
    assert [e["event"] for e in ev] == ["recovery_unblock_rejected"]


# ─────────────── Verwijderen ───────────────


async def test_delete_key(client: AsyncClient, hw_env: TestCA, mailbox: Any) -> None:
    vid = await setup_user(client)
    kid = (await enroll(client, vid, SoftAuthenticator(hw_env))).json()["id"]
    r = await client.delete(f"/vault/{vid}/keys/{kid}")
    assert r.status_code == 204 and r.content == b""
    assert (await client.get(f"/vault/{vid}/keys")).json()["keys"] == []
    assert "HorseSafe: sleutel verwijderd" in mailbox.subjects()
    assert (await client.delete(f"/vault/{vid}/keys/{kid}")).status_code == 404


# ─────────────── Opnieuw verzegelen (§12.6.4) ───────────────


async def test_reseal(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    kid = (await enroll(client, vid, bio)).json()["id"]
    new = fake_sealed(kid)
    payload = {"items": [{"id": kid, "sealed": new}]}
    # Login-sessie zonder step-up → 403
    await client.post("/auth/logout")
    await client.post(
        "/auth/login", json={"email": "keys@example.com", "password": "SuperStrongPw123!"}
    )
    r = await client.put(f"/vault/{vid}/keys/sealed", json=payload)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    assert (await stepup_bio(client, bio)).status_code == 200
    r = await client.put(
        f"/vault/{vid}/keys/sealed", json={"items": [{"id": kid, "sealed": fake_sealed(vid)}]}
    )
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_sealed"
    r = await client.put(
        f"/vault/{vid}/keys/sealed",
        json={"items": [{"id": "00000000-0000-4000-8000-000000000000", "sealed": new}]},
    )
    assert r.status_code == 400 and r.json()["detail"]["error"] == "unknown_key"
    r = await client.put(
        f"/vault/{vid}/keys/sealed", json={"items": [{"id": kid, "sealed": new}] * 2}
    )
    assert r.status_code == 422
    r = await client.put(f"/vault/{vid}/keys/sealed", json=payload)
    assert r.status_code == 200 and r.json() == {"updated": 1}
    assert (await unlock(client, vid, bio, kid)).json()["sealed"] == new


# ─────────────── Rekey (§12.6.5) ───────────────


async def _rekey(
    client: AsyncClient,
    vid: str,
    etag: str | None,
    items: list[dict[str, str]],
    blob: bytes = FAKE_KDBX_BLOB + b"-nieuw",
) -> Any:
    headers = {"If-Match": etag} if etag is not None else {}
    return await client.put(
        f"/vault/{vid}/rekey",
        headers=headers,
        data={"sealed": json.dumps({"items": items})},
        files={"blob": ("v.kdbx", blob, "application/octet-stream")},
    )


async def test_rekey(client: AsyncClient, hw_env: TestCA, mailbox: Any) -> None:
    vid, bio, bk, _rec, rk = await _bio_and_recovery(client, hw_env)
    etag = (await client.get("/vault")).json()[0]["etag"]
    # Geblokkeerde noodsleutel telt ook mee
    assert (await client.post(f"/vault/{vid}/keys/{rk['id']}/block")).status_code == 200
    items = [
        {"id": bk["id"], "sealed": fake_sealed(bk["id"])},
        {"id": rk["id"], "sealed": fake_sealed(rk["id"])},
    ]

    r = await _rekey(client, vid, None, items)
    assert r.status_code == 428 and r.json()["detail"]["error"] == "if_match_required"
    r = await _rekey(client, vid, etag, items[:1])
    assert r.status_code == 409 and r.json()["detail"]["error"] == "keys_mismatch"
    r = await _rekey(client, vid, etag, [items[0], {**items[1], "sealed": fake_sealed(bk["id"])}])
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_sealed"
    r = await _rekey(client, vid, "verkeerd", items)
    assert r.status_code == 412 and r.json()["detail"]["current_etag"] == etag
    r = await client.put(
        f"/vault/{vid}/rekey",
        headers={"If-Match": etag},
        data={"sealed": "{kapot"},
        files={"blob": ("v.kdbx", b"x", "application/octet-stream")},
    )
    assert r.status_code == 422
    # Niets is veranderd door de mislukte pogingen
    assert (await client.get(f"/vault/{vid}")).content == FAKE_KDBX_BLOB

    r = await _rekey(client, vid, etag, items)
    assert r.status_code == 200, r.text
    assert r.json()["resealed"] == 2 and r.headers["etag"] == r.json()["vault"]["etag"] != etag
    assert (await client.get(f"/vault/{vid}")).content == FAKE_KDBX_BLOB + b"-nieuw"
    assert (await unlock(client, vid, bio, bk["id"])).json()["sealed"] == items[0]["sealed"]
    ev = await _events("vault_rekey")
    assert json.loads(ev[0]["detail"]) == {
        "vault_id": vid,
        "size": len(FAKE_KDBX_BLOB) + 6,
        "keys": 2,
    }
    assert "HorseSafe: wachtwoord of keyfile van je kluis gewijzigd" in mailbox.subjects()


async def test_rekey_requires_stepup_and_no_keys_ok(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    etag = (await client.get("/vault")).json()[0]["etag"]
    r = await _rekey(client, vid, etag, [])
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    secret = await enable_totp(client)
    assert (await stepup_totp(client, secret)).status_code == 200
    r = await _rekey(client, vid, etag, [])
    assert r.status_code == 200 and r.json()["resealed"] == 0


async def test_rekey_write_failure_rolls_back(
    client: AsyncClient, hw_env: TestCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    kid = (await enroll(client, vid, bio)).json()["id"]
    assert (await stepup_bio(client, bio)).status_code == 200
    etag = (await client.get("/vault")).json()[0]["etag"]
    sealed_before = (await unlock(client, vid, bio, kid)).json()["sealed"]

    from backend.services import storage_service

    def boom(*_a: object) -> None:
        raise OSError("schijf vol")

    monkeypatch.setattr(storage_service, "_atomic_write", boom)
    r = await _rekey(client, vid, etag, [{"id": kid, "sealed": fake_sealed(kid)}])
    assert r.status_code == 500
    assert (await client.get("/vault")).json()[0]["etag"] == etag
    assert (await unlock(client, vid, bio, kid)).json()["sealed"] == sealed_before


async def test_rekey_mail_failure_does_not_fail_committed_rekey(
    client: AsyncClient, hw_env: TestCA, mailbox: Any
) -> None:
    """Reviewronde 2: de meldmail gaat ná het antwoord (BackgroundTask); een kapotte of trage mailer
    maakt een gecommitte rekey nooit tot een (schijnbare) mislukking."""
    from backend.routes import vault_keys as route

    vid = await setup_user(client)
    secret = await enable_totp(client)
    assert (await stepup_totp(client, secret)).status_code == 200
    etag = (await client.get("/vault")).json()[0]["etag"]
    mailbox.fail = True
    r = await _rekey(client, vid, etag, [])
    assert r.status_code == 200, r.text
    assert r.json()["vault"]["etag"] == (await client.get("/vault")).json()[0]["etag"] != etag
    failed = await _events("notify_failed")
    assert any(json.loads(e["detail"]).get("event") == "vault_rekey" for e in failed)
    # De route stuurt de melding niet meer vóór het antwoord
    import inspect

    src = inspect.getsource(route.rekey)
    assert "BackgroundTask(" in src and "await _mail(" not in src
