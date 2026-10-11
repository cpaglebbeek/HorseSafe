"""v0.2.0-Koblitz — step-up (§12.8)."""

from __future__ import annotations

from typing import Any

import jwt
import pytest
from httpx import AsyncClient

from .hwkeys_helpers import enable_totp, enroll, setup_user, stepup_bio, stepup_totp
from .softauth import AAGUID_YK5, SoftAuthenticator, TestCA


def _claims(client: AsyncClient) -> dict[str, Any]:
    token = client.cookies.get("horsesafe_session")
    assert token
    return dict(jwt.decode(token, options={"verify_signature": False}))


async def test_bio_stepup_sets_claims(
    client: AsyncClient, hw_env: TestCA, clock: dict[str, int]
) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    r = await stepup_bio(client, bio)
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "method": "bio", "stepup_until": clock["t"] + 300}
    c = _claims(client)
    assert (
        c["stepup_method"] == "bio" and c["stepup_until"] == clock["t"] + 300 and c["mfa"] is True
    )
    keys = (await client.get(f"/vault/{vid}/keys")).json()["keys"]
    assert c["stepup_key"] == keys[0]["id"]


async def test_bio_stepup_rejections(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    # Andere credential (geen actieve bio van deze gebruiker)
    o = (await client.post("/webauthn/options", json={"purpose": "stepup"})).json()
    other = SoftAuthenticator(hw_env)
    r = await client.post(
        "/auth/stepup",
        json={"method": "bio", "challenge_id": o["challenge_id"], **other.get(o["challenge"])},
    )
    assert r.status_code == 400 and r.json()["detail"]["error"] == "credential_mismatch"
    # Unlock-challenge gebruiken voor step-up
    o = (await client.post("/webauthn/options", json={"purpose": "unlock", "vault_id": vid})).json()
    r = await client.post(
        "/auth/stepup",
        json={"method": "bio", "challenge_id": o["challenge_id"], **bio.get(o["challenge"])},
    )
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_challenge"
    r = await stepup_bio(client, bio, uv=False)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "uv_missing"
    assert "stepup_until" not in _claims(client)


async def test_recovery_key_cannot_stepup(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    assert (
        await enroll(
            client, vid, SoftAuthenticator(hw_env, AAGUID_YK5), kind="recovery", label="Kluis"
        )
    ).status_code == 201
    r = await client.post("/webauthn/options", json={"purpose": "stepup"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "no_bio_keys"


async def test_totp_not_allowed_with_active_bio(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    secret = await enable_totp(client)
    assert (await enroll(client, vid, SoftAuthenticator(hw_env))).status_code == 201
    r = await stepup_totp(client, secret)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_method_not_allowed"


async def test_totp_unavailable(client: AsyncClient, hw_env: TestCA) -> None:
    await setup_user(client)
    r = await client.post("/auth/stepup", json={"method": "totp", "code": "123456"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "stepup_unavailable"


async def test_totp_stepup_and_rate_limit(client: AsyncClient, hw_env: TestCA) -> None:
    await setup_user(client)
    secret = await enable_totp(client)
    r = await stepup_totp(client, secret)
    assert r.status_code == 200 and r.json()["method"] == "totp"
    assert _claims(client)["stepup_method"] == "totp"
    for _ in range(5):
        r = await client.post("/auth/stepup", json={"method": "totp", "code": "000000"})
        assert r.status_code == 401 and r.json()["detail"]["error"] == "invalid_code"
    r = await stepup_totp(client, secret)
    assert r.status_code == 429 and r.json()["detail"]["error"] == "too_many_attempts"


async def test_stepup_expires(client: AsyncClient, hw_env: TestCA, clock: dict[str, int]) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    assert (await stepup_bio(client, bio)).status_code == 200
    assert (
        await client.post(
            "/webauthn/options", json={"purpose": "register", "vault_id": vid, "kind": "recovery"}
        )
    ).status_code == 200
    clock["t"] += 301
    r = await client.post(
        "/webauthn/options", json={"purpose": "register", "vault_id": vid, "kind": "recovery"}
    )
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    assert (await client.get(f"/vault/{vid}/keys")).json()["stepup_until"] is None


async def test_login_drops_stepup(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    bio = SoftAuthenticator(hw_env)
    assert (await enroll(client, vid, bio)).status_code == 201
    assert (await stepup_bio(client, bio)).status_code == 200
    await client.post(
        "/auth/login", json={"email": "keys@example.com", "password": "SuperStrongPw123!"}
    )
    assert "stepup_until" not in _claims(client)


@pytest.mark.parametrize(
    "body", [{"method": "sms", "code": "1"}, {"method": "bio"}, {"method": "totp"}]
)
async def test_stepup_validation(client: AsyncClient, hw_env: TestCA, body: dict[str, Any]) -> None:
    await setup_user(client)
    assert (await client.post("/auth/stepup", json=body)).status_code == 422


async def test_stepup_audit(client: AsyncClient, hw_env: TestCA) -> None:
    from backend.config import get_settings
    from backend.db.connection import connect

    await setup_user(client)
    secret = await enable_totp(client)
    await client.post("/auth/stepup", json={"method": "totp", "code": "000000"})
    await stepup_totp(client, secret)
    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(
            "SELECT event, detail FROM audit_log WHERE event LIKE 'stepup%' ORDER BY id"
        )
        rows = [dict(r) for r in await cur.fetchall()]
    assert [r["event"] for r in rows] == ["stepup_fail", "stepup"]
    assert secret not in str(rows) and "000000" not in str(rows)


# ─────────────── Reviewronde 1: TOTP vervangen, afkoelperiode (R6) ───────────────


async def _age_audit(hours: int) -> None:
    """Verschuif alle audit-regels ``hours`` uur naar het verleden (afkoelperiode testen)."""
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        await conn.execute("UPDATE audit_log SET ts = ts - ?", (hours * 3600,))
        await conn.commit()


async def _relogin(client: AsyncClient) -> dict[str, Any]:
    await client.post("/auth/logout")
    r = await client.post(
        "/auth/login", json={"email": "keys@example.com", "password": "SuperStrongPw123!"}
    )
    assert r.status_code == 200, r.text
    return dict(r.json())


async def test_totp_cannot_be_replaced_with_password_only(
    client: AsyncClient, hw_env: TestCA
) -> None:
    """Alleen het accountwachtwoord (mfa=false) mag het TOTP-secret niet overschrijven en zo
    S + TOTP-step-up krijgen (reviewbevinding 1)."""
    import pyotp

    vid = await setup_user(client)
    await enable_totp(client)
    bio = SoftAuthenticator(hw_env)
    bio_id = (await enroll(client, vid, bio)).json()["id"]
    assert (await _relogin(client))["mfa_required"] is True
    own = pyotp.random_base32()
    r = await client.post("/auth/totp/verify", json={"secret": own, "code": pyotp.TOTP(own).now()})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "totp_already_configured"
    assert _claims(client)["mfa"] is False
    r = await client.delete(f"/vault/{vid}/keys/{bio_id}")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "mfa_required"


async def test_totp_replace_refused_with_mfa_too(client: AsyncClient, hw_env: TestCA) -> None:
    import pyotp

    await setup_user(client)
    await enable_totp(client)  # sessie heeft nu mfa=true
    own = pyotp.random_base32()
    r = await client.post("/auth/totp/verify", json={"secret": own, "code": pyotp.TOTP(own).now()})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "totp_already_configured"


async def test_totp_changes_are_mailed_and_audited(
    client: AsyncClient, hw_env: TestCA, mailbox: Any
) -> None:
    import pyotp

    await setup_user(client)
    secret = await enable_totp(client)
    assert "HorseSafe: authenticator-app ingesteld" in mailbox.subjects()
    r = await client.post("/auth/totp/disable", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    assert "HorseSafe: authenticator-app verwijderd" in mailbox.subjects()
    assert secret not in str(mailbox.sent)


async def test_totp_stepup_cooldown_after_bio_delete(
    client: AsyncClient, hw_env: TestCA, mailbox: Any
) -> None:
    """R6: Bio verwijderen geeft niet direct een TOTP-step-up; eerst 24 uur met melding."""
    vid = await setup_user(client)
    secret = await enable_totp(client)
    bio_id = (await enroll(client, vid, SoftAuthenticator(hw_env))).json()["id"]
    assert (await client.delete(f"/vault/{vid}/keys/{bio_id}")).status_code == 204
    assert "HorseSafe: sleutel verwijderd" in mailbox.subjects()
    r = await stepup_totp(client, secret)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_cooldown"
    assert isinstance(r.json()["detail"]["retry_at"], int)
    assert "stepup_until" not in _claims(client)
    await _age_audit(25)
    r = await stepup_totp(client, secret)
    assert r.status_code == 200, r.text


async def test_totp_stepup_cooldown_after_vault_delete_with_bio(
    client: AsyncClient, hw_env: TestCA, mailbox: Any, clock: dict[str, int]
) -> None:
    """Reviewronde 3 (R6 / §12.8): een kluis verwijderen waarin de enige Bio zat, telt als het
    verwijderen van die Bio — audit ``vault_key_delete`` + melding + TOTP-afkoelperiode. Anders kon
    wie wachtwoord + TOTP heeft via een bijkluis de afkoelperiode omzeilen en daarna met een eigen
    Bio een blokkade opheffen."""
    from .test_vault import FAKE_KDBX_BLOB

    vid_a = await setup_user(client)
    secret = await enable_totp(client)
    rec = SoftAuthenticator(hw_env, AAGUID_YK5)
    r = await enroll(client, vid_a, rec, kind="recovery", label="Kluis A")
    assert r.status_code == 201, r.text
    rec_url = f"/vault/{vid_a}/keys/{r.json()['id']}"
    r = await client.post(
        "/vault",
        data={"name": "bijkluis"},
        files={"blob": ("b.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    vid_b = str(r.json()["id"])
    # TOTP instellen terwijl er al een sleutel was → eerst die afkoelperiode laten verlopen
    await _age_audit(25)
    assert (await stepup_totp(client, secret)).status_code == 200
    bio_id = (await enroll(client, vid_b, SoftAuthenticator(hw_env), label="Enige Bio")).json()[
        "id"
    ]
    clock["t"] += 60
    assert (await client.post(rec_url + "/block")).status_code == 200
    mailbox.sent.clear()

    # Aanvaller: kluis B (met de enige Bio) weggooien en direct TOTP-step-up proberen
    assert (await client.delete(f"/vault/{vid_b}")).status_code == 204
    r = await stepup_totp(client, secret)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_cooldown"
    assert "HorseSafe: sleutel verwijderd" in mailbox.subjects()
    assert "Enige Bio" in mailbox.sent[-1]["body"]
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(
            "SELECT detail FROM audit_log WHERE event = 'vault_key_delete' ORDER BY id DESC LIMIT 1"
        )
        detail = (await cur.fetchone())["detail"]
    assert bio_id in detail and '"bio"' in detail and "vault_delete" in detail
    keys = (await client.get(f"/vault/{vid_a}/keys")).json()["keys"]
    assert keys[0]["status"] == "blocked"


async def test_vault_delete_without_keys_no_cooldown_no_mail(
    client: AsyncClient, hw_env: TestCA, mailbox: Any
) -> None:
    await setup_user(client)
    secret = await enable_totp(client)
    r = await client.post(
        "/vault",
        data={"name": "leeg"},
        files={"blob": ("l.kdbx", b"x" * 64, "application/octet-stream")},
    )
    mailbox.sent.clear()
    assert (await client.delete(f"/vault/{r.json()['id']}")).status_code == 204
    assert mailbox.sent == []
    assert (await stepup_totp(client, secret)).status_code == 200


async def test_recovery_delete_has_no_cooldown(client: AsyncClient, hw_env: TestCA) -> None:
    vid = await setup_user(client)
    secret = await enable_totp(client)
    rec = SoftAuthenticator(hw_env, AAGUID_YK5)
    kid = (await enroll(client, vid, rec, kind="recovery", label="Kluis")).json()["id"]
    assert (await client.delete(f"/vault/{vid}/keys/{kid}")).status_code == 204
    assert (await stepup_totp(client, secret)).status_code == 200


async def test_totp_stepup_cooldown_after_totp_setup_with_keys(
    client: AsyncClient, hw_env: TestCA
) -> None:
    """TOTP instellen terwijl er al sleutels zijn → 24 uur geen TOTP-step-up."""
    vid = await setup_user(client)
    rec = SoftAuthenticator(hw_env, AAGUID_YK5)
    assert (await enroll(client, vid, rec, kind="recovery", label="Kluis")).status_code == 201
    secret = await enable_totp(client)
    r = await stepup_totp(client, secret)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_cooldown"
    await _age_audit(25)
    assert (await stepup_totp(client, secret)).status_code == 200
