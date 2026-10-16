"""v0.4.0-Montgomery — vertrouwde browser + telefoonvinger (docs/HARDWARE_KEYS.md §14), tests §14.10.

De browserkant is ``FakeBrowser`` (ECDSA P-256, raw r‖s zoals WebCrypto); de telefoon is de nep-app
uit ``fake_device.py`` (echte koppeling met attestatie via ``dev_env``). TOTP-codes komen van een
verzetbare TOTP-klok (``totp``), zodat elke code een nieuwe tijdstap heeft (replay-bescherming).
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any

import pyotp
import pytest
from backend.services import trust_service as trust
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient, Response

from . import seal_v2_ref as seal
from .conftest import VALID_PW
from .fake_device import FakeDevice, b64u
from .hwkeys_helpers import setup_user
from .test_devices import claim, dget, started

EMAIL = "trust@example.com"


# ─────────────── Omgeving ───────────────


@pytest.fixture(autouse=True)
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    """Geen IP-rate-limit (die per test-app in het geheugen telt) en snelle long-polls."""
    monkeypatch.setenv("HORSESAFE_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setattr(trust, "POLL_INTERVAL", 0.01)


class Totp:
    """Verzetbare TOTP-klok: elke ``code()`` hoort bij een nieuwe tijdstap."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        from backend.services import mfa_service

        self.t = float(int(time.time()) // 30 * 30)
        monkeypatch.setattr(mfa_service, "totp_now", lambda: self.t)

    def code(self, secret: str) -> str:
        self.t += 30
        return str(pyotp.TOTP(secret).at(self.t))

    def same(self, secret: str) -> str:
        """De code van de huidige stap opnieuw (replay)."""
        return str(pyotp.TOTP(secret).at(self.t))


@pytest.fixture
def totp(monkeypatch: pytest.MonkeyPatch) -> Totp:
    return Totp(monkeypatch)


class FakeBrowser:
    """K_B (niet-exporteerbaar in het echt), browser_id, label en het koppelbewijs."""

    def __init__(self, label: str = "Chrome – laptop") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.browser_id = str(uuid.uuid4())
        self.label = label

    @property
    def pub_b(self) -> str:
        return b64u(
            self.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )

    def sign(self, msg: bytes) -> str:
        r, s = decode_dss_signature(self.key.sign(msg, ec.ECDSA(hashes.SHA256())))
        return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def proof(self, vid: str, ph: bytes | None, kh: bytes | None, label: str | None = None) -> str:
        pt = seal.plaintext(ph, kh)
        t = trust.bind_t(vid, self.browser_id, self.pub_b, label or self.label)
        return b64u(trust.proof(trust.k_bind(pt, vid), t))

    def trust_body(self, vid: str, ph: bytes | None, kh: bytes | None) -> dict[str, Any]:
        return {
            "browser_id": self.browser_id,
            "vault_id": vid,
            "pub_B": self.pub_b,
            "label": self.label,
            "proof": self.proof(vid, ph, kh),
        }


@dataclass
class World:
    vid: str
    secret: str
    device: FakeDevice
    browser: FakeBrowser
    ph: bytes
    kh: bytes


async def enable_totp(client: AsyncClient, totp: Totp) -> str:
    secret = (await client.post("/auth/totp/setup")).json()["secret"]
    r = await client.post("/auth/totp/verify", json={"secret": secret, "code": totp.code(secret)})
    assert r.status_code == 200, r.text
    return str(secret)


async def stepup(client: AsyncClient, totp: Totp, secret: str) -> None:
    r = await client.post("/auth/stepup", json={"method": "totp", "code": totp.code(secret)})
    assert r.status_code == 200, r.text


async def pair_phone(
    client: AsyncClient, dev_env: Any, vid: str, ph: bytes | None, kh: bytes | None, **kw: Any
) -> FakeDevice:
    pid, web = await started(client, vid)
    d = FakeDevice(dev_env.ca, **kw)
    r = await claim(client, d, web, pid)
    assert r.status_code == 201, r.text
    c = (await client.get(f"/devices/pairings/{pid}")).json()["claim"]
    sealed = seal.seal(seal.b64u_dec(c["pk_c"]), ph, kh, vault_id=vid, key_id=c["key_id"])
    r = await client.post(f"/devices/pairings/{pid}/confirm", json={"sealed": sealed})
    assert r.status_code == 201, r.text
    return d


async def world(
    client: AsyncClient,
    totp: Totp,
    dev_env: Any,
    *,
    email: str = EMAIL,
    phone: bool = True,
    trusted: bool = True,
) -> World:
    vid = await setup_user(client, email)
    secret = await enable_totp(client, totp)
    await stepup(client, totp, secret)
    ph, kh = os.urandom(32), os.urandom(32)
    d = await pair_phone(client, dev_env, vid, ph, kh) if phone else None
    b = FakeBrowser()
    if trusted:
        r = await client.post("/trusted-browsers", json=b.trust_body(vid, ph, kh))
        assert r.status_code == 201, r.text
    return World(vid, secret, d, b, ph, kh)  # type: ignore[arg-type]


async def browser_login(
    client: AsyncClient,
    b: FakeBrowser,
    code: str,
    *,
    email: str = EMAIL,
    tamper_sig: bool = False,
) -> Response:
    ch = (await client.post("/auth/browser/challenge", json={"email": email})).json()
    msg = trust.login_t(ch["challenge_id"], seal.b64u_dec(ch["challenge"]), b.browser_id, email)
    sig = b.sign(msg + (b"x" if tamper_sig else b""))
    return await client.post(
        "/auth/browser/login",
        json={
            "challenge_id": ch["challenge_id"],
            "browser_id": b.browser_id,
            "sig": sig,
            "totp": code,
        },
    )


@dataclass
class Req:
    approval_id: str
    created_at: int
    e_l: x25519.X25519PrivateKey
    nonce: bytes
    put: Response


async def request_unlock(
    client: AsyncClient, w: World, *, bad_sig: bool = False, b: FakeBrowser | None = None
) -> Req:
    b = b or w.browser
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": b.browser_id})
    assert r.status_code == 201, r.text
    aid, created = r.json()["approval_id"], r.json()["created_at"]
    e_l = x25519.X25519PrivateKey.generate()
    epk = b64u(e_l.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    nonce = os.urandom(32)
    t = trust.req_t(aid, w.vid, b.browser_id, epk, nonce, created + (1 if bad_sig else 0))
    put = await client.put(
        f"/vault/{w.vid}/approvals/{aid}",
        json={"epk_L": epk, "nonce_L": b64u(nonce), "sig_req": b.sign(t)},
    )
    return Req(aid, created, e_l, nonce, put)


def dpost(client: AsyncClient, d: FakeDevice, path: str, body: dict[str, Any], **kw: Any) -> Any:
    raw = json.dumps(body).encode()
    return client.post(
        path,
        content=raw,
        headers={"Content-Type": "application/json", **d.signed_headers("POST", path, raw, **kw)},
    )


async def phone_decides(
    client: AsyncClient,
    d: FakeDevice,
    *,
    decision: str = "approve",
    tamper_label: bool = False,
) -> tuple[Response, dict[str, Any]]:
    st = (await dget(client, d, "/device/v1/status")).json()
    assert st["approvals"], st
    aid = st["approvals"][0]["approval_id"]
    r = await dget(client, d, f"/device/v1/approvals/{aid}")
    assert r.status_code == 200, r.text
    ap = r.json()
    store = (await dget(client, d, f"/device/v1/keys/{ap['key_id']}/sealed")).json()
    body = d.decide_body(ap, store["sealed"], decision=decision, tamper_label=tamper_label)
    return await dpost(client, d, f"/device/v1/approvals/{aid}", body), body


async def _rows(sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        cur = await conn.execute(sql, args)
        return [dict(r) for r in await cur.fetchall()]


async def _events(*names: str) -> list[dict[str, Any]]:
    rows = await _rows("SELECT event, detail FROM audit_log ORDER BY id")
    out = [
        {"event": r["event"], "detail": json.loads(r["detail"]) if r["detail"] else None}
        for r in rows
    ]
    return [e for e in out if not names or e["event"] in names]


def _set_session(client: AsyncClient, token: str) -> None:
    """Vervang het sessiecookie (zelfde domein, zodat er geen tweede cookie naast komt)."""
    domain = next(c.domain for c in client.cookies.jar if c.name == "horsesafe_session")
    client.cookies.clear()
    client.cookies.set("horsesafe_session", token, domain=domain)


def _claims(client: AsyncClient) -> dict[str, Any]:
    from backend.services import jwt_service

    return jwt_service.decode(client.cookies["horsesafe_session"])


# ─────────────── Volledige flow ───────────────


async def test_full_flow(client: AsyncClient, dev_env: Any, totp: Totp, mailbox: Any) -> None:
    w = await world(client, totp, dev_env)
    assert mailbox.subjects()[-1] == "HorseSafe: browser vertrouwd"
    lst = (await client.get("/trusted-browsers")).json()["browsers"]
    assert lst == [
        {
            "browser_id": w.browser.browser_id,
            "vault_id": w.vid,
            "label": "Chrome – laptop",
            "created_at": lst[0]["created_at"],
            "last_used_at": None,
        }
    ]

    # Uitloggen en inloggen op de vertrouwde browser (zonder wachtwoord)
    await client.post("/auth/logout")
    r = await browser_login(client, w.browser, totp.code(w.secret))
    assert r.status_code == 200, r.text
    assert r.json()["browser_id"] == w.browser.browser_id and r.json()["vault_id"] == w.vid
    c = _claims(client)
    assert c["mfa"] is True and c["amr"] == ["browser", "totp"]
    assert c["browser_id"] == w.browser.browser_id and uuid.UUID(c["sid"])
    assert (await client.get("/trusted-browsers")).json()["browsers"][0]["last_used_at"]

    # Ontgrendelverzoek: draft → pending
    req = await request_unlock(client, w)
    assert req.put.status_code == 200, req.put.text
    exp = req.put.json()["expires_at"]
    assert exp >= req.created_at + trust.PENDING_TTL - 1
    r = await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")
    assert r.json() == {"status": "pending"}

    # Telefoon: ziet het verzoek met kaartgegevens, keurt goed
    st = (await dget(client, w.device, "/device/v1/status")).json()
    assert st["approvals"] == [{"approval_id": req.approval_id, "vault_id": w.vid}]
    ap = (await dget(client, w.device, f"/device/v1/approvals/{req.approval_id}")).json()
    assert ap["browser"]["label"] == "Chrome – laptop" and ap["browser"]["pub_B"] == w.browser.pub_b
    assert ap["vault_name"] == "default" and ap["ip"] and ap["created_at"] == req.created_at
    assert ap["expires_at"] == exp and ap["requested_at"] == exp - trust.PENDING_TTL
    r, body = await phone_decides(client, w.device)
    assert r.status_code == 200 and r.json() == {
        "approval_id": req.approval_id,
        "status": "approved",
    }

    # Browser haalt resp één keer op en opent het met e_L
    r = await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}?wait=5")
    assert r.status_code == 200 and r.json()["status"] == "approved"
    resp = r.json()["resp"]
    e_sk = req.e_l.private_bytes_raw()
    ph, kh = seal.unseal(
        resp,
        e_sk,
        purpose="relay",
        vault_id=w.vid,
        bind=trust.relay_bind(req.approval_id, b64u(req.nonce)),
        kid=req.approval_id,
    )
    assert (ph, kh) == (w.ph, w.kh)
    # resp gewist, status consumed, daarna 410
    rows = await _rows("SELECT status, resp FROM approvals WHERE id = ?", (req.approval_id,))
    assert rows == [{"status": "consumed", "resp": None}]
    r = await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")
    assert r.status_code == 410 and r.json()["detail"]["error"] == "gone"

    ev = [e["event"] for e in await _events()]
    for name in (
        "browser_trust",
        "browser_login",
        "approval_request",
        "approval_approve",
        "approval_consumed",
    ):
        assert name in ev
    # nooit challenge, proof, handtekeningen, epk_L, nonce of resp in de audit
    blob = json.dumps(await _events())
    for secret in (resp, ap["browser"]["proof"], ap["sig_req"], ap["epk_L"], ap["nonce_L"]):
        assert secret not in blob
    # Goedgekeurd: geen mail
    assert "HorseSafe: verzoek geweigerd" not in mailbox.subjects()


async def test_long_poll_returns_on_approval(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    assert req.put.status_code == 200

    async def later() -> None:
        await asyncio.sleep(0.2)
        r, _ = await phone_decides(client, w.device)
        assert r.status_code == 200

    poll, _ = await asyncio.gather(
        client.get(f"/vault/{w.vid}/approvals/{req.approval_id}?wait=10"), later()
    )
    assert poll.json()["status"] == "approved" and poll.json()["resp"]


async def test_device_status_long_poll(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    r = await dget(client, w.device, "/device/v1/status?wait=1")
    assert r.status_code == 200 and r.json()["approvals"] == []

    async def later() -> Req:
        await asyncio.sleep(0.2)
        return await request_unlock(client, w)

    st, req = await asyncio.gather(dget(client, w.device, "/device/v1/status?wait=10"), later())
    assert st.json()["approvals"] == [{"approval_id": req.approval_id, "vault_id": w.vid}]
    assert (await client.get(f"/vault/{w.vid}/approvals/x?wait=26")).status_code == 422


# ─────────────── Vertrouwen ───────────────


async def test_trust_requires_stepup_ownership_and_limits(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env, trusted=False)
    b = FakeBrowser()
    body = b.trust_body(w.vid, w.ph, w.kh)
    # zonder geldige step-up
    from backend.services import jwt_service

    me = (await client.get("/auth/me")).json()
    _set_session(
        client,
        jwt_service.issue(
            me["id"], False, mfa_passed=True, **jwt_service.carry_claims(_claims(client))
        ),
    )
    r = await client.post("/trusted-browsers", json=body)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "stepup_required"
    await stepup(client, totp, w.secret)
    # onbekende of andermans kluis → 404 (eigendom vóór step-up)
    r = await client.post("/trusted-browsers", json={**body, "vault_id": str(uuid.uuid4())})
    assert r.status_code == 404
    # vorm: geen uuid v4 in kleine letters, label met opmaakteken, ongeldige sleutel
    bad = [
        {**body, "browser_id": body["browser_id"].upper()},
        {**body, "label": "a‮b"},
        {**body, "label": ""},
        {**body, "proof": "abc"},
        {**body, "extra": 1},
    ]
    for x in bad:
        assert (await client.post("/trusted-browsers", json=x)).status_code == 422
    r = await client.post("/trusted-browsers", json={**body, "pub_B": b64u(b"\x30" * 40)})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_public_key"
    # ok, dubbel → 409
    assert (await client.post("/trusted-browsers", json=body)).status_code == 201
    r = await client.post("/trusted-browsers", json=body)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "browser_exists"
    # max 10 actief per gebruiker
    for _ in range(9):
        assert (
            await client.post("/trusted-browsers", json=FakeBrowser().trust_body(w.vid, w.ph, w.kh))
        ).status_code == 201
    r = await client.post("/trusted-browsers", json=FakeBrowser().trust_body(w.vid, w.ph, w.kh))
    assert r.status_code == 409 and r.json()["detail"]["error"] == "too_many_browsers"
    # intrekken maakt plaats
    assert (await client.delete(f"/trusted-browsers/{b.browser_id}")).status_code == 204
    assert (await client.delete(f"/trusted-browsers/{b.browser_id}")).status_code == 404
    assert len((await client.get("/trusted-browsers")).json()["browsers"]) == 9
    assert (
        await client.post("/trusted-browsers", json=FakeBrowser().trust_body(w.vid, w.ph, w.kh))
    ).status_code == 201


async def test_trust_requires_totp(client: AsyncClient) -> None:
    vid = await setup_user(client, "nototp@example.com")
    # zonder TOTP is de sessie S (mfa=true) maar step-up kan niet → 403 stepup_required
    r = await client.post("/trusted-browsers", json=FakeBrowser().trust_body(vid, None, b"k" * 32))
    assert r.status_code == 403


async def test_other_user_cannot_see_or_revoke(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    await client.post("/auth/logout")
    await setup_user(client, "ander@example.com")
    assert (await client.get("/trusted-browsers")).json()["browsers"] == []
    assert (await client.delete(f"/trusted-browsers/{w.browser.browser_id}")).status_code == 404
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 404


# ─────────────── Inloggen ───────────────


async def test_challenge_no_enumeration_and_rate_limit(client: AsyncClient) -> None:
    await setup_user(client, "bestaat@example.com")
    a = await client.post("/auth/browser/challenge", json={"email": "bestaat@example.com"})
    b = await client.post("/auth/browser/challenge", json={"email": "bestaat-niet@example.com"})
    assert a.status_code == b.status_code == 200
    assert set(a.json()) == set(b.json()) == {"challenge_id", "challenge", "expires_at"}
    assert len(seal.b64u_dec(a.json()["challenge"])) == 32
    for _ in range(9):
        assert (
            await client.post("/auth/browser/challenge", json={"email": "Bestaat@Example.com"})
        ).status_code == 200
    r = await client.post("/auth/browser/challenge", json={"email": "bestaat@example.com"})
    assert r.status_code == 429


def test_challenge_ip_rate_limit_pattern() -> None:
    from backend.middlewares.ratelimit import RateLimitMiddleware

    m = RateLimitMiddleware(app=None)
    assert m._key("1.2.3.4", "/auth/browser/challenge") == (
        "1.2.3.4:browser_challenge",
        (10, 600),
    )


async def _fail(r: Response) -> None:
    assert r.status_code == 401 and r.json() == {"detail": {"error": "browser_login_failed"}}


async def test_login_challenge_single_use_and_wrong_sig(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    await client.post("/auth/logout")
    ch = (await client.post("/auth/browser/challenge", json={"email": EMAIL})).json()
    msg = trust.login_t(
        ch["challenge_id"], seal.b64u_dec(ch["challenge"]), w.browser.browser_id, EMAIL
    )
    body = {
        "challenge_id": ch["challenge_id"],
        "browser_id": w.browser.browser_id,
        "sig": w.browser.sign(msg),
        "totp": "000000",  # fout → challenge toch verbruikt
    }
    await _fail(await client.post("/auth/browser/login", json=body))
    body["totp"] = totp.code(w.secret)
    await _fail(await client.post("/auth/browser/login", json=body))  # eenmalig
    await _fail(await browser_login(client, w.browser, totp.code(w.secret), tamper_sig=True))
    # andere browser (sleutel past niet bij browser_id)
    other = FakeBrowser()
    other.browser_id = w.browser.browser_id
    await _fail(await browser_login(client, other, totp.code(w.secret)))
    reasons = [e["detail"]["reason"] for e in await _events("browser_login_failed")]
    assert reasons == [
        "totp_invalid",
        "challenge_invalid",
        "signature_invalid",
        "signature_invalid",
    ]
    assert "horsesafe_session" not in client.cookies


async def test_login_expired_unknown_and_revoked(
    client: AsyncClient, dev_env: Any, totp: Totp, clock: Any
) -> None:
    w = await world(client, totp, dev_env)
    await client.post("/auth/logout")
    # verlopen challenge
    ch = (await client.post("/auth/browser/challenge", json={"email": EMAIL})).json()
    clock["t"] += trust.CHALLENGE_TTL + 1
    msg = trust.login_t(
        ch["challenge_id"], seal.b64u_dec(ch["challenge"]), w.browser.browser_id, EMAIL
    )
    r = await client.post(
        "/auth/browser/login",
        json={
            "challenge_id": ch["challenge_id"],
            "browser_id": w.browser.browser_id,
            "sig": w.browser.sign(msg),
            "totp": totp.code(w.secret),
        },
    )
    await _fail(r)
    # onbekend e-mailadres
    await _fail(await browser_login(client, w.browser, totp.code(w.secret), email="x@example.com"))
    # ingetrokken browser
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    await client.post("/auth/totp/verify", json={"code": totp.code(w.secret)})
    assert (await client.delete(f"/trusted-browsers/{w.browser.browser_id}")).status_code == 204
    await client.post("/auth/logout")
    await _fail(await browser_login(client, w.browser, totp.code(w.secret)))
    reasons = [e["detail"]["reason"] for e in await _events("browser_login_failed")]
    assert reasons == ["challenge_expired", "unknown_email", "browser_revoked"]
    assert (await _events("browser_revoke"))[0]["detail"]["reason"] == "user"


async def test_login_totp_replay(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    await client.post("/auth/logout")
    # de code van de laatste step-up is al gebruikt → geweigerd
    await _fail(await browser_login(client, w.browser, totp.same(w.secret)))
    code = totp.code(w.secret)
    assert (await browser_login(client, w.browser, code)).status_code == 200
    await client.post("/auth/logout")
    await _fail(await browser_login(client, w.browser, code))  # zelfde code nogmaals
    reasons = [e["detail"]["reason"] for e in await _events("browser_login_failed")]
    assert reasons == ["totp_replay", "totp_replay"]
    # de audit bevat alleen de tijdstap, nooit de code
    assert code not in json.dumps(await _events())


async def test_login_requires_totp(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    # /auth/totp/disable gebruikt de gewone (echte) klok
    r = await client.post("/auth/totp/disable", json={"code": pyotp.TOTP(w.secret).now()})
    assert r.status_code == 200
    await client.post("/auth/logout")
    await _fail(await browser_login(client, w.browser, totp.code(w.secret)))
    assert (await _events("browser_login_failed"))[0]["detail"]["reason"] == "totp_missing"


async def test_password_login_has_sid_and_stepup_keeps_it(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env, phone=False, trusted=False)
    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    sid = _claims(client)["sid"]
    assert "browser_id" not in _claims(client)
    await client.post("/auth/totp/verify", json={"code": totp.code(w.secret)})
    assert _claims(client)["sid"] == sid and _claims(client)["mfa"] is True
    await stepup(client, totp, w.secret)
    assert _claims(client)["sid"] == sid
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    assert _claims(client)["sid"] != sid


# ─────────────── Ontgrendelverzoeken ───────────────


async def test_session_too_old_and_no_phone_key(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    from backend.services import jwt_service

    w = await world(client, totp, dev_env, phone=False)
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "no_phone_key"
    me = (await client.get("/auth/me")).json()
    _set_session(client, jwt_service.issue(me["id"], False, mfa_passed=True, fresh_sid=False))
    assert "sid" not in _claims(client)
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "session_too_old"
    # reissue/step-up maken van een oud cookie geen sid
    await stepup(client, totp, w.secret)
    assert "sid" not in _claims(client)


async def test_browser_claim_must_match(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    await stepup(client, totp, w.secret)
    b2 = FakeBrowser("Firefox")
    assert (
        await client.post("/trusted-browsers", json=b2.trust_body(w.vid, w.ph, w.kh))
    ).status_code == 201
    await client.post("/auth/logout")
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": b2.browser_id})
    assert r.status_code == 404
    # andere kluis dan de binding → 404
    r = await client.post(
        f"/vault/{uuid.uuid4()}/approvals", json={"browser_id": w.browser.browser_id}
    )
    assert r.status_code == 404


async def test_sid_binding_and_one_open(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    assert req.put.status_code == 200
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "approval_open"
    # nieuwe sessie (andere sid) ziet het verzoek niet
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    await client.post("/auth/totp/verify", json={"code": totp.code(w.secret)})
    base = f"/vault/{w.vid}/approvals/{req.approval_id}"
    assert (await client.get(base)).status_code == 404
    assert (await client.delete(base)).status_code == 404
    r = await client.put(base, json={"epk_L": "A" * 43, "nonce_L": "A" * 43, "sig_req": "A" * 86})
    assert r.status_code == 404
    # en mag zelf een eigen verzoek starten
    req2 = await request_unlock(client, w)
    assert req2.put.status_code == 200


async def test_sig_req_invalid_and_draft_rules(
    client: AsyncClient, dev_env: Any, totp: Totp, clock: Any
) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w, bad_sig=True)
    assert req.put.status_code == 400 and req.put.json()["detail"]["error"] == "signature_invalid"
    # draft is niet zichtbaar voor de telefoon
    st = (await dget(client, w.device, "/device/v1/status", ts=clock["t"])).json()
    assert st["approvals"] == []
    r = await dget(client, w.device, f"/device/v1/approvals/{req.approval_id}", ts=clock["t"])
    assert r.status_code == 404
    # draft verloopt na 30 s
    clock["t"] += trust.DRAFT_TTL + 1
    epk = b64u(req.e_l.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    t = trust.req_t(req.approval_id, w.vid, w.browser.browser_id, epk, req.nonce, req.created_at)
    r = await client.put(
        f"/vault/{w.vid}/approvals/{req.approval_id}",
        json={"epk_L": epk, "nonce_L": b64u(req.nonce), "sig_req": w.browser.sign(t)},
    )
    assert r.status_code == 409 and r.json()["detail"]["error"] == "approval_not_draft"
    r = await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")
    assert r.json() == {"status": "expired"}


async def test_pending_expires_and_resp_wiped(
    client: AsyncClient, dev_env: Any, totp: Totp, clock: Any
) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    st = (await dget(client, w.device, "/device/v1/status", ts=clock["t"])).json()
    aid = st["approvals"][0]["approval_id"]
    ap = (await dget(client, w.device, f"/device/v1/approvals/{aid}", ts=clock["t"])).json()
    store = (
        await dget(client, w.device, f"/device/v1/keys/{ap['key_id']}/sealed", ts=clock["t"])
    ).json()
    body = w.device.decide_body(ap, store["sealed"])
    r = await dpost(client, w.device, f"/device/v1/approvals/{aid}", body, ts=clock["t"])
    assert r.status_code == 200
    # niet opgehaald binnen expires_at → expired, resp gewist
    clock["t"] += trust.PENDING_TTL + 1
    r = await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")
    assert r.json() == {"status": "expired"}
    rows = await _rows("SELECT status, resp FROM approvals WHERE id = ?", (req.approval_id,))
    assert rows == [{"status": "expired", "resp": None}]
    # te laat beslissen → 409
    req2 = await request_unlock(client, w)
    clock["t"] += trust.PENDING_TTL + 1
    r = await dpost(
        client,
        w.device,
        f"/device/v1/approvals/{req2.approval_id}",
        {"decision": "deny"},
        ts=clock["t"],
    )
    assert r.status_code == 409 and r.json()["detail"]["error"] == "approval_not_pending"


async def test_cancel(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    assert (await client.delete(f"/vault/{w.vid}/approvals/{req.approval_id}")).status_code == 204
    assert (await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")).json() == {
        "status": "cancelled"
    }
    assert (await dget(client, w.device, "/device/v1/status")).json()["approvals"] == []
    # na annuleren mag een nieuw verzoek (niet meer open)
    assert (await request_unlock(client, w)).put.status_code == 200


async def test_hourly_limit(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    for _ in range(trust.APPROVALS_PER_HOUR):
        req = await request_unlock(client, w)
        assert req.put.status_code == 200
        assert (
            await client.delete(f"/vault/{w.vid}/approvals/{req.approval_id}")
        ).status_code == 204
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 429 and r.json()["detail"]["error"] == "too_many_approvals"


async def test_deny_revokes_session_and_cooldown(
    client: AsyncClient, dev_env: Any, totp: Totp, mailbox: Any
) -> None:
    w = await world(client, totp, dev_env)
    await client.post("/auth/logout")
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    denied_sid = _claims(client)["sid"]
    req = await request_unlock(client, w)
    r, body = await phone_decides(client, w.device, decision="deny")
    assert r.status_code == 200 and r.json()["status"] == "denied"
    assert body == {"decision": "deny", "reason": "user"}
    # sessie ingetrokken: elke S-route → 401 invalid_token/session_revoked, ook step-up
    r = await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")
    assert r.status_code == 401
    assert r.json()["detail"] == {"error": "invalid_token", "reason": "session_revoked"}
    assert (await client.get("/auth/me")).status_code == 401
    r = await client.post("/auth/stepup", json={"method": "totp", "code": totp.code(w.secret)})
    assert r.status_code == 401
    # browser blijft vertrouwd maar heeft 15 min afkoeling
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "browser_cooldown"
    assert r.json()["detail"]["retry_at"] > 0
    assert mailbox.subjects()[-1] == "HorseSafe: verzoek geweigerd"
    deny = (await _events("approval_deny"))[0]["detail"]
    assert deny["reason"] == "user" and deny["decision"] == "deny"
    revoked = {r["sid"] for r in await _rows("SELECT sid FROM revoked_sessions")}
    assert denied_sid in revoked and len(revoked) == 2  # + de uitgelogde wachtwoordsessie


async def test_deny_revoke(client: AsyncClient, dev_env: Any, totp: Totp, mailbox: Any) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    r, _ = await phone_decides(client, w.device, decision="deny_revoke")
    assert r.status_code == 200
    rows = await _rows("SELECT revoked_at, revoke_reason FROM trusted_browsers")
    assert rows[0]["revoked_at"] and rows[0]["revoke_reason"] == "phone_deny"
    assert (await _events("browser_revoke"))[0]["detail"]["reason"] == "phone_deny"
    assert "niet langer vertrouwd" in mailbox.sent[-1]["body"]
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    await client.post("/auth/totp/verify", json={"code": totp.code(w.secret)})
    assert (await client.get("/trusted-browsers")).json()["browsers"] == []
    await client.post("/auth/logout")
    await _fail(await browser_login(client, w.browser, totp.code(w.secret)))
    assert req.approval_id


async def test_tampered_label_phone_refuses(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env)
    await request_unlock(client, w)
    r, body = await phone_decides(client, w.device, tamper_label=True)
    assert body == {"decision": "deny", "reason": "browser_proof_invalid"}
    assert r.status_code == 200 and r.json()["status"] == "denied"
    assert (await _events("approval_deny"))[0]["detail"]["reason"] == "browser_proof_invalid"


async def test_proof_from_other_vault_refused(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    """Een kwaadwillende server kan geen eigen browser tussenschuiven: zonder CK geen geldig bewijs."""
    w = await world(client, totp, dev_env, trusted=False)
    b = FakeBrowser()
    body = {**b.trust_body(w.vid, w.ph, w.kh), "proof": b64u(os.urandom(32))}
    await stepup(client, totp, w.secret)
    assert (await client.post("/trusted-browsers", json=body)).status_code == 201
    await request_unlock(client, w, b=b)
    r, body = await phone_decides(client, w.device)
    assert body["reason"] == "browser_proof_invalid"


# ─────────────── Device-kant ───────────────


async def test_device_validate_sealed_and_decision_rules(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    path = f"/device/v1/approvals/{req.approval_id}"
    # resp moet Seal_v2 met kid = approval_id zijn
    for bad in (
        {"decision": "approve"},
        {"decision": "approve", "resp": "{}"},
        {
            "decision": "approve",
            "resp": seal.seal(os.urandom(32), w.ph, w.kh, vault_id=w.vid, key_id=str(uuid.uuid4())),
        },
    ):
        r = await dpost(client, w.device, path, bad)
        assert r.status_code == 400 and r.json()["detail"]["error"] == "invalid_sealed"
    r = await dpost(client, w.device, path, {"decision": "deny", "resp": "x"})
    assert r.status_code == 400
    r = await dpost(client, w.device, path, {"decision": "maybe"})
    assert r.status_code == 422
    r = await dpost(client, w.device, path, {"decision": "deny", "reason": "Hoofdletters!"})
    assert r.status_code == 422
    r, _ = await phone_decides(client, w.device)
    assert r.status_code == 200
    r = await dpost(client, w.device, path, {"decision": "deny"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "approval_not_pending"
    # na goedkeuring niet meer zichtbaar voor de telefoon
    assert (await dget(client, w.device, path)).status_code == 404
    # zonder device-handtekening → 401
    assert (await client.get(path)).status_code == 401


async def test_only_device_with_key_for_vault(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    # tweede kluis met een eigen toestel
    from .test_vault import FAKE_KDBX_BLOB

    r = await client.post(
        "/vault",
        data={"name": "tweede"},
        files={"blob": ("t.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    vid2 = r.json()["id"]
    await stepup(client, totp, w.secret)
    d2 = await pair_phone(client, dev_env, vid2, w.ph, w.kh, label="Pixel")
    req = await request_unlock(client, w)
    assert (await dget(client, d2, "/device/v1/status")).json()["approvals"] == []
    assert (await dget(client, d2, f"/device/v1/approvals/{req.approval_id}")).status_code == 404
    r = await dpost(client, d2, f"/device/v1/approvals/{req.approval_id}", {"decision": "deny"})
    assert r.status_code == 404
    assert (await dget(client, w.device, "/device/v1/status")).json()["approvals"]
    # toestel verwijderd → verzoek onzichtbaar en niet meer te beslissen
    assert (await client.delete(f"/devices/{w.device.device_id}")).status_code == 204
    r = await dpost(
        client, w.device, f"/device/v1/approvals/{req.approval_id}", {"decision": "deny"}
    )
    assert r.status_code == 401  # ingetrokken toestel: device_auth_failed
    # en een nieuw verzoek kan niet meer: geen telefoonsleutel voor deze kluis
    assert (await client.delete(f"/vault/{w.vid}/approvals/{req.approval_id}")).status_code == 204
    r = await client.post(f"/vault/{w.vid}/approvals", json={"browser_id": w.browser.browser_id})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "no_phone_key"


async def test_trusted_browser_revoke_denies_open(
    client: AsyncClient, dev_env: Any, totp: Totp, mailbox: Any
) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    assert (await client.delete(f"/trusted-browsers/{w.browser.browser_id}")).status_code == 204
    assert mailbox.subjects()[-1] == "HorseSafe: browser ingetrokken"
    assert (await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")).json() == {
        "status": "denied"
    }
    assert (await dget(client, w.device, "/device/v1/status")).json()["approvals"] == []


# ─────────────── Rekey ───────────────


async def test_rekey_revokes_browsers(
    client: AsyncClient, dev_env: Any, totp: Totp, mailbox: Any
) -> None:
    w = await world(client, totp, dev_env)
    req = await request_unlock(client, w)
    keys = (await client.get(f"/vault/{w.vid}/keys")).json()["keys"]
    etag = (await client.get(f"/vault/{w.vid}")).headers["etag"]
    await stepup(client, totp, w.secret)
    from .hwkeys_helpers import fake_sealed

    sealed = json.dumps({"items": [{"id": k["id"], "sealed": fake_sealed(k["id"])} for k in keys]})
    r = await client.put(
        f"/vault/{w.vid}/rekey",
        files={"blob": ("v.kdbx", b"KDBX-nieuw" * 10, "application/octet-stream")},
        data={"sealed": sealed},
        headers={"If-Match": etag},
    )
    assert r.status_code == 200, r.text
    rows = await _rows("SELECT revoked_at, revoke_reason FROM trusted_browsers")
    assert rows[0]["revoked_at"] and rows[0]["revoke_reason"] == "rekey"
    assert (await client.get("/trusted-browsers")).json()["browsers"] == []
    assert (await client.get(f"/vault/{w.vid}/approvals/{req.approval_id}")).json() == {
        "status": "denied"
    }
    assert (await _events("browser_revoke"))[0]["detail"]["reason"] == "rekey"
    await asyncio.sleep(0.05)  # mail gaat als BackgroundTask na het antwoord
    assert "vertrouwde browser(s)" in mailbox.sent[-1]["body"]


# ─────────────── revoked_sessions ───────────────


async def test_revoked_session_blocks_jwt(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    w = await world(client, totp, dev_env, phone=False, trusted=False)
    sid = _claims(client)["sid"]
    from backend.config import get_settings
    from backend.db.connection import connect

    async with connect(get_settings().db_path) as conn:
        await conn.execute(
            "INSERT INTO revoked_sessions (sid, revoked_at, expires_at) VALUES (?, 0, ?)",
            (sid, 2**40),
        )
        await conn.commit()
    for r in (
        await client.get("/auth/me"),
        await client.get("/vault"),
        await client.get(f"/vault/{w.vid}/keys"),
    ):
        assert r.status_code == 401 and r.json()["detail"]["reason"] == "session_revoked"
    # opnieuw inloggen geeft een nieuwe sid
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    assert (await client.get("/auth/me")).status_code == 200


# ─────────────── Sessies intrekken bij uitloggen en bij intrekken van de browser ───────────────


async def _status_with(client: AsyncClient, token: str) -> int:
    _set_session(client, token)
    return (await client.get("/auth/me")).status_code


async def _password_session(client: AsyncClient, totp: Totp, w: World) -> str:
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    await client.post("/auth/totp/verify", json={"code": totp.code(w.secret)})
    return str(client.cookies["horsesafe_session"])


async def test_logout_revokes_sid(client: AsyncClient, dev_env: Any, totp: Totp) -> None:
    await world(client, totp, dev_env, phone=False, trusted=False)
    token = client.cookies["horsesafe_session"]
    sid = _claims(client)["sid"]
    assert (await client.post("/auth/logout")).status_code == 200
    rows = await _rows("SELECT sid FROM revoked_sessions")
    assert rows == [{"sid": sid}]
    await client.post("/auth/login", json={"email": EMAIL, "password": VALID_PW})
    assert await _status_with(client, token) == 401
    r = await client.get("/auth/me")
    assert r.json()["detail"]["reason"] == "session_revoked"


async def test_delete_browser_revokes_its_sessions(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    pw_token = await _password_session(client, totp, w)
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    b_token = str(client.cookies["horsesafe_session"])
    _set_session(client, pw_token)
    assert (await client.delete(f"/trusted-browsers/{w.browser.browser_id}")).status_code == 204
    assert await _status_with(client, b_token) == 401
    assert await _status_with(client, pw_token) == 200  # andere sessies blijven


async def test_deny_revoke_revokes_all_browser_sessions(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    pw_token = await _password_session(client, totp, w)
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    first = str(client.cookies["horsesafe_session"])
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    second = str(client.cookies["horsesafe_session"])
    await request_unlock(client, w)
    r, _ = await phone_decides(client, w.device, decision="deny_revoke")
    assert r.status_code == 200
    assert await _status_with(client, first) == 401
    assert await _status_with(client, second) == 401
    assert await _status_with(client, pw_token) == 200


async def test_rekey_revokes_browser_sessions(
    client: AsyncClient, dev_env: Any, totp: Totp
) -> None:
    w = await world(client, totp, dev_env)
    assert (await browser_login(client, w.browser, totp.code(w.secret))).status_code == 200
    b_token = str(client.cookies["horsesafe_session"])
    await _password_session(client, totp, w)
    keys = (await client.get(f"/vault/{w.vid}/keys")).json()["keys"]
    etag = (await client.get(f"/vault/{w.vid}")).headers["etag"]
    await stepup(client, totp, w.secret)
    pw_token = str(client.cookies["horsesafe_session"])
    from .hwkeys_helpers import fake_sealed

    sealed = json.dumps({"items": [{"id": k["id"], "sealed": fake_sealed(k["id"])} for k in keys]})
    r = await client.put(
        f"/vault/{w.vid}/rekey",
        files={"blob": ("v.kdbx", b"KDBX-nieuw" * 10, "application/octet-stream")},
        data={"sealed": sealed},
        headers={"If-Match": etag},
    )
    assert r.status_code == 200, r.text
    assert await _status_with(client, b_token) == 401
    assert await _status_with(client, pw_token) == 200
