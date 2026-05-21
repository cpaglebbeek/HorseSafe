from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW


async def _register_login(client: AsyncClient, email: str) -> str:
    r = await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    user_id = r.json()["user_id"]
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})
    return user_id


async def _set_keypair(client: AsyncClient) -> None:
    """Stub keypair (echte ECDH gebeurt browser-side; backend slaat alleen opaque strings op)."""
    fake_pubkey = "FAKE_PUBKEY_BASE64_JWK_VALUE_FOR_TESTING_PURPOSES"
    fake_priv = "FAKE_ENCRYPTED_PRIVATE_KEY_BASE64_AES_GCM_PAYLOAD_FOR_TESTS"
    r = await client.post("/keypair", json={"pubkey": fake_pubkey, "encrypted_privkey": fake_priv})
    assert r.status_code == 200, r.text


async def test_keypair_requires_auth(client: AsyncClient) -> None:
    r = await client.post("/keypair", json={"pubkey": "x" * 30, "encrypted_privkey": "y" * 30})
    assert r.status_code == 401


async def test_keypair_set_and_get(client: AsyncClient) -> None:
    await _register_login(client, "kp1@example.com")
    await _set_keypair(client)
    r = await client.get("/keypair")
    assert r.status_code == 200
    body = r.json()
    assert body["pubkey"].startswith("FAKE_PUBKEY")
    assert body["encrypted_privkey"].startswith("FAKE_ENCRYPTED")


async def test_me_has_keypair_flag(client: AsyncClient) -> None:
    await _register_login(client, "kp-me@example.com")
    r = await client.get("/auth/me")
    assert r.json()["has_keypair"] is False
    await _set_keypair(client)
    r = await client.get("/auth/me")
    assert r.json()["has_keypair"] is True


async def test_pubkey_lookup_by_email(client: AsyncClient) -> None:
    await _register_login(client, "alice@example.com")
    await _set_keypair(client)
    r = await client.get("/users/by-email/alice@example.com/pubkey")
    assert r.status_code == 200
    assert "pubkey" in r.json()


async def test_pubkey_lookup_unknown(client: AsyncClient) -> None:
    await _register_login(client, "user1@example.com")
    await _set_keypair(client)
    r = await client.get("/users/by-email/unknown@example.com/pubkey")
    assert r.status_code == 404


async def test_pubkey_lookup_user_without_keypair(client: AsyncClient) -> None:
    # User 2 zonder keypair
    await _register_login(client, "no-kp@example.com")
    await client.post("/auth/logout")
    # User 1 met keypair
    await _register_login(client, "with-kp@example.com")
    await _set_keypair(client)
    r = await client.get("/users/by-email/no-kp@example.com/pubkey")
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "user_or_keypair_not_found"


async def test_share_create_and_inbox(client: AsyncClient) -> None:
    # User A — sender
    await _register_login(client, "sender@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    # User B — recipient
    await _register_login(client, "recipient@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    # User A logt opnieuw in en stuurt share
    await client.post("/auth/login", json={"email": "sender@example.com", "password": VALID_PW})
    payload = "ENCRYPTED_PAYLOAD_BASE64_OPAQUE_TO_SERVER_" + "x" * 50
    r = await client.post(
        "/shares",
        json={
            "to_email": "recipient@example.com",
            "encrypted_payload": payload,
            "title_hint": "Test entry",
        },
    )
    assert r.status_code == 201, r.text
    share_id = r.json()["id"]

    # User B logt in en haalt inbox op
    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": "recipient@example.com", "password": VALID_PW})
    r = await client.get("/shares/inbox")
    assert r.status_code == 200
    inbox = r.json()
    assert len(inbox) == 1
    assert inbox[0]["id"] == share_id
    assert inbox[0]["from_email"] == "sender@example.com"
    assert inbox[0]["title_hint"] == "Test entry"
    assert inbox[0]["encrypted_payload"] == payload


async def test_share_accept_flow(client: AsyncClient) -> None:
    await _register_login(client, "snd@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    await _register_login(client, "rcv@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": "snd@example.com", "password": VALID_PW})
    r = await client.post(
        "/shares",
        json={
            "to_email": "rcv@example.com",
            "encrypted_payload": "PAYLOAD" + "x" * 30,
            "title_hint": "x",
        },
    )
    share_id = r.json()["id"]

    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": "rcv@example.com", "password": VALID_PW})
    r = await client.post(f"/shares/{share_id}/accept")
    assert r.status_code == 200

    # Na accept: inbox is leeg
    r = await client.get("/shares/inbox")
    assert r.json() == []


async def test_share_decline_flow(client: AsyncClient) -> None:
    await _register_login(client, "snd2@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    await _register_login(client, "rcv2@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": "snd2@example.com", "password": VALID_PW})
    r = await client.post(
        "/shares",
        json={"to_email": "rcv2@example.com", "encrypted_payload": "PAYLOAD" + "x" * 30},
    )
    share_id = r.json()["id"]

    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": "rcv2@example.com", "password": VALID_PW})
    r = await client.post(f"/shares/{share_id}/decline")
    assert r.status_code == 200
    r = await client.get("/shares/inbox")
    assert r.json() == []


async def test_share_cannot_to_self(client: AsyncClient) -> None:
    await _register_login(client, "self-share@example.com")
    await _set_keypair(client)
    r = await client.post(
        "/shares",
        json={"to_email": "self-share@example.com", "encrypted_payload": "x" * 30},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "cannot_share_to_self"


async def test_share_to_unknown_user(client: AsyncClient) -> None:
    await _register_login(client, "lonely@example.com")
    await _set_keypair(client)
    r = await client.post(
        "/shares",
        json={"to_email": "ghost@example.com", "encrypted_payload": "x" * 30},
    )
    assert r.status_code == 404


async def test_share_isolation(client: AsyncClient) -> None:
    """User C kan share van A→B niet accepteren."""
    await _register_login(client, "a@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    await _register_login(client, "b@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")
    await _register_login(client, "c@example.com")
    await _set_keypair(client)
    await client.post("/auth/logout")

    await client.post("/auth/login", json={"email": "a@example.com", "password": VALID_PW})
    r = await client.post(
        "/shares",
        json={"to_email": "b@example.com", "encrypted_payload": "PAYLOAD" + "x" * 30},
    )
    share_id = r.json()["id"]

    # User C probeert accept
    await client.post("/auth/logout")
    await client.post("/auth/login", json={"email": "c@example.com", "password": VALID_PW})
    r = await client.post(f"/shares/{share_id}/accept")
    assert r.status_code == 404


async def test_keypair_rewrap(client: AsyncClient) -> None:
    await _register_login(client, "rewrap@example.com")
    await _set_keypair(client)
    new_priv = "REWRAPPED_PRIVATE_KEY_BASE64_NEW_MASTER_KEY_" + "y" * 30
    r = await client.post("/keypair/rewrap", json={"encrypted_privkey": new_priv})
    assert r.status_code == 200
    # Pubkey blijft hetzelfde, privkey is gewijzigd
    r = await client.get("/keypair")
    assert r.json()["encrypted_privkey"].startswith("REWRAPPED")
    assert r.json()["pubkey"].startswith("FAKE_PUBKEY")
