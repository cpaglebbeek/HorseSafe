from __future__ import annotations

from httpx import AsyncClient

from .conftest import VALID_PW

# Minimaal "KDBX"-marker (eerste 4 bytes van KDBX4 signature). De backend valideert
# dit nog niet in Fase 1; in Fase 5 (import) komt er strikte header-check.
FAKE_KDBX_BLOB = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + b"FAKE_VAULT_PAYLOAD" * 50


async def _register_and_login(client: AsyncClient, email: str = "vault-user@example.com") -> None:
    await client.post(
        "/auth/register",
        json={"email": email, "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": email, "password": VALID_PW})


async def test_vault_requires_auth(client: AsyncClient) -> None:
    r = await client.get("/vault")
    assert r.status_code == 401


async def test_vault_lifecycle(client: AsyncClient) -> None:
    await _register_and_login(client)

    # 1. Lege lijst
    r = await client.get("/vault")
    assert r.status_code == 200
    assert r.json() == []

    # 2. Create
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("default.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 201, r.text
    meta = r.json()
    assert meta["name"] == "default"
    assert meta["size_bytes"] == len(FAKE_KDBX_BLOB)
    assert len(meta["etag"]) == 64  # sha256 hex
    vault_id = meta["id"]
    etag_v1 = meta["etag"]

    # 3. List
    r = await client.get("/vault")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["id"] == vault_id

    # 4. Read blob
    r = await client.get(f"/vault/{vault_id}")
    assert r.status_code == 200
    assert r.content == FAKE_KDBX_BLOB
    assert r.headers["etag"] == etag_v1
    assert r.headers["content-type"] == "application/octet-stream"

    # 5. Update met correct If-Match
    new_blob = FAKE_KDBX_BLOB + b"_v2"
    r = await client.put(
        f"/vault/{vault_id}",
        headers={"If-Match": etag_v1},
        files={"blob": ("default.kdbx", new_blob, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    etag_v2 = r.json()["etag"]
    assert etag_v2 != etag_v1
    assert r.json()["size_bytes"] == len(new_blob)

    # 6. Update met stale If-Match → 412
    r = await client.put(
        f"/vault/{vault_id}",
        headers={"If-Match": etag_v1},
        files={"blob": ("default.kdbx", b"new", "application/octet-stream")},
    )
    assert r.status_code == 412
    assert r.json()["detail"]["error"] == "etag_mismatch"
    assert r.json()["detail"]["current_etag"] == etag_v2

    # 7. Delete
    r = await client.delete(f"/vault/{vault_id}")
    assert r.status_code == 204

    r = await client.get(f"/vault/{vault_id}")
    assert r.status_code == 404


async def test_vault_isolation_between_users(client: AsyncClient) -> None:
    # User 1 maakt vault
    await _register_and_login(client, "user1@example.com")
    r = await client.post(
        "/vault",
        data={"name": "secrets"},
        files={"blob": ("v.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 201
    user1_vault_id = r.json()["id"]
    await client.post("/auth/logout")

    # User 2 mag user 1's vault niet zien
    await _register_and_login(client, "user2@example.com")
    r = await client.get("/vault")
    assert r.status_code == 200
    assert r.json() == []  # eigen lijst is leeg

    r = await client.get(f"/vault/{user1_vault_id}")
    assert r.status_code == 404  # vault van ander is "not found" voor user 2


async def test_duplicate_name_rejected(client: AsyncClient) -> None:
    await _register_and_login(client, "dup@example.com")
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("v.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 201
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("v.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "name_in_use"
