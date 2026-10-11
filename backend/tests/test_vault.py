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
    assert r.headers["etag"] == etag_v2  # ook als header (reviewronde 2: tweede save gaf 422)
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


async def test_update_waits_for_concurrent_rekey_and_conflicts(client: AsyncClient) -> None:
    """Reviewronde 3: een save die tegelijk met een rekey loopt, mag de gerekeyde blob niet
    overschrijven. Hier houdt een tweede verbinding de schrijfvergrendeling vast zoals /rekey dat
    doet (BEGIN IMMEDIATE, nieuwe etag + blob, dan COMMIT). De PUT met de oude etag moet daarop
    wachten, de nieuwe etag zien en 412 geven; de blob blijft die van de rekey."""
    import asyncio
    from pathlib import Path

    from backend.config import get_settings
    from backend.db.connection import connect
    from backend.services import storage_service

    await client.post(
        "/auth/register",
        json={"email": "race@example.com", "password": VALID_PW, "ack_data_loss": True},
    )
    await client.post("/auth/login", json={"email": "race@example.com", "password": VALID_PW})
    r = await client.post(
        "/vault",
        data={"name": "default"},
        files={"blob": ("default.kdbx", FAKE_KDBX_BLOB, "application/octet-stream")},
    )
    vid, old_etag = r.json()["id"], r.json()["etag"]
    rekeyed = FAKE_KDBX_BLOB + b"_rekeyed"

    async with connect(get_settings().db_path) as rk:
        await rk.execute("BEGIN IMMEDIATE")
        cur = await rk.execute("SELECT blob_path FROM vaults WHERE id = ?", (vid,))
        blob_path = Path(str((await cur.fetchone())["blob_path"]))
        save = asyncio.create_task(
            client.put(
                f"/vault/{vid}",
                headers={"If-Match": old_etag},
                files={
                    "blob": ("default.kdbx", FAKE_KDBX_BLOB + b"_oud", "application/octet-stream")
                },
            )
        )
        await asyncio.sleep(0.3)  # de save staat nu te wachten op de vergrendeling
        assert not save.done()
        new_etag = storage_service._hash_bytes(rekeyed)
        await rk.execute("UPDATE vaults SET etag = ? WHERE id = ?", (new_etag, vid))
        storage_service._atomic_write(blob_path, rekeyed)
        await rk.commit()
    r = await save
    assert r.status_code == 412, r.text
    assert r.json()["detail"]["current_etag"] == new_etag
    assert blob_path.read_bytes() == rekeyed
    r = await client.get(f"/vault/{vid}")
    assert r.content == rekeyed and r.headers["etag"] == new_etag
