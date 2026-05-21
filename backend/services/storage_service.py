from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from pathlib import Path

import aiosqlite

from ..config import get_settings


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _vault_path(vaults_dir: Path, user_id: str, vault_id: str) -> Path:
    p = vaults_dir / user_id / f"{vault_id}.kdbx"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


async def list_vaults(conn: aiosqlite.Connection, user_id: str) -> list[dict[str, object]]:
    cursor = await conn.execute(
        """SELECT id, name, size_bytes, etag, created_at, updated_at
           FROM vaults WHERE user_id = ? ORDER BY name""",
        (user_id,),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def create_vault(
    conn: aiosqlite.Connection, user_id: str, name: str, blob: bytes
) -> dict[str, object]:
    settings = get_settings()
    if len(blob) > settings.vault_max_bytes:
        raise ValueError("blob_too_large")
    vault_id = str(uuid.uuid4())
    blob_path = _vault_path(settings.vaults_dir, user_id, vault_id)
    _atomic_write(blob_path, blob)
    etag = _hash_bytes(blob)
    now = int(time.time())
    try:
        await conn.execute(
            """INSERT INTO vaults (id, user_id, name, blob_path, size_bytes, etag, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (vault_id, user_id, name, str(blob_path), len(blob), etag, now, now),
        )
        await conn.commit()
    except aiosqlite.IntegrityError as e:
        blob_path.unlink(missing_ok=True)
        raise ValueError("name_in_use") from e
    return {
        "id": vault_id,
        "name": name,
        "size_bytes": len(blob),
        "etag": etag,
        "created_at": now,
        "updated_at": now,
    }


async def get_vault_meta(
    conn: aiosqlite.Connection, user_id: str, vault_id: str
) -> dict[str, object] | None:
    cursor = await conn.execute(
        """SELECT id, user_id, name, blob_path, size_bytes, etag, created_at, updated_at
           FROM vaults WHERE id = ? AND user_id = ?""",
        (vault_id, user_id),
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


async def read_vault_blob(
    conn: aiosqlite.Connection, user_id: str, vault_id: str
) -> tuple[bytes, str] | None:
    meta = await get_vault_meta(conn, user_id, vault_id)
    if not meta:
        return None
    blob_path = Path(str(meta["blob_path"]))
    if not blob_path.exists():
        return None
    blob = blob_path.read_bytes()
    return blob, str(meta["etag"])


async def update_vault_blob(
    conn: aiosqlite.Connection,
    user_id: str,
    vault_id: str,
    new_blob: bytes,
    if_match: str,
) -> dict[str, object] | None:
    """Update vault-blob met optimistic-lock. Returnt nieuwe meta of None bij conflict/not-found."""
    settings = get_settings()
    if len(new_blob) > settings.vault_max_bytes:
        raise ValueError("blob_too_large")
    meta = await get_vault_meta(conn, user_id, vault_id)
    if not meta:
        return None
    if str(meta["etag"]) != if_match:
        return {"_conflict": True, "current_etag": meta["etag"]}
    blob_path = Path(str(meta["blob_path"]))
    _atomic_write(blob_path, new_blob)
    new_etag = _hash_bytes(new_blob)
    now = int(time.time())
    await conn.execute(
        "UPDATE vaults SET size_bytes = ?, etag = ?, updated_at = ? WHERE id = ?",
        (len(new_blob), new_etag, now, vault_id),
    )
    await conn.commit()
    meta["size_bytes"] = len(new_blob)
    meta["etag"] = new_etag
    meta["updated_at"] = now
    return meta


async def delete_vault(conn: aiosqlite.Connection, user_id: str, vault_id: str) -> bool:
    meta = await get_vault_meta(conn, user_id, vault_id)
    if not meta:
        return False
    blob_path = Path(str(meta["blob_path"]))
    _secure_delete(blob_path)
    await conn.execute("DELETE FROM vaults WHERE id = ? AND user_id = ?", (vault_id, user_id))
    await conn.commit()
    return True


def _atomic_write(target: Path, data: bytes) -> None:
    """Schrijf naar tmp + rename (POSIX atomic op zelfde fs)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + f".tmp.{secrets.token_hex(8)}")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _secure_delete(path: Path) -> None:
    """3-pass random overschrijf + unlink. KDBX is al ciphertext maar zorgvuldig."""
    if not path.exists():
        return
    size = path.stat().st_size
    try:
        with path.open("r+b") as f:
            for _ in range(3):
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)
