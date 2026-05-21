from __future__ import annotations

import asyncio
import re
from pathlib import Path

from ..config import get_settings
from .connection import connect

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


async def get_current_version() -> int:
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = await cursor.fetchone()
        return int(row["version"]) if row else 1


async def run_migrations() -> list[int]:
    """Pas alle openstaande migraties toe. Returnt lijst van toegepaste versies."""
    settings = get_settings()
    if not MIGRATIONS_DIR.exists():
        return []
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    applied: list[int] = []
    current = await get_current_version()
    for f in files:
        m = re.match(r"^(\d+)_", f.name)
        if not m:
            continue
        version = int(m.group(1))
        if version <= current:
            continue
        sql = f.read_text(encoding="utf-8")
        async with connect(settings.db_path) as conn:
            await conn.executescript(sql)
            await conn.commit()
        applied.append(version)
        current = version
    return applied


if __name__ == "__main__":
    applied = asyncio.run(run_migrations())
    if applied:
        print(f"Applied migrations: {applied}")
    else:
        print("No migrations to apply")
