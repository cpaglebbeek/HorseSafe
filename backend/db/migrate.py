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
        cursor = await conn.execute("SELECT MAX(version) AS version FROM schema_version")
        row = await cursor.fetchone()
        return int(row["version"]) if row and row["version"] is not None else 1


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


async def check_vault_keys_schema() -> None:
    """Weiger te starten op een DB met de nooit-uitgerolde WIP-005 (vault_keys zonder 'status').

    Migratie 005 is herschreven (docs/HARDWARE_KEYS.md §12.9); zo'n dev-DB moet opnieuw worden
    aangemaakt. Productie (schema 4) heeft de tabel niet en krijgt de nieuwe 005.
    """
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute("PRAGMA table_info(vault_keys)")
        cols = {str(r["name"]) for r in await cursor.fetchall()}
    if cols and "status" not in cols:
        raise RuntimeError(
            "vault_keys heeft het WIP-schema van vóór v0.2.0-Koblitz; maak deze dev-DB opnieuw aan"
        )


if __name__ == "__main__":
    applied = asyncio.run(run_migrations())
    if applied:
        print(f"Applied migrations: {applied}")
    else:
        print("No migrations to apply")
