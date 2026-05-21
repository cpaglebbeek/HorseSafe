from __future__ import annotations

import asyncio
from pathlib import Path

from ..config import get_settings
from .connection import connect


async def init_db(db_path: Path | None = None) -> None:
    """Run schema.sql tegen de doel-database. Idempotent."""
    settings = get_settings()
    target = db_path or settings.db_path
    schema_sql = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    async with connect(target) as conn:
        await conn.executescript(schema_sql)
        await conn.commit()


if __name__ == "__main__":
    asyncio.run(init_db())
    print(f"DB initialised at {get_settings().db_path}")
