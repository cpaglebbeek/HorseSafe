"""CLI: promoot een bestaand account tot admin.

Gebruik:
    cd /opt/horsesafe   # of project-root
    python -m backend.db.promote_admin user@example.com
"""

from __future__ import annotations

import asyncio
import sys

from ..config import get_settings
from .connection import connect


async def promote(email: str) -> bool:
    settings = get_settings()
    async with connect(settings.db_path) as conn:
        cursor = await conn.execute(
            "UPDATE users SET is_admin = 1 WHERE email = ?", (email.lower(),)
        )
        await conn.commit()
        return cursor.rowcount > 0


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m backend.db.promote_admin <email>", file=sys.stderr)
        sys.exit(2)
    email = sys.argv[1]
    ok = asyncio.run(promote(email))
    if ok:
        print(f"OK: {email} is admin")
    else:
        print(f"ERROR: user {email} not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
