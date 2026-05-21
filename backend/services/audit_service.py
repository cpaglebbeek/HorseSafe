from __future__ import annotations

import json
import time
from typing import Any

import aiosqlite

from ..models.audit import AuditEvent


async def log(
    conn: aiosqlite.Connection,
    *,
    user_id: str | None,
    event: AuditEvent,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict[str, Any] | None = None,
    reason: str | None = None,
) -> None:
    """Append-only audit-log write."""
    await conn.execute(
        """INSERT INTO audit_log (user_id, ts, ip, user_agent, event, detail, reason)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id,
            int(time.time()),
            ip,
            user_agent,
            event,
            json.dumps(detail) if detail else None,
            reason,
        ),
    )
    await conn.commit()
