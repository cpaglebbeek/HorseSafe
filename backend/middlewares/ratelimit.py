from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory IP-based rate-limit. Fase 1 — Redis-vervanging vanaf v0.1.0.

    Eenvoudige sliding-window per (ip, path-prefix).
    """

    LIMITS = {
        "/auth/login": (5, 900),  # 5 per 15 min
        "/auth/register": (5, 3600),  # 5 per uur
        "/vault": (60, 60),  # 60 per minuut (alle vault-routes samen)
    }
    DEFAULT_LIMIT = (300, 60)  # 300/min default

    def __init__(self, app: object) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _key(self, ip: str, path: str) -> tuple[str, tuple[int, int]]:
        for prefix, limit in self.LIMITS.items():
            if path.startswith(prefix):
                return f"{ip}:{prefix}", limit
        return f"{ip}:*", self.DEFAULT_LIMIT

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        ip = request.client.host if request.client else "unknown"
        key, (max_hits, window) = self._key(ip, request.url.path)
        now = time.time()
        bucket = self._hits[key]
        while bucket and bucket[0] < now - window:
            bucket.popleft()
        if len(bucket) >= max_hits:
            return JSONResponse(
                {"error": "rate_limited", "message": "Te veel aanvragen, probeer later opnieuw"},
                status_code=429,
            )
        bucket.append(now)
        return await call_next(request)
