from __future__ import annotations

import re
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
    # Patronen gaan vóór de prefixen. Claim is publiek (alleen mac): 10 per 10 min per IP
    # (docs/HARDWARE_KEYS.md §13.4). Pollen van /devices/pairings/{id} valt onder de default.
    # v0.4.0-Montgomery: inlog-challenge voor een vertrouwde browser 10 per 10 min per IP (§14.4;
    # per e-mail telt de route zelf).
    PATTERNS = (
        (re.compile(r"^/devices/pairings/[^/]+/claim$"), "pairing_claim", (10, 600)),
        (re.compile(r"^/auth/browser/challenge$"), "browser_challenge", (10, 600)),
    )

    def __init__(self, app: object) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _key(self, ip: str, path: str) -> tuple[str, tuple[int, int]]:
        for pattern, name, plimit in self.PATTERNS:
            if pattern.match(path):
                return f"{ip}:{name}", plimit
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
