import time
from collections import defaultdict
import asyncio
from typing import Dict, List, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status
from app.core.config import settings
from app.core.logging import logger


class InMemoryRateLimiter:
    """Thread-safe sliding window rate limiter for development and environments without Redis."""
    def __init__(self):
        self._history: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60) -> tuple[bool, int, int]:
        now = time.time()
        cutoff = now - window_seconds

        async with self._lock:
            # Purge timestamps outside the window
            timestamps = [ts for ts in self._history[key] if ts > cutoff]
            remaining = max(0, max_requests - len(timestamps))

            if len(timestamps) >= max_requests:
                self._history[key] = timestamps
                retry_after = int(window_seconds - (now - timestamps[0]))
                return False, 0, max(1, retry_after)

            timestamps.append(now)
            self._history[key] = timestamps
            return True, remaining - 1, 0

    async def reset(self):
        async with self._lock:
            self._history.clear()


limiter = InMemoryRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Applies sliding window rate limiting per client IP address.
    Strict limits are enforced on authentication routes to mitigate brute force & credential stuffing.
    """
    async def dispatch(self, request: Request, call_next):
        # Extract client IP
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Health checks bypass rate limiting to prevent false negatives in monitoring
        if path.endswith("/health"):
            return await call_next(request)

        # Route-sensitive limits
        if "/auth/" in path:
            limit = settings.AUTH_RATE_LIMIT_PER_MINUTE
            prefix = "auth"
        else:
            limit = settings.RATE_LIMIT_PER_MINUTE
            prefix = "api"

        key = f"rate:{prefix}:{client_ip}"
        allowed, remaining, retry_after = await limiter.is_allowed(key, max_requests=limit, window_seconds=60)

        if not allowed:
            logger.warning(f"Rate limit exceeded for IP {client_ip} on {path}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Too Many Requests",
                    "detail": "Rate limit quota exceeded. Please retry after the specified cool-down period.",
                    "retry_after_seconds": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                }
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
