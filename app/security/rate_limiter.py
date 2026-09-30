"""Sliding Window Rate Limiter with Standard HTTP 429 Headers.

EDUCATIONAL ARCHITECTURE:
This module demonstrates mitigation against OWASP API4 (Unrestricted Resource Consumption).
It implements a sliding-window counter algorithm tracking requests per client/partner
and per endpoint.

Rate Limit Headers emitted:
- 'X-RateLimit-Limit': Maximum requests allowed in the sliding window.
- 'X-RateLimit-Remaining': Number of remaining allowed requests.
- 'X-RateLimit-Reset': UTC epoch timestamp when the current window expires.
- 'Retry-After': Number of seconds the client must pause before retrying.

In a distributed multi-node production deployment, this cache abstraction is backed
by a shared Redis/Dragonfly cluster with atomic EVAL scripts. For this local educational
simulator, a thread-safe in-memory sliding window cache is used.
"""
from collections import deque
from datetime import datetime, timezone
import math
import threading
import time
from typing import Dict, Tuple, Optional
from fastapi import Request, HTTPException, status
from app.config import get_settings

settings = get_settings()


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter."""
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # key: (identifier, endpoint) -> deque of timestamp floats
        self._history: Dict[Tuple[str, str], deque] = {}
        self._lock = threading.Lock()

    def check_rate_limit(
        self,
        identifier: str,
        endpoint: str,
        limit: int
    ) -> Tuple[bool, int, int, int]:
        """
        Check rate limit and update sliding window.
        Returns: (is_allowed, remaining, reset_epoch, retry_after)
        """
        now = time.time()
        window_start = now - self.window_seconds
        key = (identifier, endpoint)

        with self._lock:
            if key not in self._history:
                self._history[key] = deque()

            timestamps = self._history[key]

            # Purge timestamps outside the sliding window
            while timestamps and timestamps[0] < window_start:
                timestamps.popleft()

            current_count = len(timestamps)
            reset_epoch = int(math.ceil(now + self.window_seconds))

            if current_count >= limit:
                # Limit exceeded!
                oldest_timestamp = timestamps[0]
                retry_after = max(1, int(math.ceil(oldest_timestamp + self.window_seconds - now)))
                remaining = 0
                return False, remaining, reset_epoch, retry_after

            # Record this request
            timestamps.append(now)
            remaining = max(0, limit - len(timestamps))
            return True, remaining, reset_epoch, 0

    def clear(self) -> None:
        """Clear limiter state (useful for test resets)."""
        with self._lock:
            self._history.clear()


# Global limiter instances
partner_limiter = SlidingWindowRateLimiter(window_seconds=60)


def enforce_rate_limit(request: Request, endpoint_tag: Optional[str] = None):
    """
    FastAPI dependency: Enforces per-partner and per-endpoint rate limits.
    Adds rate limit headers to request.state for subsequent response injection.
    """
    partner = getattr(request.state, "partner", None)
    identifier = partner.client_id if partner else (request.client.host if request.client else "anonymous")
    endpoint = endpoint_tag or request.url.path
    limit = partner.rate_limit_rpm if partner else settings.DEFAULT_ENDPOINT_RATE_LIMIT

    allowed, remaining, reset_epoch, retry_after = partner_limiter.check_rate_limit(
        identifier=identifier,
        endpoint=endpoint,
        limit=limit
    )

    # Attach headers to request state
    request.state.rate_limit_headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_epoch)
    }

    if not allowed:
        headers = {
            **request.state.rate_limit_headers,
            "Retry-After": str(retry_after)
        }
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "error_description": f"Rate limit of {limit} requests per minute exceeded. Please retry after {retry_after} seconds.",
                "retry_after": retry_after
            },
            headers=headers
        )
