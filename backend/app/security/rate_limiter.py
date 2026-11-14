"""
PREVENT-X Rate Limiter
Implements in-memory sliding window rate limiting for authentication and API endpoints.
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple
from backend.app.core.config import settings
from backend.app.core.exceptions import RateLimitExceededException


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter with microsecond timestamp granularity.
    Thread-safe for ASGI worker event loops.
    """
    def __init__(self):
        # Key: client_key -> List of timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int = 60,
    ) -> Tuple[bool, int]:
        """
        Evaluates whether request with `key` can proceed.
        Returns: (is_allowed, retry_after_seconds)
        """
        now = time.time()
        window_start = now - window_seconds

        # Clean old timestamps
        history = [ts for ts in self._requests[key] if ts > window_start]
        self._requests[key] = history

        if len(history) >= max_requests:
            oldest_relevant = history[0]
            retry_after = max(1, int(oldest_relevant + window_seconds - now))
            return False, retry_after

        # Record new request
        self._requests[key].append(now)
        return True, 0

    def enforce(
        self,
        key: str,
        max_requests: int,
        window_seconds: int = 60,
    ) -> None:
        """
        Enforces rate limit, raising RateLimitExceededException if exceeded.
        """
        allowed, retry_after = self.check_rate_limit(key, max_requests, window_seconds)
        if not allowed:
            raise RateLimitExceededException(retry_after=retry_after)

    def reset(self, key: str) -> None:
        """Clears rate limit state for a key (e.g. after successful login)."""
        if key in self._requests:
            del self._requests[key]


# Global rate limiter instance
rate_limiter = SlidingWindowRateLimiter()

