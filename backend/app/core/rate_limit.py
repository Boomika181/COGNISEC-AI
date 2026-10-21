import time
import threading
from collections import deque
from typing import Dict, Tuple, Optional
from fastapi import HTTPException, status


class InMemoryRateLimiter:
    """
    Thread-safe sliding-window in-memory rate limiter.
    Provides anti-brute-force and anti-flooding protection without external dependencies.
    """

    def __init__(self, enabled: bool = True):
        self._lock = threading.Lock()
        self._records: Dict[str, deque] = {}  # key -> deque of timestamps
        self.enabled = enabled

    def check(self, key: str, max_requests: int, window_seconds: int = 60) -> Tuple[bool, int]:
        """
        Checks if the request is within rate limits.
        Returns:
            (allowed: bool, retry_after: int)
        """
        if not self.enabled:
            return True, 0

        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            if key not in self._records:
                self._records[key] = deque()

            bucket = self._records[key]

            # Evict timestamps outside the sliding window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= max_requests:
                # Calculate remaining seconds until oldest request expires
                oldest = bucket[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, retry_after

            bucket.append(now)
            return True, 0

    def enforce(
        self,
        key: str,
        max_requests: int,
        window_seconds: int = 60,
        detail: str = "Rate limit exceeded. Please wait before retrying."
    ):
        """
        Enforces rate limit, raising HTTP 429 if exceeded.
        """
        allowed, retry_after = self.check(key, max_requests, window_seconds)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"{detail} (Retry after {retry_after} seconds)",
                headers={"Retry-After": str(retry_after)}
            )

    def reset(self):
        """Clears all rate limit records (for test isolation)."""
        with self._lock:
            self._records.clear()


# Global singleton instance
rate_limiter = InMemoryRateLimiter(enabled=True)
