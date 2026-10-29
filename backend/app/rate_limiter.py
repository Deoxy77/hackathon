"""Lightweight thread-safe sliding-window IP rate limiter (Spec Section 8.2 & 8.6)."""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from threading import Lock


class SlidingWindowRateLimiter:
    """Tracks timestamps per client IP within a 60-second sliding window."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self._op_count = 0

    def check(self, client_key: str, max_requests: int) -> tuple[bool, int]:
        """
        Returns (allowed, retry_after_seconds).
        If allowed is True, records the hit and returns (True, 0).
        If allowed is False, returns (False, seconds_until_slot_frees).
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            self._op_count += 1
            bucket = self._hits[client_key]

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= max_requests:
                oldest = bucket[0]
                retry_after = max(1, math.ceil((oldest + self.window_seconds) - now))
                return False, retry_after

            bucket.append(now)

            # Periodic cleanup to prevent unbounded memory growth
            if self._op_count % 500 == 0:
                stale_keys = [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]
                for k in stale_keys:
                    del self._hits[k]

            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = SlidingWindowRateLimiter(window_seconds=60.0)
