"""Adaptive rate limiter with token-bucket flow control, exponential backoff, and jitter."""
from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Optional

log = logging.getLogger("shadowrecon.ratelimit")

BLOCK_STATUS_CODES = {429, 503}


class AdaptiveRateLimiter:
    """Dynamically adjusts request spacing based on server feedback (429/503 status codes)."""

    def __init__(
        self,
        baseline_delay: float = 0.0,
        max_backoff: float = 60.0,
        backoff_factor: float = 2.0,
        jitter_ratio: float = 0.2,
        rotation_threshold: int = 3,
    ) -> None:
        self.baseline_delay = max(0.0, baseline_delay)
        self.max_backoff = max_backoff
        self.backoff_factor = backoff_factor
        self.jitter_ratio = jitter_ratio
        self.rotation_threshold = rotation_threshold

        self.current_delay: float = self.baseline_delay
        self.consecutive_blocks: int = 0
        self.consecutive_successes: int = 0
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()

    def record_response(self, status_code: int) -> float:
        """Update rate-limiter state based on HTTP status code.

        Returns the new current delay.
        """
        if status_code in BLOCK_STATUS_CODES:
            self.consecutive_blocks += 1
            self.consecutive_successes = 0

            # Double current delay (or initialize to 2.0s if baseline is 0)
            if self.current_delay <= 0:
                self.current_delay = 2.0
            else:
                self.current_delay = min(self.max_backoff, self.current_delay * self.backoff_factor)

            log.warning(
                "Rate limit hit (HTTP %d). Applying exponential backoff: %.2fs (consecutive blocks: %d)",
                status_code,
                self.current_delay,
                self.consecutive_blocks,
            )
        elif 200 <= status_code < 400:
            self.consecutive_successes += 1
            if self.consecutive_successes >= 3 and self.current_delay > self.baseline_delay:
                # Decay delay back towards baseline
                self.current_delay = max(
                    self.baseline_delay,
                    self.current_delay / self.backoff_factor,
                )
                self.consecutive_blocks = 0
                log.debug("Sustained success. Decaying delay down to %.2fs", self.current_delay)

        return self.current_delay

    @property
    def should_rotate_ip(self) -> bool:
        """Returns True if sustained blocking indicates the current IP/circuit is exhausted."""
        return self.consecutive_blocks >= self.rotation_threshold

    def reset_blocks(self) -> None:
        """Reset consecutive block counter after successful IP/circuit rotation."""
        self.consecutive_blocks = 0

    async def acquire(self) -> float:
        """Wait until rate-limit quota is available before proceeding.

        Returns the sleep duration in seconds.
        """
        async with self._lock:
            now = time.perf_counter()
            elapsed = now - self._last_request_time if self._last_request_time > 0 else 999.0

            if self.current_delay <= 0:
                self._last_request_time = time.perf_counter()
                return 0.0

            # Apply randomized jitter (+/- jitter_ratio)
            jitter_delta = self.current_delay * self.jitter_ratio
            target_delay = self.current_delay + random.uniform(-jitter_delta, jitter_delta)
            target_delay = max(0.0, target_delay)

            sleep_time = target_delay - elapsed
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            self._last_request_time = time.perf_counter()
            return max(0.0, sleep_time)
