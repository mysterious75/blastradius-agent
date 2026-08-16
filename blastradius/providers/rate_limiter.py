"""RateLimiter — per-provider token bucket, 429 backoff, circuit breaker.

Zero dependencies (stdlib threading + time).
"""

import threading
import time
from typing import Dict, Optional

PROVIDER_RATES = {
    "openai": 60,
    "anthropic": 50,
    "deepseek": 100,
    "groq": 30,
}
DEFAULT_RATE = 60
BACKOFF_SECONDS = [1, 2, 4, 8]
CIRCUIT_FAILURES = 5
CIRCUIT_OPEN_SECONDS = 300  # 5 minutes


class RateLimitedError(RuntimeError):
    """Raised when the provider returns HTTP 429 (rate limited)."""


class RateLimiter:
    """Token-bucket rate limiter with retry/backoff + circuit breaker."""

    def __init__(self, rates: Optional[Dict[str, int]] = None, now=None):
        self.rates = {**PROVIDER_RATES, **(rates or {})}
        self._now = now or time.monotonic
        self._lock = threading.Lock()
        self._buckets: Dict[str, tuple] = {}
        self._failures: Dict[str, int] = {}
        self._down_until: Dict[str, float] = {}
        # usage tracking
        self.requests_made: Dict[str, int] = {}
        self.tokens_used: Dict[str, int] = {}
        self.cost_estimate: float = 0.0

    # ------------------------------------------------------------------
    # Token bucket
    # ------------------------------------------------------------------

    def _rate(self, provider: str) -> int:
        return self.rates.get(provider, DEFAULT_RATE)

    def wait_if_needed(self, provider: str) -> float:
        """Consume one token; sleep when the bucket is empty. Returns wait time."""
        with self._lock:
            rate = self._rate(provider)
            now = self._now()
            tokens, refill = self._buckets.get(provider, (float(rate), now))
            tokens = min(rate, tokens + (now - refill) * rate)
            if tokens >= 1.0:
                self._buckets[provider] = (tokens - 1.0, now)
                wait = 0.0
            else:
                wait = (1.0 - tokens) / rate
                self._buckets[provider] = (0.0, now + wait)
        if wait > 0:
            time.sleep(wait)
        return wait

    # ------------------------------------------------------------------
    # Backoff + circuit breaker
    # ------------------------------------------------------------------

    @staticmethod
    def backoff_sleep(attempt: int) -> float:
        """Seconds to sleep before retry attempt (0-based): 1, 2, 4, 8, 8..."""
        return BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)]

    def record_success(self, provider: str) -> None:
        with self._lock:
            self._failures[provider] = 0

    def record_failure(self, provider: str) -> None:
        with self._lock:
            self._failures[provider] = self._failures.get(provider, 0) + 1
            if self._failures[provider] >= CIRCUIT_FAILURES:
                self._down_until[provider] = self._now() + CIRCUIT_OPEN_SECONDS
                self._failures[provider] = 0

    def is_open(self, provider: str) -> bool:
        """True while the circuit breaker has the provider DOWN."""
        with self._lock:
            until = self._down_until.get(provider, 0.0)
            if until and self._now() >= until:
                self._down_until.pop(provider, None)
                return False
            return until > self._now()

    # ------------------------------------------------------------------
    # Usage tracking
    # ------------------------------------------------------------------

    def track(
        self, provider: str, input_tokens: int = 0, output_tokens: int = 0, cost: float = 0.0
    ) -> None:
        with self._lock:
            self.requests_made[provider] = self.requests_made.get(provider, 0) + 1
            self.tokens_used[provider] = (
                self.tokens_used.get(provider, 0) + input_tokens + output_tokens
            )
            self.cost_estimate += cost
