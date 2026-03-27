"""
TrigGuard Rate Limiting

Production-grade rate limiting for API and per-tenant throttling.

Algorithms:
    - Token Bucket: Smooths traffic with burst allowance
    - Sliding Window: Precise rate tracking
    - Fixed Window: Simple, low-overhead

Usage:
    from trigguard.ratelimit.limiter import get_rate_limiter, RateLimitConfig

    limiter = get_rate_limiter()

    if limiter.allow("tenant-123", "spend"):
        # Proceed with request
        ...
    else:
        # Rate limited
        raise RateLimitExceeded()
"""

import time
import threading
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger("trigguard.ratelimit")


class RateLimitAlgorithm(Enum):
    """Rate limiting algorithm."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    # Limits
    requests_per_second: float = 100.0
    requests_per_minute: float = 1000.0
    requests_per_hour: float = 10000.0
    requests_per_day: float = 100000.0

    # Token bucket specific
    burst_size: int = 50

    # Algorithm
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET

    # Behavior
    fail_open: bool = False  # Allow on limiter errors

    # Per-surface limits (multiplier)
    surface_multipliers: Dict[str, float] = field(default_factory=dict)


@dataclass
class RateLimitResult:
    """Result of rate limit check."""

    allowed: bool
    remaining: int
    reset_at: float  # Unix timestamp
    retry_after_seconds: float = 0.0
    limit: int = 0

    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers."""
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(self.reset_at)),
            "Retry-After": (
                str(int(self.retry_after_seconds)) if not self.allowed else ""
            ),
        }


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""

    def __init__(self, result: RateLimitResult, message: str = "Rate limit exceeded"):
        self.result = result
        self.message = message
        super().__init__(message)


# ============================================================================
# Token Bucket Algorithm
# ============================================================================


class TokenBucket:
    """
    Token bucket rate limiter.

    Allows bursts up to bucket capacity while maintaining
    average rate over time.
    """

    def __init__(
        self,
        rate: float,  # tokens per second
        capacity: int,  # max tokens
    ):
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_update = time.time()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate,
        )
        self.last_update = now

    def consume(self, tokens: int = 1) -> Tuple[bool, int]:
        """
        Try to consume tokens.

        Returns (allowed, remaining) tuple.
        """
        with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, int(self.tokens)

            return False, int(self.tokens)

    def remaining(self) -> int:
        """Get remaining tokens."""
        with self._lock:
            self._refill()
            return int(self.tokens)


# ============================================================================
# Sliding Window Algorithm
# ============================================================================


class SlidingWindow:
    """
    Sliding window rate limiter.

    More accurate than fixed window but higher memory usage.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: float,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: List[float] = []
        self._lock = threading.Lock()

    def _cleanup(self, now: float) -> None:
        """Remove expired requests."""
        cutoff = now - self.window_seconds
        self.requests = [t for t in self.requests if t > cutoff]

    def record(self) -> Tuple[bool, int]:
        """
        Record a request.

        Returns (allowed, remaining) tuple.
        """
        with self._lock:
            now = time.time()
            self._cleanup(now)

            if len(self.requests) < self.limit:
                self.requests.append(now)
                return True, self.limit - len(self.requests)

            return False, 0

    def remaining(self) -> int:
        """Get remaining requests in window."""
        with self._lock:
            self._cleanup(time.time())
            return max(0, self.limit - len(self.requests))

    def reset_at(self) -> float:
        """Get timestamp when oldest request expires."""
        with self._lock:
            if self.requests:
                return self.requests[0] + self.window_seconds
            return time.time()


# ============================================================================
# Fixed Window Algorithm
# ============================================================================


class FixedWindow:
    """
    Fixed window rate limiter.

    Simple and memory-efficient but can allow 2x burst at window edges.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: float,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.count = 0
        self.window_start = time.time()
        self._lock = threading.Lock()

    def _check_window(self, now: float) -> None:
        """Reset counter if window has passed."""
        elapsed = now - self.window_start
        if elapsed >= self.window_seconds:
            self.count = 0
            self.window_start = now

    def record(self) -> Tuple[bool, int]:
        """
        Record a request.

        Returns (allowed, remaining) tuple.
        """
        with self._lock:
            now = time.time()
            self._check_window(now)

            if self.count < self.limit:
                self.count += 1
                return True, self.limit - self.count

            return False, 0

    def remaining(self) -> int:
        """Get remaining requests in window."""
        with self._lock:
            self._check_window(time.time())
            return max(0, self.limit - self.count)

    def reset_at(self) -> float:
        """Get timestamp when window resets."""
        return self.window_start + self.window_seconds


# ============================================================================
# Rate Limiter
# ============================================================================


class RateLimiter:
    """
    Multi-key rate limiter with configurable algorithms.

    Supports:
        - Per-tenant limits
        - Per-surface limits
        - Multiple time windows
        - Burst handling
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._lock = threading.Lock()

        # Buckets by key (tenant_id or IP)
        self._buckets: Dict[str, TokenBucket] = {}
        self._windows: Dict[str, SlidingWindow] = {}
        self._fixed_windows: Dict[str, FixedWindow] = {}

    def _get_bucket(self, key: str) -> TokenBucket:
        """Get or create token bucket for key."""
        if key not in self._buckets:
            with self._lock:
                if key not in self._buckets:
                    self._buckets[key] = TokenBucket(
                        rate=self.config.requests_per_second,
                        capacity=self.config.burst_size,
                    )
        return self._buckets[key]

    def _get_window(self, key: str, window_seconds: float, limit: int) -> SlidingWindow:
        """Get or create sliding window for key."""
        window_key = f"{key}:{window_seconds}"
        if window_key not in self._windows:
            with self._lock:
                if window_key not in self._windows:
                    self._windows[window_key] = SlidingWindow(limit, window_seconds)
        return self._windows[window_key]

    def _get_fixed_window(
        self, key: str, window_seconds: float, limit: int
    ) -> FixedWindow:
        """Get or create fixed window for key."""
        window_key = f"{key}:{window_seconds}"
        if window_key not in self._fixed_windows:
            with self._lock:
                if window_key not in self._fixed_windows:
                    self._fixed_windows[window_key] = FixedWindow(limit, window_seconds)
        return self._fixed_windows[window_key]

    def _get_surface_limit(self, surface: str, base_limit: float) -> float:
        """Apply surface multiplier to limit."""
        multiplier = self.config.surface_multipliers.get(surface, 1.0)
        return base_limit * multiplier

    def allow(
        self,
        key: str,
        surface: str = "",
        tokens: int = 1,
    ) -> RateLimitResult:
        """
        Check if request is allowed.

        Args:
            key: Rate limit key (tenant_id, IP, etc.)
            surface: Execution surface for surface-specific limits
            tokens: Number of tokens to consume

        Returns:
            RateLimitResult with allowed status and metadata.
        """
        try:
            if self.config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                return self._check_token_bucket(key, surface, tokens)
            elif self.config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                return self._check_sliding_window(key, surface)
            else:
                return self._check_fixed_window(key, surface)

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")

            if self.config.fail_open:
                return RateLimitResult(
                    allowed=True,
                    remaining=999,
                    reset_at=time.time() + 60,
                )
            else:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=time.time() + 60,
                    retry_after_seconds=60,
                )

    def _check_token_bucket(
        self,
        key: str,
        surface: str,
        tokens: int,
    ) -> RateLimitResult:
        """Check using token bucket algorithm."""
        bucket = self._get_bucket(key)
        allowed, remaining = bucket.consume(tokens)

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=time.time() + (1.0 / bucket.rate) if not allowed else 0,
            retry_after_seconds=1.0 / bucket.rate if not allowed else 0,
            limit=bucket.capacity,
        )

    def _check_sliding_window(
        self,
        key: str,
        surface: str,
    ) -> RateLimitResult:
        """Check using sliding window algorithm."""
        limit = int(self._get_surface_limit(surface, self.config.requests_per_minute))
        window = self._get_window(key, 60.0, limit)

        allowed, remaining = window.record()

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=window.reset_at(),
            retry_after_seconds=window.reset_at() - time.time() if not allowed else 0,
            limit=limit,
        )

    def _check_fixed_window(
        self,
        key: str,
        surface: str,
    ) -> RateLimitResult:
        """Check using fixed window algorithm."""
        limit = int(self._get_surface_limit(surface, self.config.requests_per_minute))
        window = self._get_fixed_window(key, 60.0, limit)

        allowed, remaining = window.record()

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=window.reset_at(),
            retry_after_seconds=window.reset_at() - time.time() if not allowed else 0,
            limit=limit,
        )

    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key."""
        if self.config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            if key in self._buckets:
                return self._buckets[key].remaining()
        return self.config.burst_size

    def reset(self, key: str) -> None:
        """Reset limits for a key."""
        with self._lock:
            self._buckets.pop(key, None)

            # Remove all windows for this key
            keys_to_remove = [k for k in self._windows if k.startswith(f"{key}:")]
            for k in keys_to_remove:
                del self._windows[k]

            keys_to_remove = [k for k in self._fixed_windows if k.startswith(f"{key}:")]
            for k in keys_to_remove:
                del self._fixed_windows[k]

    def cleanup_expired(self) -> int:
        """Clean up expired entries. Returns count removed."""
        # Token buckets don't need cleanup
        # Windows auto-cleanup on access
        return 0


# ============================================================================
# Middleware
# ============================================================================


class RateLimitMiddleware:
    """
    Rate limiting middleware for FastAPI/Starlette.

    Usage:
        app.add_middleware(RateLimitMiddleware, limiter=limiter)
    """

    def __init__(
        self,
        app,
        limiter: RateLimiter,
        key_func: Optional[callable] = None,
    ):
        self.app = app
        self.limiter = limiter
        self.key_func = key_func or self._default_key

    def _default_key(self, request) -> str:
        """Default key extraction (client IP or tenant)."""
        # Try tenant ID from header
        tenant_id = request.headers.get("X-Tenant-Id")
        if tenant_id:
            return f"tenant:{tenant_id}"

        # Fall back to IP
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive)
        key = self.key_func(request)

        # Get surface from path or header
        surface = request.headers.get("X-Surface", "")

        result = self.limiter.allow(key, surface)

        if not result.allowed:
            response = JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests",
                    "retry_after": result.retry_after_seconds,
                },
                headers=result.to_headers(),
            )
            await response(scope, receive, send)
            return

        # Add rate limit headers to response
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                for key, value in result.to_headers().items():
                    if value:
                        headers[key.lower().encode()] = value.encode()
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ============================================================================
# Global Instance
# ============================================================================

_limiter: Optional[RateLimiter] = None
_limiter_lock = threading.Lock()


def get_rate_limiter(config: Optional[RateLimitConfig] = None) -> RateLimiter:
    """Get or create global rate limiter."""
    global _limiter

    with _limiter_lock:
        if _limiter is None:
            _limiter = RateLimiter(config)
        return _limiter


def configure_rate_limiter(config: RateLimitConfig) -> RateLimiter:
    """Configure global rate limiter."""
    global _limiter

    with _limiter_lock:
        _limiter = RateLimiter(config)
        return _limiter


def check_rate_limit(
    key: str,
    surface: str = "",
) -> RateLimitResult:
    """Check rate limit using global limiter."""
    return get_rate_limiter().allow(key, surface)


def require_rate_limit(
    key: str,
    surface: str = "",
) -> None:
    """Check rate limit and raise if exceeded."""
    result = check_rate_limit(key, surface)
    if not result.allowed:
        raise RateLimitExceeded(result)
