"""
TrigGuard Rate Limiting Tests

Unit tests for rate limiting algorithms.
"""

import pytest
import time
from unittest.mock import Mock, patch

from ratelimit.limiter import (
    RateLimiter,
    RateLimitConfig,
    RateLimitResult,
    RateLimitAlgorithm,
    RateLimitExceeded,
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    get_rate_limiter,
    configure_rate_limiter,
    check_rate_limit,
    require_rate_limit,
)


class TestTokenBucket:
    """Test token bucket algorithm."""
    
    def test_initial_capacity(self):
        """Test bucket starts full."""
        bucket = TokenBucket(rate=10.0, capacity=100)
        assert bucket.remaining() == 100
    
    def test_consume_success(self):
        """Test consuming available tokens."""
        bucket = TokenBucket(rate=10.0, capacity=100)
        
        allowed, remaining = bucket.consume(10)
        
        assert allowed is True
        assert remaining == 90
    
    def test_consume_failure(self):
        """Test consuming more than available."""
        bucket = TokenBucket(rate=10.0, capacity=10)
        
        bucket.consume(10)  # Empty the bucket
        allowed, remaining = bucket.consume(1)
        
        assert allowed is False
        assert remaining == 0
    
    def test_refill(self):
        """Test token refill over time."""
        bucket = TokenBucket(rate=10.0, capacity=10)
        
        bucket.consume(10)  # Empty
        time.sleep(0.2)  # Wait for refill
        
        remaining = bucket.remaining()
        assert remaining >= 1  # Should have refilled some
    
    def test_refill_capped(self):
        """Test refill doesn't exceed capacity."""
        bucket = TokenBucket(rate=100.0, capacity=10)
        
        time.sleep(0.2)
        remaining = bucket.remaining()
        
        assert remaining <= 10  # Should not exceed capacity


class TestSlidingWindow:
    """Test sliding window algorithm."""
    
    def test_record_within_limit(self):
        """Test recording within limit."""
        window = SlidingWindow(limit=10, window_seconds=1.0)
        
        allowed, remaining = window.record()
        
        assert allowed is True
        assert remaining == 9
    
    def test_record_exceeds_limit(self):
        """Test recording that exceeds limit."""
        window = SlidingWindow(limit=3, window_seconds=1.0)
        
        for _ in range(3):
            window.record()
        
        allowed, remaining = window.record()
        
        assert allowed is False
        assert remaining == 0
    
    def test_window_expiration(self):
        """Test requests expire after window."""
        window = SlidingWindow(limit=3, window_seconds=0.1)
        
        for _ in range(3):
            window.record()
        
        time.sleep(0.15)
        
        allowed, remaining = window.record()
        assert allowed is True
    
    def test_reset_at(self):
        """Test reset timestamp."""
        window = SlidingWindow(limit=10, window_seconds=60.0)
        window.record()
        
        reset = window.reset_at()
        assert reset > time.time()
        assert reset <= time.time() + 60


class TestFixedWindow:
    """Test fixed window algorithm."""
    
    def test_record_within_limit(self):
        """Test recording within limit."""
        window = FixedWindow(limit=10, window_seconds=1.0)
        
        allowed, remaining = window.record()
        
        assert allowed is True
        assert remaining == 9
    
    def test_record_exceeds_limit(self):
        """Test recording that exceeds limit."""
        window = FixedWindow(limit=3, window_seconds=1.0)
        
        for _ in range(3):
            window.record()
        
        allowed, remaining = window.record()
        
        assert allowed is False
        assert remaining == 0
    
    def test_window_reset(self):
        """Test window resets after period."""
        window = FixedWindow(limit=3, window_seconds=0.1)
        
        for _ in range(3):
            window.record()
        
        time.sleep(0.15)
        
        allowed, remaining = window.record()
        assert allowed is True
        assert remaining == 2  # Limit - 1


class TestRateLimitResult:
    """Test rate limit result."""
    
    def test_to_headers(self):
        """Test header generation."""
        result = RateLimitResult(
            allowed=True,
            remaining=50,
            reset_at=1234567890.0,
            limit=100,
        )
        
        headers = result.to_headers()
        
        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "50"
        assert headers["X-RateLimit-Reset"] == "1234567890"
    
    def test_to_headers_denied(self):
        """Test headers when denied."""
        result = RateLimitResult(
            allowed=False,
            remaining=0,
            reset_at=1234567890.0,
            retry_after_seconds=30,
            limit=100,
        )
        
        headers = result.to_headers()
        assert headers["Retry-After"] == "30"


class TestRateLimitConfig:
    """Test rate limit configuration."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = RateLimitConfig()
        
        assert config.requests_per_second == 100.0
        assert config.burst_size == 50
        assert config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET
        assert config.fail_open is False


class TestRateLimiter:
    """Test main rate limiter."""
    
    def test_allow_within_limit(self):
        """Test allowing request within limit."""
        config = RateLimitConfig(
            requests_per_second=100.0,
            burst_size=50,
        )
        limiter = RateLimiter(config)
        
        result = limiter.allow("tenant-1")
        
        assert result.allowed is True
        assert result.remaining < 50
    
    def test_deny_over_limit(self):
        """Test denying request over limit."""
        config = RateLimitConfig(
            requests_per_second=1.0,
            burst_size=2,
        )
        limiter = RateLimiter(config)
        
        limiter.allow("tenant-1")
        limiter.allow("tenant-1")
        result = limiter.allow("tenant-1")
        
        assert result.allowed is False
    
    def test_different_keys_isolated(self):
        """Test different keys have separate limits."""
        config = RateLimitConfig(burst_size=2)
        limiter = RateLimiter(config)
        
        limiter.allow("tenant-1")
        limiter.allow("tenant-1")
        
        # tenant-2 should have full quota
        result = limiter.allow("tenant-2")
        assert result.allowed is True
    
    def test_sliding_window_algorithm(self):
        """Test sliding window algorithm."""
        config = RateLimitConfig(
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            requests_per_minute=5,
        )
        limiter = RateLimiter(config)
        
        for _ in range(5):
            result = limiter.allow("key")
            assert result.allowed is True
        
        result = limiter.allow("key")
        assert result.allowed is False
    
    def test_fixed_window_algorithm(self):
        """Test fixed window algorithm."""
        config = RateLimitConfig(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            requests_per_minute=5,
        )
        limiter = RateLimiter(config)
        
        for _ in range(5):
            result = limiter.allow("key")
            assert result.allowed is True
        
        result = limiter.allow("key")
        assert result.allowed is False
    
    def test_surface_multiplier(self):
        """Test surface-specific multipliers."""
        config = RateLimitConfig(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            requests_per_minute=10,
            surface_multipliers={"spend": 0.1},  # 10% of normal
        )
        limiter = RateLimiter(config)
        
        # Spend surface should only allow 1 request (10 * 0.1 = 1)
        result = limiter.allow("key", surface="spend")
        assert result.allowed is True
        
        result = limiter.allow("key", surface="spend")
        assert result.allowed is False
    
    def test_fail_open(self):
        """Test fail-open on error."""
        config = RateLimitConfig(fail_open=True)
        limiter = RateLimiter(config)
        
        # Force an error by breaking internal state
        with patch.object(limiter, "_get_bucket", side_effect=Exception("Test error")):
            result = limiter.allow("key")
        
        assert result.allowed is True
    
    def test_fail_closed(self):
        """Test fail-closed on error (default)."""
        config = RateLimitConfig(fail_open=False)
        limiter = RateLimiter(config)
        
        with patch.object(limiter, "_get_bucket", side_effect=Exception("Test error")):
            result = limiter.allow("key")
        
        assert result.allowed is False
    
    def test_get_remaining(self):
        """Test getting remaining count."""
        config = RateLimitConfig(burst_size=100)
        limiter = RateLimiter(config)
        
        limiter.allow("key")
        limiter.allow("key")
        
        remaining = limiter.get_remaining("key")
        assert remaining == 98
    
    def test_reset_key(self):
        """Test resetting limits for key."""
        config = RateLimitConfig(burst_size=2)
        limiter = RateLimiter(config)
        
        limiter.allow("key")
        limiter.allow("key")
        assert limiter.allow("key").allowed is False
        
        limiter.reset("key")
        assert limiter.allow("key").allowed is True


class TestRateLimitExceeded:
    """Test rate limit exception."""
    
    def test_exception_has_result(self):
        """Test exception contains result."""
        result = RateLimitResult(
            allowed=False,
            remaining=0,
            reset_at=time.time() + 60,
        )
        
        exc = RateLimitExceeded(result)
        
        assert exc.result == result
        assert "exceeded" in str(exc).lower()


class TestGlobalLimiter:
    """Test global limiter functions."""
    
    def test_get_rate_limiter_singleton(self):
        """Test global limiter is singleton."""
        import ratelimit.limiter as module
        module._limiter = None
        
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        
        assert limiter1 is limiter2
    
    def test_configure_rate_limiter(self):
        """Test configuring global limiter."""
        config = RateLimitConfig(burst_size=999)
        limiter = configure_rate_limiter(config)
        
        assert limiter.config.burst_size == 999
    
    def test_check_rate_limit(self):
        """Test global check function."""
        import ratelimit.limiter as module
        module._limiter = None
        
        result = check_rate_limit("test-key")
        assert isinstance(result, RateLimitResult)
    
    def test_require_rate_limit_success(self):
        """Test require doesn't raise when allowed."""
        import ratelimit.limiter as module
        module._limiter = None
        
        require_rate_limit("test-key-new")  # Should not raise
    
    def test_require_rate_limit_failure(self):
        """Test require raises when denied."""
        config = RateLimitConfig(burst_size=0)  # No capacity
        configure_rate_limiter(config)
        
        with pytest.raises(RateLimitExceeded):
            require_rate_limit("test-key")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
