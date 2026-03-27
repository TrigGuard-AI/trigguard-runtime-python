"""
TrigGuard Cache Tests

Unit tests for the decision caching layer.
"""

import pytest
import time
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from trigguard.cache.decision_cache import (
    DecisionCache,
    DecisionCacheConfig,
    InMemoryCache,
    CacheEntry,
    CacheStats,
    CacheStrategy,
    get_cache,
    configure_cache,
    cached_evaluate,
    cached_evaluate_sync,
)


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_entry_creation(self):
        """Test creating cache entry."""
        entry = CacheEntry(
            value={"permit": True},
            created_at=time.time(),
            expires_at=time.time() + 300,
            policy_version="v1",
        )

        assert entry.value == {"permit": True}
        assert entry.access_count == 0


class TestCacheStats:
    """Test CacheStats."""

    def test_hit_rate_calculation(self):
        """Test hit rate calculation."""
        stats = CacheStats(hits=80, misses=20)
        assert stats.hit_rate == 0.8

    def test_hit_rate_zero_total(self):
        """Test hit rate with no requests."""
        stats = CacheStats()
        assert stats.hit_rate == 0.0

    def test_to_dict(self):
        """Test stats export."""
        stats = CacheStats(hits=10, misses=5, size=100)
        data = stats.to_dict()

        assert data["hits"] == 10
        assert data["misses"] == 5
        assert data["hit_rate"] == 10 / 15


class TestInMemoryCache:
    """Test in-memory cache backend."""

    def test_get_miss(self):
        """Test cache miss."""
        cache = InMemoryCache()
        result = cache.get("nonexistent")

        assert result is None
        assert cache.stats().misses == 1

    def test_set_and_get(self):
        """Test setting and getting value."""
        cache = InMemoryCache()
        cache.set("key1", {"permit": True})

        result = cache.get("key1")

        assert result == {"permit": True}
        assert cache.stats().hits == 1

    def test_ttl_expiration(self):
        """Test TTL-based expiration."""
        cache = InMemoryCache(default_ttl_seconds=0.1)
        cache.set("key1", {"permit": True}, ttl_seconds=0.1)

        # Should exist immediately
        assert cache.get("key1") is not None

        # Wait for expiration
        time.sleep(0.15)

        # Should be expired
        assert cache.get("key1") is None

    def test_lru_eviction(self):
        """Test LRU eviction at capacity."""
        cache = InMemoryCache(max_size=3)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Access key1 to make it recently used
        cache.get("key1")

        # Add key4, should evict key2 (least recently used)
        cache.set("key4", "value4")

        assert cache.get("key1") is not None  # Recently accessed
        assert cache.get("key2") is None  # Evicted
        assert cache.get("key3") is not None
        assert cache.get("key4") is not None

    def test_delete(self):
        """Test deleting entry."""
        cache = InMemoryCache()
        cache.set("key1", "value1")

        assert cache.delete("key1") is True
        assert cache.get("key1") is None
        assert cache.delete("nonexistent") is False

    def test_clear(self):
        """Test clearing cache."""
        cache = InMemoryCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.stats().size == 0

    def test_policy_invalidation(self):
        """Test invalidating entries on policy change."""
        cache = InMemoryCache()

        # Set entries with policy version
        cache.set("key1", "value1", policy_version="v1")
        cache.set("key2", "value2", policy_version="v1")
        cache.set("key3", "value3", policy_version="v2")

        # Invalidate v1
        count = cache.invalidate_policy("v1", "v3")

        assert count == 2
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        # key3 was v2, but now current is v3, so it should also be invalid
        # Actually, key3 should still be there until accessed with version mismatch

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = InMemoryCache()
        cache.set("key1", "value1", ttl_seconds=0.05)
        cache.set("key2", "value2", ttl_seconds=1.0)

        time.sleep(0.1)

        count = cache.cleanup_expired()

        assert count == 1
        assert cache.get("key1") is None
        assert cache.get("key2") is not None


class TestDecisionCache:
    """Test DecisionCache."""

    def test_hash_determinism(self):
        """Test request hashing is deterministic."""
        cache = DecisionCache()

        request = {
            "surface": "read",
            "action": "get_data",
            "arguments": {"id": 123},
        }

        hash1 = cache.hash_request(request)
        hash2 = cache.hash_request(request)

        assert hash1 == hash2

    def test_hash_different_for_different_requests(self):
        """Test different requests have different hashes."""
        cache = DecisionCache()

        hash1 = cache.hash_request({"surface": "read"})
        hash2 = cache.hash_request({"surface": "write"})

        assert hash1 != hash2

    def test_hash_ignores_signals(self):
        """Test signals are not included in hash."""
        cache = DecisionCache()

        request1 = {"surface": "read", "signals": [{"type": "anomaly"}]}
        request2 = {"surface": "read", "signals": []}

        # Both have same surface, different signals
        # But signals are dynamic, so hash should be same for base request
        hash1 = cache.hash_request(request1)
        hash2 = cache.hash_request(request2)

        # Actually signals ARE excluded from hash, so these should match
        assert hash1 == hash2

    def test_uncacheable_surface(self):
        """Test uncacheable surfaces are not cached."""
        config = DecisionCacheConfig(uncacheable_surfaces=["code_execution"])
        cache = DecisionCache(config)

        request = {"surface": "code_execution", "action": "run"}
        result = {"permit": False}

        cache.set(request, result)

        # Should not be cached
        assert cache.get(request) is None

    def test_requests_with_signals_not_cached(self):
        """Test requests with signals are not cached."""
        cache = DecisionCache()

        request = {
            "surface": "read",
            "signals": [{"type": "anomaly"}],
        }
        result = {"permit": True}

        cache.set(request, result)

        # Should not be cached (signals = dynamic)
        assert cache.get(request) is None

    def test_surface_specific_ttl(self):
        """Test surface-specific TTL configuration."""
        config = DecisionCacheConfig(
            default_ttl_seconds=300,
            ttl_by_surface={
                "read": 600,  # Longer TTL for reads
                "write": 60,  # Shorter TTL for writes
            },
        )
        cache = DecisionCache(config)

        # These would use different TTLs internally
        cache.set({"surface": "read"}, {"permit": True})
        cache.set({"surface": "write"}, {"permit": True})

        # Both should be cached
        assert cache.get({"surface": "read"}) is not None
        assert cache.get({"surface": "write"}) is not None

    def test_disabled_cache(self):
        """Test cache when disabled."""
        config = DecisionCacheConfig(enabled=False)
        cache = DecisionCache(config)

        request = {"surface": "read"}
        cache.set(request, {"permit": True})

        assert cache.get(request) is None

    def test_stats(self):
        """Test stats retrieval."""
        cache = DecisionCache()

        cache.set({"surface": "read"}, {"permit": True})
        cache.get({"surface": "read"})  # Hit
        cache.get({"surface": "write"})  # Miss

        stats = cache.stats()
        assert stats.hits == 1
        assert stats.misses == 1


class TestGlobalCache:
    """Test global cache functions."""

    def test_get_cache_singleton(self):
        """Test get_cache returns singleton."""
        # Reset global cache
        import cache.decision_cache as module

        module._cache = None

        cache1 = get_cache()
        cache2 = get_cache()

        assert cache1 is cache2

    def test_configure_cache(self):
        """Test configuring global cache."""
        config = DecisionCacheConfig(max_size=5000)
        cache = configure_cache(config)

        assert cache.config.max_size == 5000


class TestCachedEvaluate:
    """Test cached evaluation functions."""

    @pytest.mark.asyncio
    async def test_cached_evaluate_miss(self):
        """Test cached_evaluate on cache miss."""
        # Reset cache
        import cache.decision_cache as module

        module._cache = None

        evaluator = AsyncMock(return_value={"permit": True})

        result = await cached_evaluate(
            {"surface": "read"},
            evaluator,
        )

        assert result == {"permit": True}
        evaluator.assert_called_once()

    @pytest.mark.asyncio
    async def test_cached_evaluate_hit(self):
        """Test cached_evaluate on cache hit."""
        import cache.decision_cache as module

        module._cache = None

        cache = get_cache()
        request = {"surface": "read", "action": "test"}
        cache.set(request, {"permit": True, "cached": True})

        evaluator = AsyncMock(return_value={"permit": True})

        result = await cached_evaluate(request, evaluator)

        # Should return cached result without calling evaluator
        assert result["cached"] is True
        evaluator.assert_not_called()

    def test_cached_evaluate_sync(self):
        """Test synchronous cached evaluation."""
        import cache.decision_cache as module

        module._cache = None

        evaluator = Mock(return_value={"permit": True})

        result = cached_evaluate_sync(
            {"surface": "read"},
            evaluator,
        )

        assert result == {"permit": True}
        evaluator.assert_called_once()

        # Second call should hit cache
        result2 = cached_evaluate_sync(
            {"surface": "read"},
            evaluator,
        )

        # Evaluator should still only be called once
        evaluator.assert_called_once()


class TestCacheIntegration:
    """Integration tests."""

    def test_full_cache_flow(self):
        """Test complete cache workflow."""
        config = DecisionCacheConfig(
            max_size=100,
            default_ttl_seconds=5,
            uncacheable_surfaces=["code_execution"],
        )
        cache = DecisionCache(config)

        # Cache some decisions
        for i in range(10):
            cache.set(
                {"surface": "read", "action": f"get_{i}"},
                {"permit": True, "idx": i},
            )

        # Verify hits
        for i in range(10):
            result = cache.get({"surface": "read", "action": f"get_{i}"})
            assert result is not None
            assert result["idx"] == i

        # Verify stats
        stats = cache.stats()
        assert stats.hits == 10

        # Policy invalidation
        cache.invalidate_policy("v1", "v2")

        # All should be invalidated
        for i in range(10):
            result = cache.get({"surface": "read", "action": f"get_{i}"})
            assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
