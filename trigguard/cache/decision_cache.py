"""
TrigGuard Decision Cache

High-performance caching layer for frequently evaluated requests.

The cache uses a determinism-safe approach:
- Only caches decisions for identical request hashes
- Automatically invalidates on policy changes
- Supports TTL and LRU eviction policies
- Thread-safe for concurrent access

Usage:
    from trigguard.cache.decision_cache import get_cache, cached_evaluate

    cache = get_cache()

    # Direct cache access
    result = cache.get(request_hash)
    cache.set(request_hash, result)

    # Cached evaluation
    result = await cached_evaluate(request)
"""

import hashlib
import json
import time
import threading
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Generic, TypeVar
from collections import OrderedDict
from datetime import datetime, timezone

logger = logging.getLogger("trigguard.cache")


T = TypeVar("T")


class CacheStrategy(Enum):
    """Cache eviction strategy."""

    LRU = "lru"  # Least Recently Used
    TTL = "ttl"  # Time-To-Live only
    LRU_TTL = "lru_ttl"  # Both LRU and TTL


@dataclass
class CacheEntry:
    """Single cache entry."""

    value: Any
    created_at: float
    expires_at: float
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    policy_version: str = ""


@dataclass
class CacheStats:
    """Cache statistics."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0
    size: int = 0
    max_size: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "invalidations": self.invalidations,
            "size": self.size,
            "max_size": self.max_size,
            "hit_rate": self.hit_rate,
        }


class CacheBackend(ABC, Generic[T]):
    """Abstract cache backend."""

    @abstractmethod
    def get(self, key: str) -> Optional[T]:
        """Get value from trigguard.cache."""
        pass

    @abstractmethod
    def set(self, key: str, value: T, ttl_seconds: float = 0) -> None:
        """Set value in cache."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete key from trigguard.cache."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all entries."""
        pass

    @abstractmethod
    def stats(self) -> CacheStats:
        """Get cache statistics."""
        pass


class InMemoryCache(CacheBackend[T]):
    """
    In-memory LRU cache with TTL support.

    Thread-safe implementation using OrderedDict.
    """

    def __init__(
        self,
        max_size: int = 10000,
        default_ttl_seconds: float = 300.0,
        strategy: CacheStrategy = CacheStrategy.LRU_TTL,
    ):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._max_size = max_size
        self._default_ttl = default_ttl_seconds
        self._strategy = strategy
        self._stats = CacheStats(max_size=max_size)
        self._current_policy_version = ""

    def get(self, key: str) -> Optional[T]:
        """Get value from trigguard.cache."""
        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._stats.misses += 1
                return None

            now = time.time()

            # Check TTL
            if entry.expires_at > 0 and now > entry.expires_at:
                del self._cache[key]
                self._stats.misses += 1
                self._stats.evictions += 1
                return None

            # Check policy version
            if (
                self._current_policy_version
                and entry.policy_version != self._current_policy_version
            ):
                del self._cache[key]
                self._stats.misses += 1
                self._stats.invalidations += 1
                return None

            # Update access metadata for LRU
            entry.access_count += 1
            entry.last_accessed = now
            self._cache.move_to_end(key)

            self._stats.hits += 1
            return entry.value

    def set(
        self,
        key: str,
        value: T,
        ttl_seconds: float = 0,
        policy_version: str = "",
    ) -> None:
        """Set value in cache."""
        with self._lock:
            now = time.time()
            ttl = ttl_seconds if ttl_seconds > 0 else self._default_ttl

            entry = CacheEntry(
                value=value,
                created_at=now,
                expires_at=now + ttl if ttl > 0 else 0,
                policy_version=policy_version or self._current_policy_version,
            )

            # Evict if at capacity
            while len(self._cache) >= self._max_size:
                self._evict_one()

            self._cache[key] = entry
            self._cache.move_to_end(key)
            self._stats.size = len(self._cache)

    def _evict_one(self) -> None:
        """Evict one entry based on strategy."""
        if not self._cache:
            return

        # LRU: remove oldest (first in OrderedDict)
        key = next(iter(self._cache))
        del self._cache[key]
        self._stats.evictions += 1

    def delete(self, key: str) -> bool:
        """Delete key from trigguard.cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._stats.size = len(self._cache)
                return True
            return False

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._stats.evictions += count
            self._stats.size = 0

    def invalidate_policy(self, old_version: str, new_version: str) -> int:
        """
        Invalidate entries for old policy version.

        Returns number of invalidated entries.
        """
        with self._lock:
            self._current_policy_version = new_version

            keys_to_remove = [
                k for k, v in self._cache.items() if v.policy_version == old_version
            ]

            for key in keys_to_remove:
                del self._cache[key]

            count = len(keys_to_remove)
            self._stats.invalidations += count
            self._stats.size = len(self._cache)

            logger.info(
                f"Policy invalidation: {count} entries removed "
                f"({old_version} -> {new_version})"
            )

            return count

    def stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            self._stats.size = len(self._cache)
            return self._stats

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        with self._lock:
            now = time.time()
            expired = [
                k
                for k, v in self._cache.items()
                if v.expires_at > 0 and now > v.expires_at
            ]

            for key in expired:
                del self._cache[key]

            count = len(expired)
            self._stats.evictions += count
            self._stats.size = len(self._cache)
            return count


class RedisCache(CacheBackend[T]):
    """
    Redis-backed cache for distributed deployments.

    Requires redis-py: pip install redis
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        prefix: str = "trigguard:",
        default_ttl_seconds: float = 300.0,
        password: Optional[str] = None,
    ):
        try:
            import redis
        except ImportError:
            raise ImportError(
                "redis is required for RedisCache. " "Install with: pip install redis"
            )

        self._client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=True,
        )
        self._prefix = prefix
        self._default_ttl = default_ttl_seconds
        self._stats = CacheStats()

    def _key(self, key: str) -> str:
        """Get prefixed key."""
        return f"{self._prefix}{key}"

    def get(self, key: str) -> Optional[T]:
        """Get value from Redis."""
        try:
            data = self._client.get(self._key(key))
            if data is None:
                self._stats.misses += 1
                return None

            self._stats.hits += 1
            return json.loads(data)
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            self._stats.misses += 1
            return None

    def set(
        self,
        key: str,
        value: T,
        ttl_seconds: float = 0,
        **kwargs,
    ) -> None:
        """Set value in Redis."""
        try:
            ttl = int(ttl_seconds if ttl_seconds > 0 else self._default_ttl)
            data = json.dumps(value, default=str)
            self._client.setex(self._key(key), ttl, data)
        except Exception as e:
            logger.error(f"Redis set error: {e}")

    def delete(self, key: str) -> bool:
        """Delete key from Redis."""
        try:
            return self._client.delete(self._key(key)) > 0
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False

    def clear(self) -> None:
        """Clear all entries with prefix."""
        try:
            keys = self._client.keys(f"{self._prefix}*")
            if keys:
                self._client.delete(*keys)
        except Exception as e:
            logger.error(f"Redis clear error: {e}")

    def stats(self) -> CacheStats:
        """Get cache statistics."""
        try:
            info = self._client.info("memory")
            self._stats.size = self._client.dbsize()
        except Exception:
            pass
        return self._stats


@dataclass
class DecisionCacheConfig:
    """Configuration for decision cache."""

    enabled: bool = True
    backend: str = "memory"  # "memory" or "redis"
    max_size: int = 10000
    default_ttl_seconds: float = 300.0

    # Surface-specific TTLs
    ttl_by_surface: Dict[str, float] = field(default_factory=dict)

    # Redis config
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    # Disable caching for specific surfaces
    uncacheable_surfaces: List[str] = field(
        default_factory=lambda: ["code_execution", "delegation"]
    )


class DecisionCache:
    """
    Decision cache with support for policy-aware invalidation.

    Features:
        - Determinism-safe hashing of requests
        - Policy version-aware invalidation
        - Surface-specific TTLs
        - Optional bypass for irreversible surfaces
    """

    def __init__(self, config: Optional[DecisionCacheConfig] = None):
        self.config = config or DecisionCacheConfig()

        if self.config.backend == "redis":
            self._backend: CacheBackend = RedisCache(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                default_ttl_seconds=self.config.default_ttl_seconds,
            )
        else:
            self._backend = InMemoryCache(
                max_size=self.config.max_size,
                default_ttl_seconds=self.config.default_ttl_seconds,
            )

        self._policy_version = ""

    def hash_request(self, request: Dict[str, Any]) -> str:
        """
        Generate deterministic hash for a request.

        The hash must be stable across identical requests.
        """
        # Normalize request for consistent hashing
        normalized = {
            "surface": request.get("surface", ""),
            "action": request.get("action", ""),
            "arguments": json.dumps(
                request.get("arguments", {}),
                sort_keys=True,
            ),
            "context": json.dumps(
                request.get("context", {}),
                sort_keys=True,
            ),
            # Note: signals are NOT included in hash (dynamic)
        }

        canonical = json.dumps(normalized, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]

    def get(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get cached decision for request.

        Returns None if not cached or surface is uncacheable.
        """
        if not self.config.enabled:
            return None

        surface = request.get("surface", "")

        # Check if surface is cacheable
        if surface in self.config.uncacheable_surfaces:
            return None

        # Check for signals (dynamic data = uncacheable)
        if request.get("signals"):
            return None

        request_hash = self.hash_request(request)
        cached = self._backend.get(request_hash)

        if cached:
            logger.debug(f"Cache hit: {request_hash[:8]}...")

        return cached

    def set(
        self,
        request: Dict[str, Any],
        result: Dict[str, Any],
        policy_version: str = "",
    ) -> None:
        """
        Cache a decision result.

        Only caches if surface is cacheable.
        """
        if not self.config.enabled:
            return

        surface = request.get("surface", "")

        # Don't cache uncacheable surfaces
        if surface in self.config.uncacheable_surfaces:
            return

        # Don't cache if request had signals
        if request.get("signals"):
            return

        request_hash = self.hash_request(request)

        # Get surface-specific TTL
        ttl = self.config.ttl_by_surface.get(
            surface,
            self.config.default_ttl_seconds,
        )

        # Store with policy version for invalidation
        if hasattr(self._backend, "set"):
            self._backend.set(
                request_hash,
                result,
                ttl_seconds=ttl,
                policy_version=policy_version,
            )

    def invalidate_policy(self, old_version: str, new_version: str) -> None:
        """Invalidate cache on policy change."""
        self._policy_version = new_version

        if hasattr(self._backend, "invalidate_policy"):
            self._backend.invalidate_policy(old_version, new_version)
        else:
            # Fallback: clear entire cache
            self._backend.clear()

    def stats(self) -> CacheStats:
        """Get cache statistics."""
        return self._backend.stats()

    def clear(self) -> None:
        """Clear the cache."""
        self._backend.clear()


# Global cache instance
_cache: Optional[DecisionCache] = None
_cache_lock = threading.Lock()


def get_cache(config: Optional[DecisionCacheConfig] = None) -> DecisionCache:
    """Get or create the global cache instance."""
    global _cache

    with _cache_lock:
        if _cache is None:
            _cache = DecisionCache(config)
        return _cache


def configure_cache(config: DecisionCacheConfig) -> DecisionCache:
    """Configure and replace the global cache."""
    global _cache

    with _cache_lock:
        _cache = DecisionCache(config)
        return _cache


# Cache-aware evaluation wrapper
async def cached_evaluate(
    request: Dict[str, Any],
    evaluator: Callable,
    policy_version: str = "",
) -> Dict[str, Any]:
    """
    Evaluate with caching.

    Args:
        request: Evaluation request
        evaluator: Function to call on cache miss
        policy_version: Current policy version

    Returns:
        Evaluation result (from cache or fresh)
    """
    cache = get_cache()

    # Try cache
    cached = cache.get(request)
    if cached is not None:
        return cached

    # Evaluate
    result = await evaluator(request)

    # Cache result
    cache.set(request, result, policy_version=policy_version)

    return result


def cached_evaluate_sync(
    request: Dict[str, Any],
    evaluator: Callable,
    policy_version: str = "",
) -> Dict[str, Any]:
    """Synchronous version of cached_evaluate."""
    cache = get_cache()

    cached = cache.get(request)
    if cached is not None:
        return cached

    result = evaluator(request)
    cache.set(request, result, policy_version=policy_version)

    return result
