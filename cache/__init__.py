"""
TrigGuard Cache Module

Caching layer for decision results.
"""

from cache.decision_cache import (
    DecisionCache,
    DecisionCacheConfig,
    CacheStats,
    CacheStrategy,
    InMemoryCache,
    get_cache,
    configure_cache,
    cached_evaluate,
    cached_evaluate_sync,
)

__all__ = [
    "DecisionCache",
    "DecisionCacheConfig",
    "CacheStats",
    "CacheStrategy",
    "InMemoryCache",
    "get_cache",
    "configure_cache",
    "cached_evaluate",
    "cached_evaluate_sync",
]
