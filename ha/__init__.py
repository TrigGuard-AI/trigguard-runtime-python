"""
TrigGuard High Availability Module

Production HA patterns.
"""

from ha.cluster import (
    HAManager,
    HAConfig,
    HAMiddleware,
    NodeInfo,
    NodeState,
    LeaderState,
    LeaderElection,
    GracefulShutdown,
    HealthChecker,
    HealthCheck,
    HealthStatus,
    PolicyHealthCheck,
    CacheHealthCheck,
    get_ha_manager,
    configure_ha_manager,
    start_ha_manager,
)

__all__ = [
    "HAManager",
    "HAConfig",
    "HAMiddleware",
    "NodeInfo",
    "NodeState",
    "LeaderState",
    "LeaderElection",
    "GracefulShutdown",
    "HealthChecker",
    "HealthCheck",
    "HealthStatus",
    "PolicyHealthCheck",
    "CacheHealthCheck",
    "get_ha_manager",
    "configure_ha_manager",
    "start_ha_manager",
]
