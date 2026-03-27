"""
TrigGuard High Availability

HA patterns for production deployments.

Features:
    - Leader election for singleton tasks
    - Health check endpoints
    - Graceful shutdown handling
    - Cluster membership awareness
    - Failover coordination

Usage:
    from trigguard.ha.cluster import HAManager, start_ha_manager

    ha = HAManager(node_id="node-1")

    async with ha:
        if ha.is_leader:
            # Run leader-only tasks
            ...
"""

import asyncio
import os
import signal
import socket
import time
import threading
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Set, Tuple
from datetime import datetime, timezone
from contextlib import asynccontextmanager

logger = logging.getLogger("trigguard.ha")


class NodeState(Enum):
    """Node lifecycle state."""

    STARTING = "starting"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DRAINING = "draining"
    STOPPED = "stopped"


class LeaderState(Enum):
    """Leader election state."""

    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


@dataclass
class NodeInfo:
    """Information about a cluster node."""

    node_id: str
    hostname: str
    address: str
    port: int
    state: NodeState = NodeState.STARTING
    last_heartbeat: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def local(cls, node_id: Optional[str] = None, port: int = 8000) -> "NodeInfo":
        """Create NodeInfo for local node."""
        hostname = socket.gethostname()
        return cls(
            node_id=node_id or f"{hostname}-{os.getpid()}",
            hostname=hostname,
            address=socket.gethostbyname(hostname),
            port=port,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "address": self.address,
            "port": self.port,
            "state": self.state.value,
            "last_heartbeat": self.last_heartbeat,
            "metadata": self.metadata,
        }


@dataclass
class HAConfig:
    """High availability configuration."""

    # Node identity
    node_id: Optional[str] = None
    port: int = 8000

    # Health check
    health_check_interval_seconds: float = 5.0
    health_check_timeout_seconds: float = 3.0
    unhealthy_threshold: int = 3

    # Leader election
    enable_leader_election: bool = True
    election_timeout_seconds: float = 10.0
    heartbeat_interval_seconds: float = 2.0

    # Graceful shutdown
    shutdown_timeout_seconds: float = 30.0
    drain_connections: bool = True

    # Callbacks
    on_become_leader: Optional[Callable[[], None]] = None
    on_lose_leadership: Optional[Callable[[], None]] = None
    on_shutdown: Optional[Callable[[], None]] = None


@dataclass
class HealthStatus:
    """Health check status."""

    healthy: bool
    checks: Dict[str, bool]
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "checks": self.checks,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class HealthCheck(ABC):
    """Abstract health check."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Check name."""
        pass

    @abstractmethod
    async def check(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform health check.

        Returns (is_healthy, details) tuple.
        """
        pass


class PolicyHealthCheck(HealthCheck):
    """Check if policy is loaded."""

    @property
    def name(self) -> str:
        return "policy"

    async def check(self) -> Tuple[bool, Dict[str, Any]]:
        try:
            from trigguard.policy.policy_registry import get_policy_registry

            registry = get_policy_registry()
            return True, {"version": registry.version}
        except Exception as e:
            return False, {"error": str(e)}


class CacheHealthCheck(HealthCheck):
    """Check if cache is healthy."""

    @property
    def name(self) -> str:
        return "cache"

    async def check(self) -> Tuple[bool, Dict[str, Any]]:
        try:
            from trigguard.cache.decision_cache import get_cache

            cache = get_cache()
            stats = cache.stats()
            return True, {"hit_rate": stats.hit_rate, "size": stats.size}
        except Exception as e:
            return False, {"error": str(e)}


class HealthChecker:
    """Manages health checks."""

    def __init__(self, checks: Optional[List[HealthCheck]] = None):
        self._checks = checks or []
        self._consecutive_failures = 0

    def add_check(self, check: HealthCheck) -> None:
        """Add a health check."""
        self._checks.append(check)

    async def run_checks(self) -> HealthStatus:
        """Run all health checks."""
        results = {}
        details = {}

        for check in self._checks:
            try:
                healthy, check_details = await check.check()
                results[check.name] = healthy
                details[check.name] = check_details
            except Exception as e:
                results[check.name] = False
                details[check.name] = {"error": str(e)}

        all_healthy = all(results.values()) if results else True

        if all_healthy:
            self._consecutive_failures = 0
        else:
            self._consecutive_failures += 1

        return HealthStatus(
            healthy=all_healthy,
            checks=results,
            details=details,
        )


class LeaderElection:
    """
    Simple leader election using heartbeats.

    For production, use etcd, Consul, or ZooKeeper.
    """

    def __init__(
        self,
        node_id: str,
        election_timeout: float = 10.0,
        heartbeat_interval: float = 2.0,
    ):
        self.node_id = node_id
        self.election_timeout = election_timeout
        self.heartbeat_interval = heartbeat_interval

        self._state = LeaderState.FOLLOWER
        self._leader_id: Optional[str] = None
        self._last_leader_heartbeat = 0.0
        self._running = False
        self._lock = asyncio.Lock()

        # Callbacks
        self.on_become_leader: Optional[Callable] = None
        self.on_lose_leadership: Optional[Callable] = None

    @property
    def is_leader(self) -> bool:
        """Check if this node is leader."""
        return self._state == LeaderState.LEADER

    @property
    def leader_id(self) -> Optional[str]:
        """Get current leader ID."""
        return self._leader_id if self._state != LeaderState.LEADER else self.node_id

    async def start(self) -> None:
        """Start election process."""
        self._running = True
        asyncio.create_task(self._election_loop())

    async def stop(self) -> None:
        """Stop election process."""
        self._running = False

        if self._state == LeaderState.LEADER:
            await self._step_down()

    async def _election_loop(self) -> None:
        """Background election loop."""
        while self._running:
            try:
                if self._state == LeaderState.FOLLOWER:
                    await self._check_leader_timeout()
                elif self._state == LeaderState.LEADER:
                    await self._send_heartbeat()

                await asyncio.sleep(self.heartbeat_interval)

            except Exception as e:
                logger.error(f"Election loop error: {e}")

    async def _check_leader_timeout(self) -> None:
        """Check if leader has timed out."""
        if self._leader_id is None:
            # No leader, try to become one
            await self._try_become_leader()
        elif time.time() - self._last_leader_heartbeat > self.election_timeout:
            # Leader timeout
            logger.warning(f"Leader {self._leader_id} timed out")
            self._leader_id = None
            await self._try_become_leader()

    async def _try_become_leader(self) -> None:
        """Attempt to become leader."""
        async with self._lock:
            # Simple approach: first to claim wins
            # In production, use consensus protocol
            self._state = LeaderState.LEADER
            self._leader_id = self.node_id

            logger.info(f"Node {self.node_id} became leader")

            if self.on_become_leader:
                try:
                    self.on_become_leader()
                except Exception as e:
                    logger.error(f"on_become_leader callback failed: {e}")

    async def _step_down(self) -> None:
        """Step down from leadership."""
        async with self._lock:
            if self._state == LeaderState.LEADER:
                self._state = LeaderState.FOLLOWER

                logger.info(f"Node {self.node_id} stepped down from leadership")

                if self.on_lose_leadership:
                    try:
                        self.on_lose_leadership()
                    except Exception as e:
                        logger.error(f"on_lose_leadership callback failed: {e}")

    async def _send_heartbeat(self) -> None:
        """Send leader heartbeat."""
        # In production, broadcast to all nodes
        pass

    def receive_heartbeat(self, leader_id: str) -> None:
        """Receive heartbeat from leader."""
        self._leader_id = leader_id
        self._last_leader_heartbeat = time.time()

        if self._state == LeaderState.LEADER and leader_id != self.node_id:
            # Another leader exists, step down
            asyncio.create_task(self._step_down())


class GracefulShutdown:
    """Handles graceful shutdown."""

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        drain_connections: bool = True,
    ):
        self.timeout = timeout_seconds
        self.drain_connections = drain_connections

        self._shutdown_event = asyncio.Event()
        self._active_requests = 0
        self._lock = threading.Lock()

        # Callbacks
        self.on_shutdown: Optional[Callable[[], None]] = None
        self._shutdown_handlers: List[Callable] = []

    def register_handler(self, handler: Callable) -> None:
        """Register shutdown handler."""
        self._shutdown_handlers.append(handler)

    def start_request(self) -> None:
        """Track request start."""
        with self._lock:
            self._active_requests += 1

    def end_request(self) -> None:
        """Track request end."""
        with self._lock:
            self._active_requests -= 1

    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._shutdown_event.is_set()

    @property
    def active_requests(self) -> int:
        """Get active request count."""
        return self._active_requests

    async def initiate_shutdown(self) -> None:
        """Begin graceful shutdown."""
        logger.info("Initiating graceful shutdown...")
        self._shutdown_event.set()

        # Call pre-shutdown handlers
        for handler in self._shutdown_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler()
                else:
                    handler()
            except Exception as e:
                logger.error(f"Shutdown handler failed: {e}")

        # Wait for active requests to complete
        if self.drain_connections:
            await self._drain_requests()

        # Final callback
        if self.on_shutdown:
            try:
                self.on_shutdown()
            except Exception as e:
                logger.error(f"on_shutdown callback failed: {e}")

        logger.info("Graceful shutdown complete")

    async def _drain_requests(self) -> None:
        """Wait for active requests to complete."""
        start = time.time()

        while self._active_requests > 0:
            if time.time() - start > self.timeout:
                logger.warning(
                    f"Shutdown timeout reached with {self._active_requests} "
                    f"active requests"
                )
                break

            logger.info(f"Waiting for {self._active_requests} requests to complete...")
            await asyncio.sleep(1)


class HAManager:
    """
    High availability manager.

    Coordinates health checks, leader election, and graceful shutdown.
    """

    def __init__(self, config: Optional[HAConfig] = None):
        self.config = config or HAConfig()

        # Node info
        self._node = NodeInfo.local(
            node_id=self.config.node_id,
            port=self.config.port,
        )

        # Health checking
        self._health_checker = HealthChecker()
        self._health_checker.add_check(PolicyHealthCheck())
        self._health_checker.add_check(CacheHealthCheck())

        # Leader election
        self._election: Optional[LeaderElection] = None
        if self.config.enable_leader_election:
            self._election = LeaderElection(
                node_id=self._node.node_id,
                election_timeout=self.config.election_timeout_seconds,
                heartbeat_interval=self.config.heartbeat_interval_seconds,
            )
            self._election.on_become_leader = self.config.on_become_leader
            self._election.on_lose_leadership = self.config.on_lose_leadership

        # Graceful shutdown
        self._shutdown = GracefulShutdown(
            timeout_seconds=self.config.shutdown_timeout_seconds,
            drain_connections=self.config.drain_connections,
        )
        self._shutdown.on_shutdown = self.config.on_shutdown

        # Background tasks
        self._running = False
        self._health_task: Optional[asyncio.Task] = None

    @property
    def node_id(self) -> str:
        """Get node ID."""
        return self._node.node_id

    @property
    def node_state(self) -> NodeState:
        """Get node state."""
        return self._node.state

    @property
    def is_leader(self) -> bool:
        """Check if this node is leader."""
        if self._election:
            return self._election.is_leader
        return True  # Single node = always leader

    @property
    def is_healthy(self) -> bool:
        """Check if node is healthy."""
        return self._node.state == NodeState.HEALTHY

    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._shutdown.is_shutting_down

    async def start(self) -> None:
        """Start HA manager."""
        logger.info(f"Starting HA manager for node {self.node_id}")

        self._running = True
        self._node.state = NodeState.STARTING

        # Start leader election
        if self._election:
            await self._election.start()

        # Start health check loop
        self._health_task = asyncio.create_task(self._health_loop())

        # Register signal handlers
        self._setup_signal_handlers()

        self._node.state = NodeState.HEALTHY
        logger.info(f"HA manager started for node {self.node_id}")

    async def stop(self) -> None:
        """Stop HA manager."""
        logger.info(f"Stopping HA manager for node {self.node_id}")

        self._running = False
        self._node.state = NodeState.DRAINING

        # Initiate graceful shutdown
        await self._shutdown.initiate_shutdown()

        # Stop election
        if self._election:
            await self._election.stop()

        # Stop health checks
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        self._node.state = NodeState.STOPPED
        logger.info(f"HA manager stopped for node {self.node_id}")

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda: asyncio.create_task(self._signal_handler(sig)),
                )
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

    async def _signal_handler(self, sig: signal.Signals) -> None:
        """Handle shutdown signal."""
        logger.info(f"Received signal {sig.name}")
        await self.stop()

    async def _health_loop(self) -> None:
        """Background health check loop."""
        consecutive_failures = 0

        while self._running:
            try:
                status = await self._health_checker.run_checks()

                if status.healthy:
                    consecutive_failures = 0
                    if self._node.state != NodeState.HEALTHY:
                        self._node.state = NodeState.HEALTHY
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= self.config.unhealthy_threshold:
                        self._node.state = NodeState.UNHEALTHY

                self._node.last_heartbeat = time.time()

            except Exception as e:
                logger.error(f"Health check failed: {e}")
                consecutive_failures += 1

            await asyncio.sleep(self.config.health_check_interval_seconds)

    async def get_health(self) -> HealthStatus:
        """Get current health status."""
        return await self._health_checker.run_checks()

    def add_health_check(self, check: HealthCheck) -> None:
        """Add a health check."""
        self._health_checker.add_check(check)

    def register_shutdown_handler(self, handler: Callable) -> None:
        """Register shutdown handler."""
        self._shutdown.register_handler(handler)

    def track_request_start(self) -> None:
        """Track request start for graceful shutdown."""
        self._shutdown.start_request()

    def track_request_end(self) -> None:
        """Track request end for graceful shutdown."""
        self._shutdown.end_request()

    @asynccontextmanager
    async def track_request(self):
        """Context manager for tracking requests."""
        self.track_request_start()
        try:
            yield
        finally:
            self.track_request_end()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()


# ============================================================================
# Global Manager
# ============================================================================

_ha_manager: Optional[HAManager] = None
_ha_lock = threading.Lock()


def get_ha_manager() -> Optional[HAManager]:
    """Get global HA manager."""
    return _ha_manager


def configure_ha_manager(config: HAConfig) -> HAManager:
    """Configure global HA manager."""
    global _ha_manager

    with _ha_lock:
        _ha_manager = HAManager(config)
        return _ha_manager


async def start_ha_manager(config: Optional[HAConfig] = None) -> HAManager:
    """Start global HA manager."""
    global _ha_manager

    with _ha_lock:
        _ha_manager = HAManager(config)

    await _ha_manager.start()
    return _ha_manager


# ============================================================================
# Middleware
# ============================================================================


class HAMiddleware:
    """
    HA middleware for FastAPI/Starlette.

    - Tracks active requests
    - Rejects requests during shutdown
    - Adds HA headers to responses
    """

    def __init__(self, app, ha_manager: HAManager):
        self.app = app
        self.ha = ha_manager

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Reject during shutdown
        if self.ha.is_shutting_down:
            from starlette.responses import JSONResponse

            response = JSONResponse(
                status_code=503,
                content={
                    "error": "service_unavailable",
                    "message": "Server is shutting down",
                },
                headers={"Retry-After": "30"},
            )
            await response(scope, receive, send)
            return

        # Track request
        async with self.ha.track_request():
            # Add headers
            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    headers[b"x-node-id"] = self.ha.node_id.encode()
                    headers[b"x-node-state"] = self.ha.node_state.value.encode()
                    if self.ha.is_leader:
                        headers[b"x-leader"] = b"true"
                    message["headers"] = list(headers.items())
                await send(message)

            await self.app(scope, receive, send_with_headers)
