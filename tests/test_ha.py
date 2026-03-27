"""
TrigGuard High Availability Tests

Unit tests for HA patterns.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Tuple, Dict, Any

from trigguard.ha.cluster import (
    HAManager,
    HAConfig,
    NodeInfo,
    NodeState,
    LeaderState,
    LeaderElection,
    GracefulShutdown,
    HealthChecker,
    HealthCheck,
    HealthStatus,
    get_ha_manager,
    configure_ha_manager,
)


class TestNodeInfo:
    """Test NodeInfo class."""

    def test_local_creation(self):
        """Test creating local node info."""
        node = NodeInfo.local(node_id="test-node", port=8080)

        assert node.node_id == "test-node"
        assert node.port == 8080
        assert node.state == NodeState.STARTING

    def test_local_auto_id(self):
        """Test auto-generated node ID."""
        node = NodeInfo.local()

        assert node.node_id is not None
        assert len(node.node_id) > 0

    def test_to_dict(self):
        """Test serialization."""
        node = NodeInfo.local(node_id="test")
        data = node.to_dict()

        assert data["node_id"] == "test"
        assert "hostname" in data
        assert "state" in data


class TestHealthStatus:
    """Test HealthStatus class."""

    def test_to_dict(self):
        """Test status serialization."""
        status = HealthStatus(
            healthy=True,
            checks={"cache": True, "policy": True},
            details={"cache": {"size": 100}},
        )

        data = status.to_dict()

        assert data["healthy"] is True
        assert data["checks"]["cache"] is True


class MockHealthCheck(HealthCheck):
    """Mock health check for testing."""

    def __init__(self, name: str, healthy: bool = True):
        self._name = name
        self._healthy = healthy

    @property
    def name(self) -> str:
        return self._name

    async def check(self) -> Tuple[bool, Dict[str, Any]]:
        return self._healthy, {"mock": True}


class TestHealthChecker:
    """Test HealthChecker class."""

    @pytest.mark.asyncio
    async def test_no_checks(self):
        """Test with no checks registered."""
        checker = HealthChecker()
        status = await checker.run_checks()

        assert status.healthy is True
        assert len(status.checks) == 0

    @pytest.mark.asyncio
    async def test_all_healthy(self):
        """Test with all healthy checks."""
        checker = HealthChecker(
            [
                MockHealthCheck("check1", True),
                MockHealthCheck("check2", True),
            ]
        )

        status = await checker.run_checks()

        assert status.healthy is True
        assert all(status.checks.values())

    @pytest.mark.asyncio
    async def test_one_unhealthy(self):
        """Test with one unhealthy check."""
        checker = HealthChecker(
            [
                MockHealthCheck("check1", True),
                MockHealthCheck("check2", False),
            ]
        )

        status = await checker.run_checks()

        assert status.healthy is False
        assert status.checks["check1"] is True
        assert status.checks["check2"] is False

    @pytest.mark.asyncio
    async def test_check_exception(self):
        """Test handling check exception."""

        class FailingCheck(HealthCheck):
            @property
            def name(self):
                return "failing"

            async def check(self):
                raise Exception("Check failed")

        checker = HealthChecker([FailingCheck()])
        status = await checker.run_checks()

        assert status.healthy is False
        assert "error" in status.details["failing"]


class TestLeaderElection:
    """Test LeaderElection class."""

    @pytest.mark.asyncio
    async def test_initial_state(self):
        """Test initial election state."""
        election = LeaderElection(node_id="test-node")

        assert election.is_leader is False
        assert election._state == LeaderState.FOLLOWER

    @pytest.mark.asyncio
    async def test_become_leader(self):
        """Test becoming leader."""
        election = LeaderElection(
            node_id="test-node",
            election_timeout=0.1,
        )

        await election._try_become_leader()

        assert election.is_leader is True
        assert election.leader_id == "test-node"

    @pytest.mark.asyncio
    async def test_step_down(self):
        """Test stepping down from leadership."""
        election = LeaderElection(node_id="test-node")

        await election._try_become_leader()
        assert election.is_leader is True

        await election._step_down()
        assert election.is_leader is False

    @pytest.mark.asyncio
    async def test_on_become_leader_callback(self):
        """Test callback when becoming leader."""
        callback = Mock()
        election = LeaderElection(node_id="test-node")
        election.on_become_leader = callback

        await election._try_become_leader()

        callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_receive_heartbeat(self):
        """Test receiving heartbeat from other leader."""
        election = LeaderElection(node_id="test-node")

        election.receive_heartbeat("other-leader")

        assert election._leader_id == "other-leader"


class TestGracefulShutdown:
    """Test GracefulShutdown class."""

    def test_track_requests(self):
        """Test request tracking."""
        shutdown = GracefulShutdown()

        shutdown.start_request()
        assert shutdown.active_requests == 1

        shutdown.start_request()
        assert shutdown.active_requests == 2

        shutdown.end_request()
        assert shutdown.active_requests == 1

    @pytest.mark.asyncio
    async def test_initiate_shutdown(self):
        """Test initiating shutdown."""
        shutdown = GracefulShutdown(timeout_seconds=0.5)

        await shutdown.initiate_shutdown()

        assert shutdown.is_shutting_down is True

    @pytest.mark.asyncio
    async def test_drain_requests(self):
        """Test draining active requests."""
        shutdown = GracefulShutdown(timeout_seconds=1.0)

        shutdown.start_request()

        # Start shutdown in background
        task = asyncio.create_task(shutdown.initiate_shutdown())

        await asyncio.sleep(0.1)
        shutdown.end_request()

        await task

        assert shutdown.active_requests == 0

    @pytest.mark.asyncio
    async def test_shutdown_timeout(self):
        """Test shutdown timeout with stuck requests."""
        shutdown = GracefulShutdown(timeout_seconds=0.2, drain_connections=True)

        shutdown.start_request()

        # Don't end request - should timeout
        await shutdown.initiate_shutdown()

        assert shutdown.active_requests == 1  # Still active

    @pytest.mark.asyncio
    async def test_shutdown_handlers(self):
        """Test shutdown handlers are called."""
        shutdown = GracefulShutdown()

        handler_called = []
        shutdown.register_handler(lambda: handler_called.append(1))

        await shutdown.initiate_shutdown()

        assert len(handler_called) == 1


class TestHAManager:
    """Test HAManager class."""

    @pytest.fixture
    def config(self):
        """Create test config."""
        return HAConfig(
            node_id="test-node",
            health_check_interval_seconds=0.1,
            enable_leader_election=True,
            election_timeout_seconds=0.5,
        )

    @pytest.mark.asyncio
    async def test_start_stop(self, config):
        """Test starting and stopping HA manager."""
        ha = HAManager(config)

        await ha.start()
        assert ha._running is True
        assert ha.node_state == NodeState.HEALTHY

        await ha.stop()
        assert ha._running is False
        assert ha.node_state == NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_context_manager(self, config):
        """Test async context manager."""
        async with HAManager(config) as ha:
            assert ha._running is True

        assert ha._running is False

    @pytest.mark.asyncio
    async def test_get_health(self, config):
        """Test getting health status."""
        ha = HAManager(config)

        # Mock the health checks
        ha._health_checker = HealthChecker([MockHealthCheck("test", True)])

        status = await ha.get_health()

        assert status.healthy is True

    @pytest.mark.asyncio
    async def test_is_leader(self, config):
        """Test leader status."""
        ha = HAManager(config)

        await ha.start()

        # Should become leader quickly in single-node setup
        await asyncio.sleep(0.2)
        assert ha.is_leader is True

        await ha.stop()

    @pytest.mark.asyncio
    async def test_track_request(self, config):
        """Test request tracking context manager."""
        ha = HAManager(config)

        async with ha.track_request():
            assert ha._shutdown.active_requests == 1

        assert ha._shutdown.active_requests == 0

    def test_add_health_check(self, config):
        """Test adding health check."""
        ha = HAManager(config)
        check = MockHealthCheck("custom", True)

        ha.add_health_check(check)

        assert check in ha._health_checker._checks

    def test_register_shutdown_handler(self, config):
        """Test registering shutdown handler."""
        ha = HAManager(config)
        handler = Mock()

        ha.register_shutdown_handler(handler)

        assert handler in ha._shutdown._shutdown_handlers


class TestGlobalManager:
    """Test global HA manager functions."""

    def test_configure_ha_manager(self):
        """Test configuring global manager."""
        import ha.cluster as module

        module._ha_manager = None

        config = HAConfig(node_id="global-test")
        manager = configure_ha_manager(config)

        assert manager is not None
        assert manager.node_id == "global-test"

    def test_get_ha_manager(self):
        """Test getting global manager."""
        import ha.cluster as module

        module._ha_manager = None

        assert get_ha_manager() is None

        configure_ha_manager(HAConfig())

        assert get_ha_manager() is not None

    @pytest.mark.asyncio
    async def test_start_ha_manager(self):
        """Test starting global manager."""
        import ha.cluster as module

        module._ha_manager = None

        from trigguard.ha.cluster import start_ha_manager

        manager = await start_ha_manager(
            HAConfig(
                health_check_interval_seconds=0.1,
            )
        )

        try:
            assert manager._running is True
        finally:
            await manager.stop()


class TestHAConfig:
    """Test HAConfig defaults."""

    def test_default_config(self):
        """Test default configuration values."""
        config = HAConfig()

        assert config.health_check_interval_seconds == 5.0
        assert config.enable_leader_election is True
        assert config.shutdown_timeout_seconds == 30.0
        assert config.drain_connections is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
