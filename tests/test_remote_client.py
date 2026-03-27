"""
TrigGuard Remote Client Tests

Unit tests for the remote evaluation client.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from uuid import uuid4

from trigguard.sdk.remote_client import (
    TrigGuardClient,
    RemoteEvaluationResult,
    RemoteDecision,
    RemoteHealthStatus,
    ClientConfig,
    RetryConfig,
    remote_check,
    remote_guard,
)


@pytest.fixture
def mock_httpx():
    """Mock httpx for testing."""
    with patch("trigguard.sdk.remote_client.httpx") as mock:
        yield mock


@pytest.fixture
def client():
    """Create test client."""
    return TrigGuardClient(
        "http://localhost:8000",
        api_key="test-key",
        tenant_id="test-tenant",
    )


class TestRemoteEvaluationResult:
    """Test RemoteEvaluationResult class."""

    def test_from_response(self):
        """Test creating result from API response."""
        data = {
            "permit": True,
            "decision": "allow",
            "reason": "Policy allows read",
            "request_id": "req-123",
            "surface": "read",
            "receipt_hash": "hash-abc",
            "policy_version": "v1.0",
            "latency_ms": 15.5,
            "signal_count": 2,
        }

        result = RemoteEvaluationResult.from_response(data)

        assert result.permit is True
        assert result.decision == RemoteDecision.ALLOW
        assert result.reason == "Policy allows read"
        assert result.request_id == "req-123"
        assert result.surface == "read"
        assert result.receipt_hash == "hash-abc"
        assert result.latency_ms == 15.5

    def test_fail_closed(self):
        """Test fail-closed result creation."""
        result = RemoteEvaluationResult.fail_closed(
            "Connection timeout", surface="spend"
        )

        assert result.permit is False
        assert result.decision == RemoteDecision.ERROR
        assert "FAIL_CLOSED" in result.reason
        assert "Connection timeout" in result.reason
        assert result.surface == "spend"


class TestClientConfig:
    """Test client configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ClientConfig(base_url="http://test:8000")

        assert config.timeout_seconds == 5.0
        assert config.fail_closed is True
        assert config.api_key is None

    def test_retry_config(self):
        """Test retry configuration."""
        retry = RetryConfig()

        assert retry.max_retries == 3
        assert retry.base_delay_ms == 100.0
        assert retry.exponential_base == 2.0


class TestTrigGuardClient:
    """Test TrigGuard remote client."""

    def test_init(self):
        """Test client initialization."""
        client = TrigGuardClient(
            "http://localhost:8000/",  # With trailing slash
            api_key="key123",
            tenant_id="tenant-abc",
            timeout=10.0,
            max_retries=5,
        )

        assert client.config.base_url == "http://localhost:8000"
        assert client.config.api_key == "key123"
        assert client.config.tenant_id == "tenant-abc"
        assert client.config.timeout_seconds == 10.0
        assert client.config.retry_config.max_retries == 5

    def test_headers_with_auth(self):
        """Test headers include auth when configured."""
        client = TrigGuardClient(
            "http://test:8000",
            api_key="secret-key",
            tenant_id="my-tenant",
        )

        headers = client._headers

        assert headers["Authorization"] == "Bearer secret-key"
        assert headers["X-Tenant-Id"] == "my-tenant"
        assert headers["Content-Type"] == "application/json"

    def test_headers_without_auth(self):
        """Test headers without auth."""
        client = TrigGuardClient("http://test:8000")
        headers = client._headers

        assert "Authorization" not in headers
        assert "X-Tenant-Id" not in headers


class TestCircuitBreaker:
    """Test circuit breaker functionality."""

    def test_circuit_initially_closed(self):
        """Test circuit starts closed."""
        client = TrigGuardClient("http://test:8000")
        assert client._check_circuit() is True
        assert client._circuit_open is False

    def test_circuit_opens_after_failures(self):
        """Test circuit opens after threshold failures."""
        client = TrigGuardClient("http://test:8000")
        client._circuit_threshold = 3

        for _ in range(3):
            client._record_failure()

        assert client._circuit_open is True
        assert client._check_circuit() is False

    def test_success_resets_failures(self):
        """Test success resets failure count."""
        client = TrigGuardClient("http://test:8000")

        client._record_failure()
        client._record_failure()
        assert client._consecutive_failures == 2

        client._record_success()
        assert client._consecutive_failures == 0


class TestAsyncEvaluate:
    """Test async evaluation methods."""

    @pytest.mark.asyncio
    async def test_evaluate_success(self):
        """Test successful evaluation."""
        client = TrigGuardClient("http://test:8000")

        # Mock the request method
        client._request_with_retry = AsyncMock(
            return_value={
                "permit": True,
                "decision": "allow",
                "reason": "Test allowed",
                "request_id": "req-123",
                "surface": "read",
                "receipt_hash": "hash-123",
                "policy_version": "v1",
                "latency_ms": 5.0,
            }
        )

        result = await client.evaluate("read", "get_data")

        assert result.permit is True
        assert result.decision == RemoteDecision.ALLOW
        client._request_with_retry.assert_called_once()

    @pytest.mark.asyncio
    async def test_evaluate_fail_closed(self):
        """Test fail-closed on error."""
        client = TrigGuardClient("http://test:8000", fail_closed=True)

        client._request_with_retry = AsyncMock(
            side_effect=ConnectionError("Network error")
        )

        result = await client.evaluate("spend", "transfer")

        assert result.permit is False
        assert result.decision == RemoteDecision.ERROR
        assert "FAIL_CLOSED" in result.reason

    @pytest.mark.asyncio
    async def test_evaluate_batch(self):
        """Test batch evaluation."""
        client = TrigGuardClient("http://test:8000")

        client._request_with_retry = AsyncMock(
            return_value={
                "results": [
                    {"permit": True, "decision": "allow", "surface": "read"},
                    {"permit": False, "decision": "deny", "surface": "spend"},
                ],
                "total": 2,
                "permitted": 1,
                "denied": 1,
            }
        )

        results = await client.evaluate_batch(
            [
                {"surface": "read"},
                {"surface": "spend"},
            ]
        )

        assert len(results) == 2
        assert results[0].permit is True
        assert results[1].permit is False

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check."""
        client = TrigGuardClient("http://test:8000")

        client._request_with_retry = AsyncMock(
            return_value={
                "status": "healthy",
                "version": "0.1.0",
                "policy_version": "v1",
                "uptime_seconds": 3600,
                "gates_evaluated": 1000,
            }
        )

        health = await client.health()

        assert health.healthy is True
        assert health.version == "0.1.0"
        assert health.uptime_seconds == 3600

    @pytest.mark.asyncio
    async def test_ready_check(self):
        """Test readiness check."""
        client = TrigGuardClient("http://test:8000")

        client._request_with_retry = AsyncMock(return_value={"ready": True})

        ready = await client.ready()
        assert ready is True

    @pytest.mark.asyncio
    async def test_ready_returns_false_on_error(self):
        """Test ready returns False on error."""
        client = TrigGuardClient("http://test:8000")

        client._request_with_retry = AsyncMock(side_effect=Exception("Server down"))

        ready = await client.ready()
        assert ready is False


class TestContextManager:
    """Test async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as context manager."""
        async with TrigGuardClient("http://test:8000") as client:
            # Mock to avoid actual HTTP calls
            client._request_with_retry = AsyncMock(
                return_value={
                    "permit": True,
                    "decision": "allow",
                }
            )

            result = await client.evaluate("read")
            assert result.permit is True


class TestRemoteGuardDecorator:
    """Test remote_guard decorator."""

    @pytest.mark.asyncio
    async def test_guard_allows(self):
        """Test decorator allows when permitted."""
        client = TrigGuardClient("http://test:8000")
        client.evaluate = AsyncMock(
            return_value=RemoteEvaluationResult(
                permit=True,
                decision=RemoteDecision.ALLOW,
                reason="Allowed",
                request_id="req-1",
                surface="spend",
            )
        )

        @remote_guard(client, "spend", "transfer")
        async def transfer(amount: float):
            return f"Transferred {amount}"

        result = await transfer(amount=100)
        assert result == "Transferred 100"

    @pytest.mark.asyncio
    async def test_guard_denies(self):
        """Test decorator raises on deny."""
        client = TrigGuardClient("http://test:8000")
        client.evaluate = AsyncMock(
            return_value=RemoteEvaluationResult(
                permit=False,
                decision=RemoteDecision.DENY,
                reason="Amount too high",
                request_id="req-1",
                surface="spend",
                receipt_hash="deny-hash",
            )
        )

        @remote_guard(client, "spend", "transfer")
        async def transfer(amount: float):
            return f"Transferred {amount}"

        with pytest.raises(PermissionError) as exc:
            await transfer(amount=1000000)

        assert "Amount too high" in str(exc.value)
        assert "deny-hash" in str(exc.value)


class TestRemoteCheckFunction:
    """Test convenience remote_check function."""

    @pytest.mark.asyncio
    async def test_remote_check(self):
        """Test one-off remote check."""
        with patch("trigguard.sdk.remote_client.TrigGuardClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.evaluate = AsyncMock(
                return_value=RemoteEvaluationResult(
                    permit=True,
                    decision=RemoteDecision.ALLOW,
                    reason="OK",
                    request_id="test",
                    surface="read",
                )
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock()
            MockClient.return_value = mock_instance

            result = await remote_check(
                "http://test:8000",
                "read",
                "get_data",
            )

            assert result.permit is True


class TestSyncAPI:
    """Test synchronous API."""

    def test_check_sync(self):
        """Test synchronous check method."""
        client = TrigGuardClient("http://test:8000")

        # Mock evaluate
        async def mock_evaluate(*args, **kwargs):
            return RemoteEvaluationResult(
                permit=True,
                decision=RemoteDecision.ALLOW,
                reason="OK",
                request_id="test",
                surface="read",
            )

        with patch.object(client, "evaluate", mock_evaluate):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.run_until_complete = Mock(
                    return_value=RemoteEvaluationResult(
                        permit=True,
                        decision=RemoteDecision.ALLOW,
                        reason="OK",
                        request_id="test",
                        surface="read",
                    )
                )

                result = client.check("read")
                assert result.permit is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
