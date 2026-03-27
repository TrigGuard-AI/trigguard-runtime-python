"""
TrigGuard Server Tests

Unit and integration tests for the TrigGuard HTTP API.
"""

import pytest
import time
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock
from uuid import uuid4

# Skip all tests if FastAPI not available
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from server.models import (
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
    BatchEvaluateRequest,
    SignalModel,
)
from server.trigguard_server import create_app


@pytest.fixture
def mock_gate():
    """Mock the TrigGuard gate."""
    with patch("server.routes.gate") as mock:
        mock.policy_version = "test-policy-v1"
        
        # Default to ALLOW
        result = Mock()
        result.permit = True
        result.decision = Mock(value="allow")
        result.reason = "Test allowed"
        result.signals = []
        result.receipt = Mock(receipt_hash="test-hash-123")
        
        mock.check.return_value = result
        yield mock


@pytest.fixture
def mock_telemetry():
    """Mock telemetry."""
    with patch("server.routes.get_telemetry") as mock:
        telemetry = Mock()
        telemetry.gates_evaluated = Mock(value=100)
        telemetry.export.return_value = {"gates_evaluated": 100}
        mock.return_value = telemetry
        yield mock


@pytest.fixture
def mock_policy():
    """Mock policy registry."""
    with patch("server.routes.get_policy_registry") as mock:
        policy = Mock()
        policy.version = "test-policy-v1"
        policy.is_external_policy = False
        mock.return_value = policy
        yield mock


@pytest.fixture
def app(mock_gate, mock_telemetry, mock_policy):
    """Create test application with mocks."""
    # Also patch lifespan dependencies
    with patch("server.trigguard_server.get_telemetry", mock_telemetry):
        with patch("server.trigguard_server.get_policy_registry", mock_policy):
            with patch("server.trigguard_server.gate", mock_gate):
                return create_app(debug=True)


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestHealthEndpoints:
    """Test health and status endpoints."""
    
    def test_root_endpoint(self, client):
        """Test root returns service info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "TrigGuard Server"
        assert "version" in data
        assert "documentation" in data
    
    def test_health_check(self, client):
        """Test health endpoint returns status."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "policy_version" in data
        assert "uptime_seconds" in data
    
    def test_liveness_probe(self, client):
        """Test Kubernetes liveness probe."""
        response = client.get("/api/v1/live")
        assert response.status_code == 200
        assert response.json()["alive"] is True
    
    def test_readiness_probe(self, client):
        """Test Kubernetes readiness probe."""
        response = client.get("/api/v1/ready")
        assert response.status_code == 200
        assert response.json()["ready"] is True


class TestEvaluateEndpoint:
    """Test the main evaluate endpoint."""
    
    def test_evaluate_simple_allow(self, client, mock_gate):
        """Test basic evaluation that allows."""
        response = client.post(
            "/api/v1/evaluate",
            json={
                "surface": "read",
                "action": "get_user",
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["permit"] is True
        assert data["decision"] == "allow"
        assert data["surface"] == "read"
        assert "request_id" in data
        assert "latency_ms" in data
    
    def test_evaluate_with_signals(self, client, mock_gate):
        """Test evaluation with signal data."""
        response = client.post(
            "/api/v1/evaluate",
            json={
                "surface": "spend",
                "action": "transfer",
                "signals": [
                    {
                        "signal_type": "anomaly",
                        "severity": 0.8,
                        "description": "Unusual transfer amount",
                    }
                ],
            }
        )
        
        assert response.status_code == 200
        mock_gate.check.assert_called_once()
        call_args = mock_gate.check.call_args[0][0]
        assert len(call_args["signals"]) == 1
    
    def test_evaluate_with_context(self, client, mock_gate):
        """Test evaluation with context data."""
        response = client.post(
            "/api/v1/evaluate",
            json={
                "surface": "write",
                "action": "update_profile",
                "arguments": {"user_id": "123", "field": "email"},
                "context": {"session_id": "abc", "ip": "192.168.1.1"},
            }
        )
        
        assert response.status_code == 200
        call_args = mock_gate.check.call_args[0][0]
        assert call_args["arguments"]["user_id"] == "123"
        assert call_args["context"]["session_id"] == "abc"
    
    def test_evaluate_with_headers(self, client, mock_gate):
        """Test evaluation with request ID header."""
        response = client.post(
            "/api/v1/evaluate",
            json={"surface": "read", "action": "test"},
            headers={
                "X-Request-Id": "custom-request-123",
                "X-Tenant-Id": "tenant-abc",
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == "custom-request-123"
        
        # Tenant should be in context
        call_args = mock_gate.check.call_args[0][0]
        assert call_args["context"]["tenant_id"] == "tenant-abc"
    
    def test_evaluate_deny(self, client, mock_gate):
        """Test evaluation that denies."""
        result = Mock()
        result.permit = False
        result.decision = Mock(value="deny")
        result.reason = "Policy violation"
        result.signals = []
        result.receipt = Mock(receipt_hash="deny-hash")
        mock_gate.check.return_value = result
        
        response = client.post(
            "/api/v1/evaluate",
            json={"surface": "code_execution", "action": "run_script"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["permit"] is False
        assert data["decision"] == "deny"
    
    def test_evaluate_fail_closed(self, client, mock_gate):
        """Test fail-closed behavior on error."""
        mock_gate.check.side_effect = Exception("Unexpected error")
        
        response = client.post(
            "/api/v1/evaluate",
            json={"surface": "read", "action": "test"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["permit"] is False
        assert "FAIL_CLOSED" in data["reason"]
    
    def test_evaluate_returns_timing(self, client):
        """Test that response includes timing header."""
        response = client.post(
            "/api/v1/evaluate",
            json={"surface": "read", "action": "test"}
        )
        
        assert "X-Process-Time-Ms" in response.headers


class TestBatchEndpoint:
    """Test batch evaluation endpoint."""
    
    def test_batch_evaluate(self, client, mock_gate):
        """Test batch evaluation of multiple requests."""
        response = client.post(
            "/api/v1/evaluate/batch",
            json={
                "requests": [
                    {"surface": "read", "action": "get_user"},
                    {"surface": "write", "action": "update_profile"},
                    {"surface": "read", "action": "list_items"},
                ]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert len(data["results"]) == 3
        assert "total_latency_ms" in data
    
    def test_batch_counts(self, client, mock_gate):
        """Test batch returns correct counts."""
        # Make second call return deny
        allow_result = Mock()
        allow_result.permit = True
        allow_result.decision = Mock(value="allow")
        allow_result.reason = "Test allowed"
        allow_result.signals = []
        allow_result.receipt = Mock(receipt_hash="test-hash")
        
        deny_result = Mock()
        deny_result.permit = False
        deny_result.decision = Mock(value="deny")
        deny_result.reason = "Test denied"
        deny_result.signals = []
        deny_result.receipt = Mock(receipt_hash="deny-hash")
        
        mock_gate.check.side_effect = [allow_result, deny_result, allow_result]
        
        response = client.post(
            "/api/v1/evaluate/batch",
            json={
                "requests": [
                    {"surface": "read"},
                    {"surface": "spend"},
                    {"surface": "read"},
                ]
            }
        )
        
        data = response.json()
        assert data["permitted"] == 2
        assert data["denied"] == 1


class TestPolicyEndpoint:
    """Test policy information endpoint."""
    
    def test_get_policy_info(self, client):
        """Test policy info returns configuration."""
        response = client.get("/api/v1/policy")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "is_external" in data
        assert "irreversible_surfaces" in data
        assert "spend" in data["irreversible_surfaces"]


class TestMetricsEndpoint:
    """Test metrics endpoint."""
    
    def test_get_metrics(self, client):
        """Test metrics export."""
        response = client.get("/api/v1/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "gates_evaluated" in data


class TestSurfacesEndpoint:
    """Test surfaces listing endpoint."""
    
    def test_list_surfaces(self, client):
        """Test listing available surfaces."""
        with patch("server.routes.TIER1_SURFACES", [Mock(value="spend")]):
            with patch("server.routes.TIER2_SURFACES", [Mock(value="write")]):
                with patch("server.routes.TIER3_SURFACES", [Mock(value="read")]):
                    response = client.get("/api/v1/surfaces")
        
        assert response.status_code == 200
        data = response.json()
        assert "tier1_irreversible" in data
        assert "tier2_medium" in data
        assert "tier3_low" in data


class TestValidation:
    """Test request validation."""
    
    def test_missing_surface(self, client):
        """Test validation error for missing surface."""
        response = client.post(
            "/api/v1/evaluate",
            json={"action": "test"}  # Missing surface
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_invalid_signal(self, client):
        """Test validation for invalid signal data."""
        response = client.post(
            "/api/v1/evaluate",
            json={
                "surface": "read",
                "signals": [
                    {"severity": "not_a_number"}  # Invalid
                ]
            }
        )
        
        assert response.status_code == 422


class TestModels:
    """Test Pydantic models directly."""
    
    def test_evaluate_request_defaults(self):
        """Test EvaluateRequest default values."""
        req = EvaluateRequest(surface="read")
        assert req.action == ""
        assert req.arguments == {}
        assert req.signals == []
        assert req.context == {}
    
    def test_signal_model_defaults(self):
        """Test SignalModel default values."""
        signal = SignalModel()
        assert signal.signal_type == "unknown"
        assert signal.severity == 0.0
        assert signal.confidence == 1.0
    
    def test_batch_request_limit(self):
        """Test batch request max limit."""
        # Should not raise for 100 or fewer
        requests = [{"surface": f"read_{i}"} for i in range(100)]
        batch = BatchEvaluateRequest(requests=requests)
        assert len(batch.requests) == 100


# Integration tests (require actual implementations)
class TestIntegration:
    """Integration tests with real components."""
    
    @pytest.mark.skip(reason="Requires full system setup")
    def test_full_evaluation_flow(self):
        """Test complete evaluation through actual gate."""
        pass
    
    @pytest.mark.skip(reason="Requires full system setup")
    def test_decision_replay_integration(self):
        """Test replay with actual decision engine."""
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
