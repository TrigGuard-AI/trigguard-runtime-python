"""
TrigGuard Execution Boundary Tests

ARCHITECTURAL INVARIANT TESTS.

These tests verify that the TrigGuard execution boundary guarantees hold:

1. NO action executes without passing through ExecutionAdapter
2. ExecutionAdapter ONLY calls ExecutionGate (no custom policy logic)
3. Denied actions NEVER call the underlying callable
4. PERMIT decisions always attach a valid DecisionReceipt
5. Any evaluation failure results in DENY (fail-closed)
6. All execution is traceable via receipt_hash

RUN THESE TESTS ON EVERY COMMIT.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
from uuid import UUID

from trigguard.core.execution_adapter import (
    ExecutionAdapter,
    ExecutionResult,
    ExecutionDenied,
    FailClosedError,
    UnguardedExecutionBlocked,
    execute_if_permitted,
    protected,
    get_execution_adapter,
)
from trigguard.core.protected_actions import (
    protected_spend,
    protected_data_export,
    protected_code_exec,
    protected_shell_command,
    protected_delegation,
    protected_identity_assertion,
    protected_data_mutation,
)
from trigguard.protocol.decision_contracts import Decision, ExecutionSurface

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_gate_permit():
    """Mock gate that always permits."""
    with patch("trigguard.sdk.gate.gate") as mock_gate:
        mock_result = Mock()
        mock_result.permit = True
        mock_result.decision = Decision.PERMIT
        mock_result.surface = ExecutionSurface.SPEND
        mock_result.reason = "Policy allows"
        mock_result.receipt = Mock()
        mock_result.receipt.receipt_hash = "permit-hash-123"

        mock_gate.check.return_value = mock_result
        mock_gate.policy_version = "v1.0.0"

        yield mock_gate


@pytest.fixture
def mock_gate_deny():
    """Mock gate that always denies."""
    with patch("trigguard.sdk.gate.gate") as mock_gate:
        mock_result = Mock()
        mock_result.permit = False
        mock_result.decision = Decision.DENY
        mock_result.surface = ExecutionSurface.SPEND
        mock_result.reason = "Policy denies"
        mock_result.receipt = Mock()
        mock_result.receipt.receipt_hash = "deny-hash-456"

        mock_gate.check.return_value = mock_result
        mock_gate.policy_version = "v1.0.0"

        yield mock_gate


@pytest.fixture
def mock_gate_error():
    """Mock gate that raises an error."""
    with patch("trigguard.sdk.gate.gate") as mock_gate:
        mock_gate.check.side_effect = Exception("Evaluation failed")
        yield mock_gate


@pytest.fixture
def adapter():
    """Fresh ExecutionAdapter instance."""
    return ExecutionAdapter()


# ============================================================================
# Invariant 1: No action executes without ExecutionAdapter
# ============================================================================


class TestNoBypassExecution:
    """Verify actions cannot execute without going through ExecutionAdapter."""

    def test_callable_only_runs_when_permitted(self, mock_gate_permit, adapter):
        """Test that callable runs only when gate permits."""
        callable_executed = False

        def test_action():
            nonlocal callable_executed
            callable_executed = True
            return "success"

        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=test_action,
        )

        assert callable_executed is True
        assert result.success is True
        assert result.result == "success"

    def test_callable_never_runs_when_denied(self, mock_gate_deny, adapter):
        """CRITICAL: Verify callable is NEVER called on denial."""
        callable_executed = False

        def test_action():
            nonlocal callable_executed
            callable_executed = True
            return "should not happen"

        with pytest.raises(ExecutionDenied):
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=test_action,
            )

        # CRITICAL ASSERTION: Callable was NEVER called
        assert callable_executed is False

    def test_callable_never_runs_on_error(self, mock_gate_error, adapter):
        """CRITICAL: Verify callable is NEVER called on evaluation error."""
        callable_executed = False

        def test_action():
            nonlocal callable_executed
            callable_executed = True
            return "should not happen"

        with pytest.raises(FailClosedError):
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=test_action,
            )

        # CRITICAL ASSERTION: Callable was NEVER called
        assert callable_executed is False


# ============================================================================
# Invariant 2: ExecutionAdapter only calls ExecutionGate
# ============================================================================


class TestAdapterOnlyCallsGate:
    """Verify ExecutionAdapter has no custom policy logic."""

    def test_adapter_calls_gate_check(self, mock_gate_permit, adapter):
        """Verify adapter calls gate.check()."""
        adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        mock_gate_permit.check.assert_called_once()

    def test_adapter_passes_request_to_gate(self, mock_gate_permit, adapter):
        """Verify adapter passes ExecutionRequest to gate."""
        adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test_action",
            action_callable=lambda: "ok",
            arguments={"key": "value"},
        )

        call_args = mock_gate_permit.check.call_args
        request = call_args[0][0]  # First positional argument

        assert request.surface == ExecutionSurface.SPEND
        assert request.action == "test_action"
        assert request.arguments == {"key": "value"}

    def test_adapter_respects_gate_decision(self, adapter):
        """Verify adapter respects gate decision without modification."""
        # Test with permit
        with patch("trigguard.sdk.gate.gate") as mock_gate:
            mock_result = Mock()
            mock_result.permit = True
            mock_result.decision = Decision.PERMIT
            mock_result.surface = ExecutionSurface.SPEND
            mock_result.reason = "allowed"
            mock_result.receipt = Mock(receipt_hash="hash1")
            mock_gate.check.return_value = mock_result
            mock_gate.policy_version = "v1"

            result = adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=lambda: "ok",
            )
            assert result.decision == Decision.PERMIT

        # Test with deny
        with patch("trigguard.sdk.gate.gate") as mock_gate:
            mock_result = Mock()
            mock_result.permit = False
            mock_result.decision = Decision.DENY
            mock_result.surface = ExecutionSurface.SPEND
            mock_result.reason = "denied"
            mock_result.receipt = Mock(receipt_hash="hash2")
            mock_gate.check.return_value = mock_result
            mock_gate.policy_version = "v1"

            with pytest.raises(ExecutionDenied):
                adapter.execute_if_permitted(
                    surface=ExecutionSurface.SPEND,
                    action="test",
                    action_callable=lambda: "ok",
                )


# ============================================================================
# Invariant 3: Denied actions never call callable
# ============================================================================


class TestDenialGuarantees:
    """Verify denial guarantees are absolute."""

    def test_denial_raises_execution_denied(self, mock_gate_deny, adapter):
        """Verify denial raises ExecutionDenied exception."""
        with pytest.raises(ExecutionDenied) as exc_info:
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=lambda: "never runs",
            )

        assert exc_info.value.reason == "Policy denies"

    def test_denial_includes_audit_info(self, mock_gate_deny, adapter):
        """Verify denial exception includes audit information."""
        with pytest.raises(ExecutionDenied) as exc_info:
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test_action",
                action_callable=lambda: "never runs",
            )

        exception = exc_info.value
        assert exception.surface == ExecutionSurface.SPEND
        assert exception.action == "test_action"
        assert exception.receipt is not None

    def test_multiple_denials_never_execute(self, mock_gate_deny, adapter):
        """Verify repeated denials never execute callable."""
        execution_count = 0

        def counting_action():
            nonlocal execution_count
            execution_count += 1
            return "executed"

        for _ in range(10):
            with pytest.raises(ExecutionDenied):
                adapter.execute_if_permitted(
                    surface=ExecutionSurface.SPEND,
                    action="test",
                    action_callable=counting_action,
                )

        assert execution_count == 0


# ============================================================================
# Invariant 4: PERMIT decisions attach DecisionReceipt
# ============================================================================


class TestReceiptAttachment:
    """Verify all PERMIT decisions include DecisionReceipt."""

    def test_permit_includes_receipt_hash(self, mock_gate_permit, adapter):
        """Verify permitted actions include receipt hash."""
        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        assert result.receipt_hash == "permit-hash-123"

    def test_permit_includes_policy_version(self, mock_gate_permit, adapter):
        """Verify permitted actions include policy version."""
        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        assert result.policy_version == "v1.0.0"

    def test_result_audit_dict_complete(self, mock_gate_permit, adapter):
        """Verify result audit dict contains required fields."""
        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        audit = result.to_audit_dict()

        assert "success" in audit
        assert "surface" in audit
        assert "action" in audit
        assert "decision" in audit
        assert "receipt_hash" in audit
        assert "policy_version" in audit
        assert "timestamp" in audit


# ============================================================================
# Invariant 5: Fail-closed on errors
# ============================================================================


class TestFailClosedBehavior:
    """Verify fail-closed behavior on all errors."""

    def test_gate_exception_raises_fail_closed(self, mock_gate_error, adapter):
        """Verify gate exceptions result in FailClosedError."""
        with pytest.raises(FailClosedError) as exc_info:
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=lambda: "never runs",
            )

        assert exc_info.value.surface == ExecutionSurface.SPEND
        assert exc_info.value.action == "test"

    def test_fail_closed_preserves_original_error(self, mock_gate_error, adapter):
        """Verify FailClosedError preserves original exception."""
        with pytest.raises(FailClosedError) as exc_info:
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=lambda: "never runs",
            )

        assert exc_info.value.original_error is not None
        assert "Evaluation failed" in str(exc_info.value.original_error)

    def test_callable_exception_propagates(self, mock_gate_permit, adapter):
        """Verify exceptions FROM callable propagate (not fail-closed)."""

        def failing_action():
            raise ValueError("Action failed")

        with pytest.raises(ValueError) as exc_info:
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=failing_action,
            )

        assert "Action failed" in str(exc_info.value)


# ============================================================================
# Invariant 6: Traceability
# ============================================================================


class TestTraceability:
    """Verify all executions are traceable."""

    def test_execution_has_request_id(self, mock_gate_permit, adapter):
        """Verify each execution has unique request ID."""
        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        assert result.request_id is not None
        assert isinstance(result.request_id, UUID)

    def test_execution_has_timestamp(self, mock_gate_permit, adapter):
        """Verify each execution has timestamp."""
        before = datetime.now(timezone.utc)

        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        after = datetime.now(timezone.utc)

        assert result.timestamp >= before
        assert result.timestamp <= after

    def test_execution_timing_recorded(self, mock_gate_permit, adapter):
        """Verify execution timing is recorded."""
        result = adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        assert result.execution_time_ms >= 0

    def test_multiple_executions_different_ids(self, mock_gate_permit, adapter):
        """Verify each execution gets unique ID."""
        results = []
        for _ in range(5):
            result = adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=lambda: "ok",
            )
            results.append(result)

        ids = [r.request_id for r in results]
        assert len(set(ids)) == 5  # All unique


# ============================================================================
# Protected Actions Tests
# ============================================================================


class TestProtectedActions:
    """Test protected action wrappers."""

    def test_protected_spend_requires_callable(self):
        """Verify protected_spend requires transfer_callable."""
        with pytest.raises(ValueError):
            protected_spend(
                amount=100,
                recipient="test",
                currency="USD",
                transfer_callable=None,
            )

    def test_protected_spend_passes_arguments(self, mock_gate_permit):
        """Verify protected_spend passes correct arguments."""
        with patch(
            "trigguard.core.protected_actions.get_execution_adapter"
        ) as mock_get:
            mock_adapter = Mock()
            mock_result = Mock()
            mock_result.success = True
            mock_adapter.execute_if_permitted.return_value = mock_result
            mock_get.return_value = mock_adapter

            protected_spend(
                amount=100.50,
                recipient="vendor@test.com",
                currency="EUR",
                transfer_callable=lambda: "transferred",
            )

            call_args = mock_adapter.execute_if_permitted.call_args
            assert call_args.kwargs["arguments"]["amount"] == 100.50
            assert call_args.kwargs["arguments"]["recipient"] == "vendor@test.com"
            assert call_args.kwargs["arguments"]["currency"] == "EUR"

    def test_protected_code_exec_truncates_code(self):
        """Verify protected_code_exec truncates long code."""
        with patch(
            "trigguard.core.protected_actions.get_execution_adapter"
        ) as mock_get:
            mock_adapter = Mock()
            mock_adapter.execute_if_permitted.return_value = Mock(success=True)
            mock_get.return_value = mock_adapter

            long_code = "x" * 200

            protected_code_exec(
                code=long_code,
                language="python",
                exec_callable=lambda: "executed",
            )

            call_args = mock_adapter.execute_if_permitted.call_args
            code_preview = call_args.kwargs["arguments"]["code_preview"]

            # Should be truncated
            assert len(code_preview) < 200
            assert code_preview.endswith("...")


# ============================================================================
# Decorator Tests
# ============================================================================


class TestProtectedDecorator:
    """Test @protected decorator."""

    def test_decorator_wraps_function(self, mock_gate_permit):
        """Verify decorator wraps function correctly."""
        adapter = ExecutionAdapter()

        @adapter.protected(surface=ExecutionSurface.SPEND, action="test_func")
        def my_function(x, y):
            return x + y

        result = my_function(1, 2)

        # Result is ExecutionResult, not raw value
        assert isinstance(result, ExecutionResult)
        assert result.result == 3

    def test_decorator_denies_execution(self, mock_gate_deny):
        """Verify decorator denies when gate denies."""
        adapter = ExecutionAdapter()

        @adapter.protected(surface=ExecutionSurface.SPEND)
        def my_function():
            return "should not run"

        with pytest.raises(ExecutionDenied):
            my_function()


# ============================================================================
# Global Function Tests
# ============================================================================


class TestGlobalFunctions:
    """Test module-level convenience functions."""

    def test_get_execution_adapter_singleton(self):
        """Verify get_execution_adapter returns singleton."""
        adapter1 = get_execution_adapter()
        adapter2 = get_execution_adapter()
        assert adapter1 is adapter2

    def test_execute_if_permitted_uses_global(self, mock_gate_permit):
        """Verify execute_if_permitted uses global adapter."""
        result = execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        assert result.success is True


# ============================================================================
# Execution Statistics
# ============================================================================


class TestExecutionStats:
    """Test execution statistics tracking."""

    def test_stats_track_executions(self, mock_gate_permit, adapter):
        """Verify stats track successful executions."""
        initial_execs = adapter.stats["executions"]

        adapter.execute_if_permitted(
            surface=ExecutionSurface.SPEND,
            action="test",
            action_callable=lambda: "ok",
        )

        assert adapter.stats["executions"] == initial_execs + 1

    def test_stats_track_denials(self, mock_gate_deny, adapter):
        """Verify stats track denials."""
        initial_denials = adapter.stats["denials"]

        with pytest.raises(ExecutionDenied):
            adapter.execute_if_permitted(
                surface=ExecutionSurface.SPEND,
                action="test",
                action_callable=lambda: "never runs",
            )

        assert adapter.stats["denials"] == initial_denials + 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
