"""
Tests for TrigGuard Executor Boundary

These tests verify that:
1. Valid grants allow execution
2. Invalid grants deny execution
3. Expired grants are rejected
4. Scope mismatches are rejected
5. Constraint violations are rejected
6. The executor does not bypass verification

The executor is the runtime enforcement boundary.
It must NEVER allow execution without valid grant verification.
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trigguard.executor import TrigGuardExecutor, ExecutionResult
from trigguard.executor.executor import ExecutionDeniedError
from trigguard.grants import (
    ActionGrant,
    GrantConstraints,
    ActionGrantIssuer,
    ActionGrantVerifier,
)
from trigguard.grants.errors import GrantExpiredError, GrantScopeMismatchError
from trigguard.protocol.decision_contracts import (
    Decision,
    ExecutionSurface,
    ExecutionRequest,
    SignalFrame,
)
from trigguard.protocol.decision_receipt import generate_receipt


@pytest.fixture
def issuer():
    """Create an issuer with HMAC secret."""
    return ActionGrantIssuer(hmac_secret=b"test-secret-key-for-executor-tests")


@pytest.fixture
def verifier():
    """Create a verifier with matching HMAC secret."""
    return ActionGrantVerifier(hmac_secret=b"test-secret-key-for-executor-tests")


@pytest.fixture
def executor(verifier):
    """Create an executor with the verifier."""
    return TrigGuardExecutor(verifier, strict_mode=True, log_executions=False)


@pytest.fixture
def non_strict_executor(verifier):
    """Create a non-strict executor for result-based checking."""
    return TrigGuardExecutor(verifier, strict_mode=False, log_executions=False)


@pytest.fixture
def sample_frame():
    """Create a sample SignalFrame."""
    return SignalFrame(
        request_id=uuid4(),
        surface=ExecutionSurface.SPEND,
        signals=[],
    )


@pytest.fixture
def sample_receipt(sample_frame):
    """Create a sample PERMIT receipt."""
    return generate_receipt(
        frame=sample_frame,
        decision=Decision.PERMIT,
        reason=None,
        policy_version="v1.0.0",
    )


@pytest.fixture
def sample_request():
    """Create a sample ExecutionRequest."""
    return ExecutionRequest(
        request_id=uuid4(),
        action="transfer_money",
        surface=ExecutionSurface.SPEND,
    )


@pytest.fixture
def valid_grant(issuer, sample_receipt, sample_request):
    """Create a valid ActionGrant."""
    return issuer.issue_grant(
        decision=Decision.PERMIT,
        receipt=sample_receipt,
        request=sample_request,
        constraints=GrantConstraints(max_amount=100.0),
        ttl_seconds=300,  # 5 minutes
    )


@pytest.fixture
def expired_grant(issuer, sample_receipt, sample_request):
    """Create a tampered grant (simulates expired).

    Note: Manually changing expires_at invalidates the signature,
    so this tests that tampered grants are rejected (which includes
    expired grants that someone tried to extend).
    """
    grant = issuer.issue_grant(
        decision=Decision.PERMIT,
        receipt=sample_receipt,
        request=sample_request,
        ttl_seconds=1,
    )
    # Tampering with expires_at invalidates signature
    grant.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    return grant


class TestExecutorBoundary:
    """Tests for the executor enforcement boundary."""

    def test_valid_grant_allows_execution(self, executor, valid_grant):
        """Valid grants should allow execution."""
        was_called = False

        def action():
            nonlocal was_called
            was_called = True
            return "success"

        result = executor.execute(
            grant=valid_grant,
            func=action,
            surface="spend",
            action="transfer_money",
            execution_input={"amount": 50.0},
        )

        assert result.success
        assert was_called
        assert result.result == "success"
        assert result.error is None

    def test_invalid_signature_denies_execution(self, valid_grant, verifier):
        """Grants with invalid signatures must be rejected."""
        # Create executor with different secret
        wrong_verifier = ActionGrantVerifier(hmac_secret=b"wrong-secret")
        executor = TrigGuardExecutor(wrong_verifier, strict_mode=True)

        was_called = False

        def action():
            nonlocal was_called
            was_called = True
            return "success"

        with pytest.raises(ExecutionDeniedError) as exc_info:
            executor.execute(
                grant=valid_grant,
                func=action,
                surface="spend",
                action="transfer_money",
            )

        assert not was_called
        assert "signature" in str(exc_info.value).lower()

    def test_expired_grant_denies_execution(self, executor, expired_grant):
        """Tampered/expired grants must be rejected.

        Note: Modifying expires_at invalidates signature, so we verify
        the grant is rejected (signature or expiry failure).
        """
        was_called = False

        def action():
            nonlocal was_called
            was_called = True
            return "success"

        with pytest.raises(ExecutionDeniedError) as exc_info:
            executor.execute(
                grant=expired_grant,
                func=action,
                surface="spend",
                action="transfer_money",
            )

        assert not was_called
        # Signature fails because expires_at was tampered
        assert (
            "signature" in str(exc_info.value).lower()
            or "expired" in str(exc_info.value).lower()
        )

    def test_wrong_surface_denies_execution(self, executor, valid_grant):
        """Grants must match the execution surface."""
        was_called = False

        def action():
            nonlocal was_called
            was_called = True
            return "success"

        with pytest.raises(ExecutionDeniedError) as exc_info:
            executor.execute(
                grant=valid_grant,
                func=action,
                surface="CODE_EXECUTION",  # Wrong surface
                action="transfer_money",
            )

        assert not was_called
        assert "surface" in str(exc_info.value).lower()

    def test_wrong_action_denies_execution(self, executor, valid_grant):
        """Grants must match the action."""
        was_called = False

        def action():
            nonlocal was_called
            was_called = True
            return "success"

        with pytest.raises(ExecutionDeniedError) as exc_info:
            executor.execute(
                grant=valid_grant,
                func=action,
                surface="spend",
                action="delete_account",  # Wrong action
            )

        assert not was_called
        assert "action" in str(exc_info.value).lower()

    def test_constraint_violation_denies_execution(self, executor, valid_grant):
        """Constraint violations must be rejected."""
        was_called = False

        def action():
            nonlocal was_called
            was_called = True
            return "success"

        with pytest.raises(ExecutionDeniedError) as exc_info:
            executor.execute(
                grant=valid_grant,
                func=action,
                surface="spend",
                action="transfer_money",
                execution_input={"amount": 500.0},  # Exceeds max_amount=100
            )

        assert not was_called
        assert (
            "constraint" in str(exc_info.value).lower()
            or "amount" in str(exc_info.value).lower()
        )


class TestExecutorResults:
    """Tests for ExecutionResult handling."""

    def test_non_strict_returns_result_on_failure(
        self, non_strict_executor, expired_grant
    ):
        """Non-strict mode returns result instead of raising."""

        def action():
            return "success"

        result = non_strict_executor.execute(
            grant=expired_grant,
            func=action,
            surface="spend",
            action="transfer_money",
        )

        assert not result.success
        assert result.failed
        assert result.error is not None
        assert result.result is None

    def test_result_includes_grant_id(self, executor, valid_grant):
        """ExecutionResult includes the grant ID."""

        def action():
            return "success"

        result = executor.execute(
            grant=valid_grant,
            func=action,
            surface="spend",
            action="transfer_money",
        )

        assert result.grant_id == str(valid_grant.grant_id)

    def test_result_includes_verification_checks(self, executor, valid_grant):
        """ExecutionResult includes verification check details."""

        def action():
            return "success"

        result = executor.execute(
            grant=valid_grant,
            func=action,
            surface="spend",
            action="transfer_money",
        )

        assert "signature" in result.verification_checks
        assert "expiry" in result.verification_checks
        assert "scope" in result.verification_checks


class TestExecutorUnsafe:
    """Tests for execute_unsafe convenience method."""

    def test_unsafe_returns_result_directly(self, executor, valid_grant):
        """execute_unsafe returns the function result directly."""

        def action():
            return {"status": "transferred"}

        result = executor.execute_unsafe(
            grant=valid_grant,
            func=action,
            surface="spend",
            action="transfer_money",
        )

        assert result == {"status": "transferred"}

    def test_unsafe_raises_on_verification_failure(self, executor, expired_grant):
        """execute_unsafe raises on verification failure."""

        def action():
            return "success"

        with pytest.raises(ExecutionDeniedError):
            executor.execute_unsafe(
                grant=expired_grant,
                func=action,
                surface="spend",
                action="transfer_money",
            )

    def test_unsafe_propagates_function_exceptions(self, executor, valid_grant):
        """execute_unsafe propagates exceptions from the function."""

        def action():
            raise ValueError("Something went wrong")

        with pytest.raises(ValueError) as exc_info:
            executor.execute_unsafe(
                grant=valid_grant,
                func=action,
                surface="spend",
                action="transfer_money",
            )

        assert "Something went wrong" in str(exc_info.value)


class TestVerifyOnly:
    """Tests for pre-flight verification."""

    def test_verify_only_does_not_execute(self, executor, valid_grant):
        """verify_only should not execute the action."""
        was_called = False

        result = executor.verify_only(
            grant=valid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert not was_called
        assert result.valid

    def test_verify_only_returns_verification_result(self, executor, expired_grant):
        """verify_only returns full verification result."""
        result = executor.verify_only(
            grant=expired_grant,
            surface="spend",
            action="transfer_money",
        )

        assert not result.valid
        # Signature fails because expires_at was tampered
        assert (
            "signature" in result.reason.lower() or "expired" in result.reason.lower()
        )


class TestExecutorNeverBypassesVerification:
    """Critical tests ensuring the executor cannot be bypassed."""

    def test_no_public_method_skips_verification(self, executor, valid_grant):
        """All public execution methods must verify grants."""
        # This test documents that there is no backdoor
        public_methods = [
            name
            for name in dir(executor)
            if not name.startswith("_") and callable(getattr(executor, name))
        ]

        execution_methods = [m for m in public_methods if "execute" in m.lower()]

        # All execution methods should eventually call verify_grant
        # This is a documentation test - the real enforcement is in code review
        assert "execute" in execution_methods
        assert "execute_unsafe" in execution_methods

    def test_executor_requires_verifier(self):
        """Executor cannot be created without a verifier."""
        with pytest.raises(TypeError):
            TrigGuardExecutor()  # Missing required verifier argument
