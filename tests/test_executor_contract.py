"""
Tests for Executor Verification Contract

Tests for:
- Valid grant allows execution
- Invalid grant blocks execution
- Audit dict contains required fields
- Contract is stateless
- No network access required
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trigguard.executor.contract import (
    ExecutorVerificationContract,
    ExecutorDecision,
    ExecutorExecutionContext,
)
from trigguard.verification.verifier_sdk import TrigGuardVerifierSDK
from trigguard.grants.action_grant import ActionGrant, GrantConstraints
from trigguard.grants.issuer import ActionGrantIssuer
from trigguard.protocol.decision_contracts import (
    Decision,
    ExecutionSurface,
    ExecutionRequest,
    SignalFrame,
)
from trigguard.protocol.decision_receipt import generate_receipt

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def hmac_secret():
    """Shared HMAC secret."""
    return b"executor-contract-test-secret"


@pytest.fixture
def issuer(hmac_secret):
    """Create issuer."""
    return ActionGrantIssuer(hmac_secret=hmac_secret, issuer_id="contract-issuer")


@pytest.fixture
def sdk(hmac_secret):
    """Create configured SDK."""
    sdk = TrigGuardVerifierSDK()
    sdk.load_hmac_secret("contract-issuer", hmac_secret)
    return sdk


@pytest.fixture
def contract(sdk):
    """Create verification contract."""
    return ExecutorVerificationContract(sdk)


@pytest.fixture
def sample_frame():
    """Create sample SignalFrame."""
    return SignalFrame(
        request_id=uuid4(),
        surface=ExecutionSurface.SPEND,
    )


@pytest.fixture
def sample_receipt(sample_frame):
    """Create sample PERMIT receipt."""
    return generate_receipt(
        frame=sample_frame,
        decision=Decision.PERMIT,
        reason=None,
        policy_version="v1.0.0",
    )


@pytest.fixture
def sample_request():
    """Create sample request."""
    return ExecutionRequest(
        request_id=uuid4(),
        action="transfer_money",
        surface=ExecutionSurface.SPEND,
    )


@pytest.fixture
def valid_grant(issuer, sample_receipt, sample_request):
    """Create valid grant."""
    return issuer.issue_grant(
        decision=Decision.PERMIT,
        receipt=sample_receipt,
        request=sample_request,
        constraints=GrantConstraints(max_amount=100.0),
        ttl_seconds=300,
    )


@pytest.fixture
def invalid_grant(issuer, sample_receipt, sample_request):
    """Create grant with wrong signature."""
    grant = issuer.issue_grant(
        decision=Decision.PERMIT,
        receipt=sample_receipt,
        request=sample_request,
    )
    # Tamper with signature
    grant.signature = "hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    return grant


# ============================================================================
# Test Classes
# ============================================================================


class TestVerifyBeforeExecute:
    """Tests for verify_before_execute."""

    def test_valid_grant_allows_execution(self, contract, valid_grant):
        """Valid grant produces allow decision."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
            execution_input={"amount": 50.0},
        )

        assert decision.allowed
        assert decision.grant_id == str(valid_grant.grant_id)

    def test_invalid_grant_blocks_execution(self, contract, invalid_grant):
        """Invalid grant produces deny decision."""
        decision = contract.verify_before_execute(
            invalid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert not decision.allowed
        assert "signature" in decision.reason.lower()

    def test_wrong_scope_blocks_execution(self, contract, valid_grant):
        """Wrong scope produces deny decision."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="CODE_EXECUTION",  # Wrong surface
            action="transfer_money",
        )

        assert not decision.allowed
        assert "surface" in decision.reason.lower()

    def test_constraint_violation_blocks_execution(self, contract, valid_grant):
        """Constraint violation produces deny decision."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
            execution_input={"amount": 500.0},  # Exceeds max_amount=100
        )

        assert not decision.allowed
        assert (
            "constraint" in decision.reason.lower()
            or "amount" in decision.reason.lower()
        )


class TestAuditDict:
    """Tests for audit dictionary."""

    def test_audit_dict_contains_grant_id(self, contract, valid_grant):
        """Audit dict contains grant_id."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        audit = decision.to_audit_dict()

        assert "grant_id" in audit
        assert audit["grant_id"] == str(valid_grant.grant_id)

    def test_audit_dict_contains_receipt_hash(self, contract, valid_grant):
        """Audit dict contains receipt_hash."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        audit = decision.to_audit_dict()

        assert "receipt_hash" in audit
        assert audit["receipt_hash"] == valid_grant.receipt_hash

    def test_audit_dict_contains_decision_hash(self, contract, valid_grant):
        """Audit dict contains decision_hash."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        audit = decision.to_audit_dict()

        assert "decision_hash" in audit
        assert audit["decision_hash"] == valid_grant.decision_hash

    def test_audit_dict_contains_verified_at(self, contract, valid_grant):
        """Audit dict contains verified_at timestamp."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        audit = decision.to_audit_dict()

        assert "verified_at" in audit
        assert audit["verified_at"] is not None

    def test_audit_dict_contains_issuer(self, contract, valid_grant):
        """Audit dict contains issuer."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        audit = decision.to_audit_dict()

        assert "issuer" in audit
        assert audit["issuer"] == "contract-issuer"


class TestExecutorDecision:
    """Tests for ExecutorDecision."""

    def test_allow_decision(self, valid_grant):
        """Can create allow decision."""
        decision = ExecutorDecision.allow(valid_grant, kid="test-key")

        assert decision.allowed
        assert decision.grant_id == str(valid_grant.grant_id)
        assert decision.receipt_hash == valid_grant.receipt_hash
        assert decision.decision_hash == valid_grant.decision_hash

    def test_deny_decision(self, valid_grant):
        """Can create deny decision."""
        decision = ExecutorDecision.deny(
            reason="Test denial",
            grant=valid_grant,
        )

        assert not decision.allowed
        assert decision.reason == "Test denial"
        assert decision.grant_id == str(valid_grant.grant_id)

    def test_deny_without_grant(self):
        """Can create deny decision without grant."""
        decision = ExecutorDecision.deny(reason="No grant provided")

        assert not decision.allowed
        assert decision.grant_id is None
        assert decision.receipt_hash is None


class TestExecutorExecutionContext:
    """Tests for ExecutorExecutionContext."""

    def test_create_context(self, valid_grant):
        """Can create execution context."""
        decision = ExecutorDecision.allow(valid_grant)

        context = ExecutorExecutionContext(
            surface="SPEND",
            action="transfer_money",
            resource="account_123",
            execution_input={"amount": 50},
            grant=valid_grant,
            decision=decision,
        )

        assert context.surface == "SPEND"
        assert context.action == "transfer_money"
        assert context.grant == valid_grant

    def test_context_audit_dict(self, valid_grant):
        """Context produces audit-safe dict."""
        decision = ExecutorDecision.allow(valid_grant)

        context = ExecutorExecutionContext(
            surface="SPEND",
            action="transfer_money",
            resource=None,
            execution_input={},
            grant=valid_grant,
            decision=decision,
        )

        audit = context.to_audit_dict()

        assert "surface" in audit
        assert "action" in audit
        assert "grant_id" in audit
        assert "decision" in audit


class TestBuildExecutionContext:
    """Tests for build_execution_context."""

    def test_build_context(self, contract, valid_grant):
        """Can build execution context."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        context = contract.build_execution_context(
            grant=valid_grant,
            decision=decision,
            surface="spend",
            action="transfer_money",
            execution_input={"amount": 50},
        )

        assert context.surface == "spend"
        assert context.action == "transfer_money"
        assert context.decision == decision


class TestContractStateless:
    """Tests confirming contract is stateless."""

    def test_contract_does_not_track_grants(self, contract, valid_grant):
        """Contract does not store grant state."""
        # Verify same grant twice
        decision1 = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        decision2 = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        # Both succeed - no "already used" tracking
        assert decision1.allowed
        assert decision2.allowed

    def test_contract_independent_of_previous_decisions(
        self, contract, valid_grant, invalid_grant
    ):
        """Decisions are independent."""
        # Fail first
        fail_decision = contract.verify_before_execute(
            invalid_grant,
            surface="spend",
            action="transfer_money",
        )

        # Success second - not affected by previous failure
        success_decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert not fail_decision.allowed
        assert success_decision.allowed


class TestContractToAuditDict:
    """Tests for contract.to_audit_dict."""

    def test_to_audit_dict(self, contract, valid_grant):
        """Contract produces audit dict."""
        decision = contract.verify_before_execute(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        audit = contract.to_audit_dict(
            grant=valid_grant,
            decision=decision,
            surface="spend",
            action="transfer_money",
        )

        assert audit["result"] == "allow"
        assert audit["grant_id"] == str(valid_grant.grant_id)
        assert audit["surface"] == "spend"
        assert audit["action"] == "transfer_money"


class TestNoNetworkRequired:
    """Tests confirming no network access needed."""

    def test_contract_works_offline(self, hmac_secret):
        """Contract works completely offline."""
        # Setup - all local
        sdk = TrigGuardVerifierSDK()
        sdk.load_hmac_secret("offline-issuer", hmac_secret)
        contract = ExecutorVerificationContract(sdk)

        issuer = ActionGrantIssuer(hmac_secret=hmac_secret, issuer_id="offline-issuer")

        # Create grant locally
        frame = SignalFrame(request_id=uuid4(), surface=ExecutionSurface.SPEND)
        receipt = generate_receipt(
            frame=frame,
            decision=Decision.PERMIT,
            reason=None,
            policy_version="v1.0.0",
        )
        request = ExecutionRequest(
            request_id=uuid4(),
            action="offline_action",
            surface=ExecutionSurface.SPEND,
        )

        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=receipt,
            request=request,
        )

        # Verify offline
        decision = contract.verify_before_execute(
            grant,
            surface="spend",
            action="offline_action",
        )

        assert decision.allowed
        # No network calls made - architectural guarantee
