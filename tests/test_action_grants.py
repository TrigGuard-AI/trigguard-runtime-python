"""
Action Grants Tests

Tests for the Action Grant issuance and verification system.
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trigguard.grants import (
    ActionGrant,
    ActionGrantIssuer,
    ActionGrantVerifier,
    GrantConstraints,
    GrantVerificationResult,
    GrantIssuanceError,
    GrantExpiredError,
    GrantSignatureError,
    GrantScopeMismatchError,
    GrantConstraintViolationError,
)
from trigguard.protocol.decision_contracts import (
    Decision,
    DecisionReceipt,
    ExecutionSurface,
    ExecutionRequest,
    SignalFrame,
)
from trigguard.protocol.decision_receipt import generate_receipt

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_frame():
    """Create a sample SignalFrame."""
    return SignalFrame(
        request_id=uuid4(),
        surface=ExecutionSurface.SPEND,
    )


@pytest.fixture
def sample_permit_receipt(sample_frame):
    """Create a sample PERMIT receipt."""
    return generate_receipt(
        frame=sample_frame,
        decision=Decision.PERMIT,
        policy_version="v1.0.0",
    )


@pytest.fixture
def sample_deny_receipt(sample_frame):
    """Create a sample DENY receipt."""
    from trigguard.protocol.decision_contracts import DenyReason

    return generate_receipt(
        frame=sample_frame,
        decision=Decision.DENY,
        reason=DenyReason.POLICY_DENIAL,
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
def issuer():
    """Create an ActionGrantIssuer with HMAC for testing."""
    return ActionGrantIssuer(
        issuer_id="test-issuer",
        use_hmac=True,
        hmac_secret=b"test-secret-key",
    )


@pytest.fixture
def verifier():
    """Create an ActionGrantVerifier with HMAC for testing."""
    return ActionGrantVerifier(hmac_secret=b"test-secret-key")


# ============================================================================
# Issuance Tests
# ============================================================================


class TestGrantIssuance:
    """Tests for Action Grant issuance."""

    def test_permit_decision_can_issue_grant(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """PERMIT decisions can receive grants."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        assert grant is not None
        assert grant.grant_id is not None
        assert grant.signature is not None
        assert grant.surface == "spend"
        assert grant.action == "transfer_money"

    def test_deny_decision_cannot_issue_grant(
        self, issuer, sample_deny_receipt, sample_request
    ):
        """DENY decisions cannot receive grants."""
        with pytest.raises(GrantIssuanceError) as exc_info:
            issuer.issue_grant(
                decision=Decision.DENY,
                receipt=sample_deny_receipt,
                request=sample_request,
            )

        assert "deny" in str(exc_info.value).lower()
        assert "only permit" in str(exc_info.value).lower()

    def test_silence_decision_cannot_issue_grant(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """SILENCE decisions cannot receive grants."""
        with pytest.raises(GrantIssuanceError) as exc_info:
            issuer.issue_grant(
                decision=Decision.SILENCE,
                receipt=sample_permit_receipt,
                request=sample_request,
            )

        assert "silence" in str(exc_info.value).lower()

    def test_missing_receipt_cannot_issue_grant(self, issuer, sample_request):
        """Cannot issue grant without a receipt."""
        with pytest.raises(GrantIssuanceError) as exc_info:
            issuer.issue_grant(
                decision=Decision.PERMIT,
                receipt=None,
                request=sample_request,
            )

        assert "without a DecisionReceipt" in str(exc_info.value)

    def test_grant_binds_policy_version(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Grant includes the policy version from the receipt."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        assert grant.policy_version == sample_permit_receipt.policy_version

    def test_grant_binds_decision_hash(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Grant includes the decision hash from the receipt."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        assert grant.decision_hash == sample_permit_receipt.decision_hash

    def test_grant_binds_receipt_hash(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Grant includes the receipt hash from the receipt."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        assert grant.receipt_hash == sample_permit_receipt.receipt_hash

    def test_grant_has_expiry(self, issuer, sample_permit_receipt, sample_request):
        """Grant has correct expiry time."""
        ttl = 60  # 60 seconds
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            ttl_seconds=ttl,
        )

        # Expiry should be approximately ttl seconds in the future
        expected_expiry = grant.issued_at + timedelta(seconds=ttl)
        assert grant.expires_at == expected_expiry

    def test_grant_with_constraints(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Grant can include constraints."""
        constraints = GrantConstraints(
            max_amount=100.0,
            allowed_currency="GBP",
            one_time_use=True,
        )

        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            constraints=constraints,
        )

        assert grant.constraints.max_amount == 100.0
        assert grant.constraints.allowed_currency == "GBP"
        assert grant.constraints.one_time_use is True


# ============================================================================
# Signature Tests
# ============================================================================


class TestSignatureVerification:
    """Tests for signature verification."""

    def test_signature_verification_succeeds_for_untampered_grant(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Valid signature passes verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        result = verifier.verify_signature(grant)
        assert result is True

    def test_signature_verification_fails_if_payload_changes(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Tampered payload fails verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        # Tamper with the grant
        original_action = grant.action
        grant.action = "tampered_action"

        # Verification should fail
        result = verifier.verify_signature(grant)
        assert result is False

        # Restore for sanity check
        grant.action = original_action
        result = verifier.verify_signature(grant)
        assert result is True


# ============================================================================
# Expiry Tests
# ============================================================================


class TestExpiryVerification:
    """Tests for expiry verification."""

    def test_expired_grant_is_rejected(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Expired grants fail verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            ttl_seconds=1,
        )

        # Fast forward past expiry
        future = datetime.now(timezone.utc) + timedelta(seconds=10)

        with pytest.raises(GrantExpiredError):
            verifier.verify_not_expired(grant, now=future)

    def test_valid_grant_is_accepted(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Non-expired grants pass verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            ttl_seconds=300,
        )

        result = verifier.verify_not_expired(grant)
        assert result is True


# ============================================================================
# Scope Tests
# ============================================================================


class TestScopeVerification:
    """Tests for scope verification."""

    def test_wrong_surface_is_rejected(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Mismatched surface fails verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        with pytest.raises(GrantScopeMismatchError) as exc_info:
            verifier.verify_scope(
                grant, surface="CODE_EXECUTION", action="transfer_money"
            )

        assert "Surface mismatch" in str(exc_info.value)

    def test_wrong_action_is_rejected(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Mismatched action fails verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        with pytest.raises(GrantScopeMismatchError) as exc_info:
            verifier.verify_scope(grant, surface="spend", action="delete_account")

        assert "Action mismatch" in str(exc_info.value)

    def test_resource_mismatch_is_rejected(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Mismatched resource fails verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            resource="account_123",
        )

        with pytest.raises(GrantScopeMismatchError) as exc_info:
            verifier.verify_scope(
                grant,
                surface="spend",
                action="transfer_money",
                resource="account_999",
            )

        assert "Resource mismatch" in str(exc_info.value)

    def test_matching_scope_is_accepted(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Matching scope passes verification."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        result = verifier.verify_scope(grant, surface="spend", action="transfer_money")
        assert result is True


# ============================================================================
# Constraint Tests
# ============================================================================


class TestConstraintVerification:
    """Tests for constraint verification."""

    def test_max_amount_constraint_enforced(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """max_amount constraint is enforced."""
        constraints = GrantConstraints(max_amount=100.0)
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            constraints=constraints,
        )

        # Within limit should pass
        result = verifier.verify_constraints(grant, {"amount": 50.0})
        assert result is True

        # Exceeding limit should fail
        with pytest.raises(GrantConstraintViolationError) as exc_info:
            verifier.verify_constraints(grant, {"amount": 150.0})

        assert "exceeds max_amount" in str(exc_info.value)

    def test_allowed_currency_constraint_enforced(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """allowed_currency constraint is enforced."""
        constraints = GrantConstraints(allowed_currency="GBP")
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            constraints=constraints,
        )

        # Correct currency should pass
        result = verifier.verify_constraints(grant, {"currency": "GBP"})
        assert result is True

        # Wrong currency should fail
        with pytest.raises(GrantConstraintViolationError) as exc_info:
            verifier.verify_constraints(grant, {"currency": "USD"})

        assert "not allowed" in str(exc_info.value)


# ============================================================================
# Canonical Serialization Tests
# ============================================================================


class TestCanonicalSerialization:
    """Tests for canonical JSON serialization."""

    def test_canonical_serialization_is_deterministic(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Canonical JSON is deterministic."""
        grant1 = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        # Create second grant with same data
        grant2 = ActionGrant(
            grant_id=grant1.grant_id,
            issuer=grant1.issuer,
            issued_at=grant1.issued_at,
            expires_at=grant1.expires_at,
            subject=grant1.subject,
            surface=grant1.surface,
            action=grant1.action,
            resource=grant1.resource,
            constraints=grant1.constraints,
            policy_version=grant1.policy_version,
            decision_hash=grant1.decision_hash,
            receipt_hash=grant1.receipt_hash,
            metadata=grant1.metadata,
        )

        assert grant1.to_canonical_json() == grant2.to_canonical_json()

    def test_signature_not_in_canonical_payload(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Signature is not included in canonical payload."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        canonical = grant.to_canonical_json()
        assert "signature" not in canonical


# ============================================================================
# Full Verification Flow Tests
# ============================================================================


class TestFullVerificationFlow:
    """Tests for complete verification flow."""

    def test_offline_verification_works_without_network(
        self, issuer, verifier, sample_permit_receipt, sample_request
    ):
        """Verification works completely offline."""
        constraints = GrantConstraints(
            max_amount=100.0,
            allowed_currency="GBP",
        )

        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
            constraints=constraints,
        )

        # Full verification without any network calls
        result = verifier.verify_grant(
            grant,
            surface="spend",
            action="transfer_money",
            execution_input={"amount": 50.0, "currency": "GBP"},
        )

        assert result.valid is True
        assert "signature" in result.checks
        assert "expiry" in result.checks
        assert "scope" in result.checks
        assert "constraints" in result.checks

    def test_full_verification_fails_on_invalid_signature(
        self, issuer, sample_permit_receipt, sample_request
    ):
        """Full verification fails if signature is invalid."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        # Use wrong HMAC secret
        bad_verifier = ActionGrantVerifier(hmac_secret=b"wrong-secret")

        result = bad_verifier.verify_grant(
            grant, surface="spend", action="transfer_money"
        )

        assert result.valid is False
        assert (
            "signature" in result.reason.lower() or "invalid" in result.reason.lower()
        )


# ============================================================================
# ActionGrant Model Tests
# ============================================================================


class TestActionGrantModel:
    """Tests for ActionGrant data model."""

    def test_is_expired_property(self):
        """is_expired property works correctly."""
        now = datetime.now(timezone.utc)

        # Expired grant
        expired_grant = ActionGrant(
            grant_id=uuid4(),
            issuer="test",
            issued_at=now - timedelta(hours=1),
            expires_at=now - timedelta(minutes=30),
            subject=None,
            surface="SPEND",
            action="test",
            resource=None,
            constraints=GrantConstraints(),
            policy_version="v1.0.0",
            decision_hash="abc",
            receipt_hash="def",
        )
        assert expired_grant.is_expired is True

        # Valid grant
        valid_grant = ActionGrant(
            grant_id=uuid4(),
            issuer="test",
            issued_at=now,
            expires_at=now + timedelta(minutes=30),
            subject=None,
            surface="SPEND",
            action="test",
            resource=None,
            constraints=GrantConstraints(),
            policy_version="v1.0.0",
            decision_hash="abc",
            receipt_hash="def",
        )
        assert valid_grant.is_expired is False

    def test_from_dict_roundtrip(self, issuer, sample_permit_receipt, sample_request):
        """Grant can be serialized and deserialized."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_permit_receipt,
            request=sample_request,
        )

        # Roundtrip
        data = grant.to_dict()
        restored = ActionGrant.from_dict(data)

        assert restored.grant_id == grant.grant_id
        assert restored.surface == grant.surface
        assert restored.action == grant.action
        assert restored.signature == grant.signature
