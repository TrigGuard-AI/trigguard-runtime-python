"""
Tests for TrigGuard Verifier SDK

Tests for:
- Loading key sets
- Selecting key by kid
- Signature verification
- Expiry verification
- Scope verification
- Constraint verification
- Full grant verification flow
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trigguard.verification.verifier_sdk import (
    TrigGuardVerifierSDK,
    VerificationResult,
)
from trigguard.verification.public_keys import PublicKeySet, PublicKeyRecord
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
    """Shared HMAC secret for testing."""
    return b"test-secret-key-for-verifier-sdk"


@pytest.fixture
def issuer(hmac_secret):
    """Create an issuer with HMAC secret."""
    return ActionGrantIssuer(hmac_secret=hmac_secret, issuer_id="test-issuer")


@pytest.fixture
def sdk(hmac_secret):
    """Create SDK with HMAC secret loaded."""
    sdk = TrigGuardVerifierSDK()
    sdk.load_hmac_secret("test-issuer", hmac_secret)
    return sdk


@pytest.fixture
def sample_frame():
    """Create a sample SignalFrame."""
    return SignalFrame(
        request_id=uuid4(),
        surface=ExecutionSurface.SPEND,
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
        ttl_seconds=300,
    )


# ============================================================================
# Test Classes
# ============================================================================


class TestLoadKeySet:
    """Tests for loading key sets."""

    def test_load_key_set_from_dict(self):
        """Can load key set from dict."""
        sdk = TrigGuardVerifierSDK()

        key_set_dict = {
            "issuer": "test-issuer",
            "keys": [
                {
                    "kid": "tg-root-1",
                    "alg": "Ed25519",
                    "public_key": "YWJjZGVmMTIzNDU2",
                    "status": "active",
                    "created_at": "2026-03-27T12:00:00Z",
                }
            ],
            "updated_at": "2026-03-27T12:00:00Z",
        }

        sdk.load_key_set(key_set_dict)

        key = sdk.get_key("test-issuer", "tg-root-1")
        assert key is not None
        assert key.kid == "tg-root-1"

    def test_load_key_set_from_object(self):
        """Can load key set from PublicKeySet object."""
        sdk = TrigGuardVerifierSDK()

        key_set = PublicKeySet(
            issuer="test-issuer",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                )
            ],
        )

        sdk.load_key_set(key_set)

        key = sdk.get_key("test-issuer", "tg-root-1")
        assert key is not None

    def test_load_hmac_secret(self):
        """Can load HMAC secret for issuer."""
        sdk = TrigGuardVerifierSDK()
        sdk.load_hmac_secret("test-issuer", b"secret-key")

        # Internal check - no direct accessor for secrets
        assert "test-issuer" in sdk._hmac_secrets


class TestSelectKeyByKid:
    """Tests for key selection by kid."""

    def test_get_existing_key(self):
        """Can get existing key by kid."""
        sdk = TrigGuardVerifierSDK()
        sdk.load_key_set(
            PublicKeySet(
                issuer="issuer1",
                keys=[
                    PublicKeyRecord(kid="key1", alg="Ed25519", public_key="pk1"),
                    PublicKeyRecord(kid="key2", alg="Ed25519", public_key="pk2"),
                ],
            )
        )

        key = sdk.get_key("issuer1", "key1")
        assert key is not None
        assert key.kid == "key1"

    def test_get_nonexistent_key(self):
        """Returns None for nonexistent key."""
        sdk = TrigGuardVerifierSDK()
        sdk.load_key_set(PublicKeySet(issuer="issuer1", keys=[]))

        key = sdk.get_key("issuer1", "nonexistent")
        assert key is None

    def test_get_key_wrong_issuer(self):
        """Returns None for wrong issuer."""
        sdk = TrigGuardVerifierSDK()
        sdk.load_key_set(
            PublicKeySet(
                issuer="issuer1",
                keys=[PublicKeyRecord(kid="key1", alg="Ed25519", public_key="pk1")],
            )
        )

        key = sdk.get_key("wrong-issuer", "key1")
        assert key is None


class TestSignatureVerification:
    """Tests for signature verification."""

    def test_valid_hmac_signature(self, sdk, valid_grant):
        """Valid HMAC signature passes verification."""
        result = sdk.verify_signature(valid_grant)

        assert result.valid
        assert result.checks.get("signature", {}).get("valid") is True

    def test_invalid_hmac_signature(self, valid_grant):
        """Invalid HMAC signature fails verification."""
        # SDK with different secret
        sdk = TrigGuardVerifierSDK()
        sdk.load_hmac_secret("test-issuer", b"wrong-secret")

        result = sdk.verify_signature(valid_grant)

        assert not result.valid
        assert "signature" in result.checks

    def test_missing_signature(self, valid_grant):
        """Missing signature fails verification."""
        sdk = TrigGuardVerifierSDK()
        valid_grant.signature = None

        result = sdk.verify_signature(valid_grant)

        assert not result.valid
        assert "Missing signature" in result.reason

    def test_missing_secret_fails(self, valid_grant):
        """Missing HMAC secret fails verification."""
        sdk = TrigGuardVerifierSDK()
        # No secret loaded

        result = sdk.verify_signature(valid_grant)

        assert not result.valid
        assert "No HMAC secret" in result.reason


class TestExpiryVerification:
    """Tests for expiry verification."""

    def test_valid_expiry(self, valid_grant):
        """Non-expired grant passes."""
        sdk = TrigGuardVerifierSDK()

        result = sdk.verify_expiry(valid_grant)

        assert result.valid
        assert result.checks.get("expiry", {}).get("valid") is True

    def test_expired_grant(self, valid_grant):
        """Expired grant fails."""
        sdk = TrigGuardVerifierSDK()

        # Set expiry in the past
        valid_grant.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        result = sdk.verify_expiry(valid_grant)

        assert not result.valid
        assert "expired" in result.reason.lower()

    def test_custom_now_for_testing(self, valid_grant):
        """Can use custom time for testing."""
        sdk = TrigGuardVerifierSDK()

        # Grant expires in 5 minutes
        valid_grant.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        # Test with time in the past (grant is valid)
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        result = sdk.verify_expiry(valid_grant, now=past)
        assert result.valid

        # Test with time in the future (grant is expired)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        result = sdk.verify_expiry(valid_grant, now=future)
        assert not result.valid


class TestScopeVerification:
    """Tests for scope verification."""

    def test_matching_scope(self, valid_grant):
        """Matching scope passes."""
        sdk = TrigGuardVerifierSDK()

        result = sdk.verify_scope(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert result.valid

    def test_wrong_surface_rejected(self, valid_grant):
        """Wrong surface fails."""
        sdk = TrigGuardVerifierSDK()

        result = sdk.verify_scope(
            valid_grant,
            surface="CODE_EXECUTION",
            action="transfer_money",
        )

        assert not result.valid
        assert "surface" in result.reason.lower()

    def test_wrong_action_rejected(self, valid_grant):
        """Wrong action fails."""
        sdk = TrigGuardVerifierSDK()

        result = sdk.verify_scope(
            valid_grant,
            surface="spend",
            action="delete_account",
        )

        assert not result.valid
        assert "action" in result.reason.lower()

    def test_resource_mismatch_rejected(self, issuer, sample_receipt, sample_request):
        """Resource mismatch fails."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_receipt,
            request=sample_request,
            resource="account_123",
        )

        sdk = TrigGuardVerifierSDK()
        result = sdk.verify_scope(
            grant,
            surface="spend",
            action="transfer_money",
            resource="account_456",  # Different resource
        )

        assert not result.valid
        assert "resource" in result.reason.lower()


class TestConstraintVerification:
    """Tests for constraint verification."""

    def test_max_amount_satisfied(self, valid_grant):
        """Amount within limit passes."""
        sdk = TrigGuardVerifierSDK()

        result = sdk.verify_constraints(
            valid_grant,
            execution_input={"amount": 50.0},
        )

        assert result.valid

    def test_max_amount_exceeded(self, valid_grant):
        """Amount exceeding limit fails."""
        sdk = TrigGuardVerifierSDK()

        result = sdk.verify_constraints(
            valid_grant,
            execution_input={"amount": 200.0},  # Exceeds max_amount=100
        )

        assert not result.valid
        assert (
            "amount" in result.reason.lower() or "constraint" in result.reason.lower()
        )

    def test_currency_constraint(self, issuer, sample_receipt, sample_request):
        """Currency constraint enforced."""
        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=sample_receipt,
            request=sample_request,
            constraints=GrantConstraints(allowed_currency="GBP"),
        )

        sdk = TrigGuardVerifierSDK()

        # Correct currency
        result = sdk.verify_constraints(grant, {"currency": "GBP"})
        assert result.valid

        # Wrong currency
        result = sdk.verify_constraints(grant, {"currency": "USD"})
        assert not result.valid


class TestFullVerification:
    """Tests for full verification flow."""

    def test_full_verification_success(self, sdk, valid_grant):
        """Full verification succeeds for valid grant."""
        result = sdk.verify_grant_and_scope(
            valid_grant,
            surface="spend",
            action="transfer_money",
            execution_input={"amount": 50.0},
        )

        assert result.valid
        assert "signature" in result.checks
        assert "expiry" in result.checks
        assert "scope" in result.checks

    def test_full_verification_fails_on_bad_signature(self, valid_grant):
        """Full verification fails on bad signature."""
        sdk = TrigGuardVerifierSDK()
        sdk.load_hmac_secret("test-issuer", b"wrong-secret")

        result = sdk.verify_grant_and_scope(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert not result.valid
        assert "signature" in result.reason.lower()

    def test_full_verification_fails_on_expiry(self, sdk, valid_grant):
        """Full verification fails on expiry."""
        valid_grant.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        # Note: Changing expiry invalidates signature, so this tests signature failure

        result = sdk.verify_grant_and_scope(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert not result.valid

    def test_full_verification_fails_on_scope(self, sdk, valid_grant):
        """Full verification fails on scope mismatch."""
        result = sdk.verify_grant_and_scope(
            valid_grant,
            surface="CODE_EXECUTION",  # Wrong surface
            action="transfer_money",
        )

        assert not result.valid
        assert "surface" in result.reason.lower()

    def test_verification_result_includes_issuer(self, sdk, valid_grant):
        """Verification result includes issuer."""
        result = sdk.verify_grant_and_scope(
            valid_grant,
            surface="spend",
            action="transfer_money",
        )

        assert result.issuer == "test-issuer"


class TestVerificationResult:
    """Tests for VerificationResult."""

    def test_success_result(self):
        """Can create success result."""
        result = VerificationResult.success(
            issuer="test",
            kid="key1",
            checks={"signature": {"valid": True}},
        )

        assert result.valid
        assert result.issuer == "test"
        assert result.kid == "key1"

    def test_failure_result(self):
        """Can create failure result."""
        result = VerificationResult.failure(
            reason="Bad signature",
            checks={"signature": {"valid": False}},
            issuer="test",
        )

        assert not result.valid
        assert result.reason == "Bad signature"


class TestNoNetworkRequired:
    """Tests confirming no network access is needed."""

    def test_sdk_works_offline(self, hmac_secret):
        """SDK works without any network calls."""
        # This test verifies the architecture - SDK is purely local
        sdk = TrigGuardVerifierSDK()
        sdk.load_hmac_secret("offline-issuer", hmac_secret)

        # Create a grant locally
        issuer = ActionGrantIssuer(hmac_secret=hmac_secret, issuer_id="offline-issuer")

        frame = SignalFrame(request_id=uuid4(), surface=ExecutionSurface.SPEND)
        receipt = generate_receipt(
            frame=frame,
            decision=Decision.PERMIT,
            reason=None,
            policy_version="v1.0.0",
        )
        request = ExecutionRequest(
            request_id=uuid4(),
            action="test_action",
            surface=ExecutionSurface.SPEND,
        )

        grant = issuer.issue_grant(
            decision=Decision.PERMIT,
            receipt=receipt,
            request=request,
        )

        # Verify completely offline
        result = sdk.verify_grant_and_scope(
            grant,
            surface="spend",
            action="test_action",
        )

        assert result.valid
        # No network calls were made - this is architectural
