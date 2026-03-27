"""
Tests for @requires_grant decorator

Tests cover:
- Missing grant raises error
- Invalid grant raises error
- Valid grant allows execution
- Async decorator works
- Introspection functions
- Non-strict mode returns None
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trigguard.sdk.decorators import (
    requires_grant,
    requires_grant_async,
    GrantVerificationError,
    MissingGrantError,
    is_protected,
    get_protected_surface,
    get_protected_action,
)
from trigguard.grants.action_grant import ActionGrant, GrantConstraints
from trigguard.grants.issuer import ActionGrantIssuer
from trigguard.protocol.decision_contracts import (
    Decision,
    ExecutionSurface,
    ExecutionRequest,
    SignalFrame,
)
from trigguard.protocol.decision_receipt import generate_receipt
from trigguard.verification.verifier_sdk import TrigGuardVerifierSDK

# Shared HMAC secret for all tests
TEST_SECRET = b"test-secret-key-for-decorator-tests"
TEST_ISSUER_ID = "decorator-test-issuer"


def create_test_grant(
    surface: str = "spend",
    action: str = "transfer_money",
    secret: bytes = TEST_SECRET,
    expires_in_seconds: int = 300,
) -> tuple[ActionGrant, TrigGuardVerifierSDK]:
    """Create a valid test grant with configured SDK."""
    # Create issuer with HMAC
    issuer = ActionGrantIssuer(
        hmac_secret=secret,
        issuer_id=TEST_ISSUER_ID,
        use_hmac=True,
    )

    # Create frame and receipt
    frame = SignalFrame(
        request_id=uuid4(),
        surface=ExecutionSurface(surface),
    )
    receipt = generate_receipt(
        frame=frame,
        decision=Decision.PERMIT,
        reason=None,
        policy_version="v1.0.0",
    )
    request = ExecutionRequest(
        request_id=uuid4(),
        action=action,
        surface=ExecutionSurface(surface),
    )

    # Handle expired grants
    ttl = expires_in_seconds if expires_in_seconds > 0 else 1

    # Issue grant
    grant = issuer.issue_grant(
        decision=Decision.PERMIT,
        receipt=receipt,
        request=request,
        constraints=GrantConstraints(),
        ttl_seconds=ttl,
    )

    # For expired grants, manually modify the timestamp
    if expires_in_seconds < 0:
        grant.expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=expires_in_seconds
        )

    # Create SDK with HMAC secret
    sdk = TrigGuardVerifierSDK()
    sdk.load_hmac_secret(TEST_ISSUER_ID, secret)

    return grant, sdk


class TestRequiresGrantBasic:
    """Basic tests for @requires_grant decorator."""

    def test_missing_grant_raises_error(self):
        """Test that missing grant raises MissingGrantError."""

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float) -> float:
            return amount

        with pytest.raises(MissingGrantError) as exc_info:
            transfer(100)

        assert exc_info.value.surface == "spend"
        assert exc_info.value.action == "transfer_money"

    def test_missing_grant_non_strict_returns_none(self):
        """Test that missing grant in non-strict mode returns None."""

        @requires_grant(surface="spend", action="transfer_money", strict=False)
        def transfer(amount: float) -> float:
            return amount

        result = transfer(100)
        assert result is None

    def test_valid_grant_allows_execution(self):
        """Test that valid grant allows function execution."""
        grant, sdk = create_test_grant(surface="spend", action="transfer_money")

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float) -> float:
            return amount * 2

        result = transfer(100, grant=grant, keyset=sdk)
        assert result == 200

    def test_function_receives_args_correctly(self):
        """Test that function receives positional and keyword args."""
        grant, sdk = create_test_grant()

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float, currency: str = "USD") -> str:
            return f"{amount} {currency}"

        result = transfer(100, currency="GBP", grant=grant, keyset=sdk)
        assert result == "100 GBP"


class TestRequiresGrantVerification:
    """Tests for grant verification in decorator."""

    def test_expired_grant_raises_error(self):
        """Test that expired grant raises GrantVerificationError.

        Note: When we manually modify the expiry time after signing,
        the signature becomes invalid. So we verify that verification fails.
        """
        grant, sdk = create_test_grant(expires_in_seconds=-100)  # Already expired

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float) -> float:
            return amount

        with pytest.raises(GrantVerificationError):
            # Verification fails because either grant is expired
            # or signature is invalid (due to post-signing modification)
            transfer(100, grant=grant, keyset=sdk)

    def test_wrong_surface_raises_error(self):
        """Test that grant for wrong surface raises error."""
        grant, sdk = create_test_grant(surface="code_execution", action="run")

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float) -> float:
            return amount

        with pytest.raises(GrantVerificationError) as exc_info:
            transfer(100, grant=grant, keyset=sdk)

        assert "surface" in exc_info.value.reason.lower()

    def test_wrong_action_raises_error(self):
        """Test that grant for wrong action raises error."""
        grant, sdk = create_test_grant(surface="spend", action="refund")

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float) -> float:
            return amount

        with pytest.raises(GrantVerificationError) as exc_info:
            transfer(100, grant=grant, keyset=sdk)

        assert "action" in exc_info.value.reason.lower()

    def test_invalid_signature_raises_error(self):
        """Test that invalid signature raises error."""
        grant, sdk = create_test_grant()
        grant.signature = "hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        @requires_grant(surface="spend", action="transfer_money")
        def transfer(amount: float) -> float:
            return amount

        with pytest.raises(GrantVerificationError):
            transfer(100, grant=grant, keyset=sdk)


class TestRequiresGrantAsync:
    """Tests for @requires_grant_async decorator."""

    @pytest.mark.asyncio
    async def test_async_missing_grant_raises_error(self):
        """Test that missing grant raises error in async."""

        @requires_grant_async(surface="spend", action="transfer_money")
        async def transfer(amount: float) -> float:
            return amount

        with pytest.raises(MissingGrantError):
            await transfer(100)

    @pytest.mark.asyncio
    async def test_async_valid_grant_allows_execution(self):
        """Test that valid grant allows async execution."""
        grant, sdk = create_test_grant()

        @requires_grant_async(surface="spend", action="transfer_money")
        async def transfer(amount: float) -> float:
            return amount * 2

        result = await transfer(100, grant=grant, keyset=sdk)
        assert result == 200


class TestIntrospection:
    """Tests for decorator introspection functions."""

    def test_is_protected(self):
        """Test is_protected detection."""

        @requires_grant(surface="spend", action="transfer")
        def protected_func():
            pass

        def unprotected_func():
            pass

        assert is_protected(protected_func) is True
        assert is_protected(unprotected_func) is False

    def test_get_protected_surface(self):
        """Test getting protected surface."""

        @requires_grant(surface="code_execution", action="run")
        def run_code():
            pass

        assert get_protected_surface(run_code) == "code_execution"

    def test_get_protected_action(self):
        """Test getting protected action."""

        @requires_grant(surface="spend", action="transfer_money")
        def transfer():
            pass

        assert get_protected_action(transfer) == "transfer_money"

    def test_unprotected_returns_none(self):
        """Test introspection returns None for unprotected functions."""

        def normal_func():
            pass

        assert get_protected_surface(normal_func) is None
        assert get_protected_action(normal_func) is None


class TestRequiresKeySet:
    """Tests for require_keyset option."""

    def test_require_keyset_without_keyset_raises(self):
        """Test that require_keyset=True raises when keyset not provided."""
        grant, _ = create_test_grant()

        @requires_grant(surface="spend", action="transfer_money", require_keyset=True)
        def transfer(amount: float) -> float:
            return amount

        with pytest.raises(GrantVerificationError) as exc_info:
            transfer(100, grant=grant)  # No keyset

        assert "keyset" in exc_info.value.reason.lower()

    def test_require_keyset_with_keyset_works(self):
        """Test that require_keyset=True works when keyset provided."""
        grant, sdk = create_test_grant()

        @requires_grant(surface="spend", action="transfer_money", require_keyset=True)
        def transfer(amount: float) -> float:
            return amount * 2

        result = transfer(100, grant=grant, keyset=sdk)
        assert result == 200


class TestDecoratorPreservesFunction:
    """Tests that decorator preserves function metadata."""

    def test_preserves_name(self):
        """Test that decorator preserves function name."""

        @requires_grant(surface="spend", action="transfer")
        def my_special_function():
            pass

        assert my_special_function.__name__ == "my_special_function"

    def test_preserves_docstring(self):
        """Test that decorator preserves docstring."""

        @requires_grant(surface="spend", action="transfer")
        def transfer():
            """Transfer money to recipient."""
            pass

        assert transfer.__doc__ == "Transfer money to recipient."


class TestExceptionDetails:
    """Tests for exception information."""

    def test_missing_grant_error_attributes(self):
        """Test MissingGrantError has correct attributes."""

        @requires_grant(surface="code_execution", action="run_shell")
        def run_shell(cmd: str):
            pass

        with pytest.raises(MissingGrantError) as exc_info:
            run_shell("ls")

        error = exc_info.value
        assert error.surface == "code_execution"
        assert error.action == "run_shell"
        assert error.reason == "No ActionGrant provided"

    def test_verification_error_includes_grant_id(self):
        """Test that GrantVerificationError includes grant_id when available."""
        grant, sdk = create_test_grant(surface="spend", action="wrong_action")

        @requires_grant(surface="spend", action="transfer_money")
        def transfer():
            pass

        with pytest.raises(GrantVerificationError) as exc_info:
            transfer(grant=grant, keyset=sdk)

        error = exc_info.value
        assert error.grant_id == str(grant.grant_id)
