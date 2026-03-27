"""
Action Grant Verifier

Verifies Action Grants offline before execution.

The verifier checks:
1. Signature is valid
2. Grant is not expired
3. Scope matches (surface, action, resource)
4. Constraints are satisfied

The verifier does NOT make policy decisions.
It only validates that the grant is authentic and applicable.

Usage:
    verifier = ActionGrantVerifier(public_key)
    result = verifier.verify_grant(
        grant,
        surface="SPEND",
        action="transfer_money",
        execution_input={"amount": 50, "currency": "GBP"},
    )

    if result.valid:
        execute_action()
    else:
        reject(result.reason)
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Union

from trigguard.grants.action_grant import ActionGrant
from trigguard.grants.errors import (
    GrantConstraintViolationError,
    GrantExpiredError,
    GrantScopeMismatchError,
    GrantSignatureError,
    GrantVerificationError,
)

# Try to import cryptography for Ed25519
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False


@dataclass
class GrantVerificationResult:
    """
    Result of grant verification.

    Attributes:
        valid: Whether the grant is valid for execution
        reason: Human-readable explanation
        checks: Details of individual verification checks
    """

    valid: bool
    reason: str
    checks: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(
        cls, checks: Optional[dict[str, Any]] = None
    ) -> "GrantVerificationResult":
        """Create a successful verification result."""
        return cls(
            valid=True,
            reason="Grant verified successfully",
            checks=checks or {},
        )

    @classmethod
    def failure(
        cls, reason: str, checks: Optional[dict[str, Any]] = None
    ) -> "GrantVerificationResult":
        """Create a failed verification result."""
        return cls(
            valid=False,
            reason=reason,
            checks=checks or {},
        )


class ActionGrantVerifier:
    """
    Verifies Action Grants offline.

    Does NOT require network access.
    Does NOT make policy decisions.
    Only validates:
    - Signature authenticity
    - Temporal validity
    - Scope matching
    - Constraint satisfaction
    """

    def __init__(
        self,
        public_key: Union[bytes, "Ed25519PublicKey", None] = None,
        hmac_secret: Optional[bytes] = None,
    ):
        """
        Initialize the verifier.

        Args:
            public_key: Ed25519 public key (32 bytes or key object)
            hmac_secret: Secret for HMAC verification (fallback)
        """
        self._hmac_secret = hmac_secret

        if public_key is None:
            self._public_key = None
        elif HAS_ED25519:
            if isinstance(public_key, bytes):
                self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
            else:
                self._public_key = public_key
        else:
            self._public_key = None

    def verify_grant(
        self,
        grant: ActionGrant,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> GrantVerificationResult:
        """
        Full verification of an Action Grant.

        Args:
            grant: The Action Grant to verify
            surface: Expected execution surface
            action: Expected action
            resource: Expected resource (optional)
            execution_input: Input values for constraint checking
            now: Current time (for testing)

        Returns:
            GrantVerificationResult with validity and details
        """
        checks = {}

        # 1. Verify signature
        try:
            sig_valid = self.verify_signature(grant)
            checks["signature"] = {"valid": sig_valid}
            if not sig_valid:
                return GrantVerificationResult.failure("Invalid signature", checks)
        except GrantSignatureError as e:
            checks["signature"] = {"valid": False, "error": str(e)}
            return GrantVerificationResult.failure(str(e), checks)

        # 2. Verify not expired
        try:
            not_expired = self.verify_not_expired(grant, now)
            checks["expiry"] = {
                "valid": not_expired,
                "expires_at": grant.expires_at.isoformat(),
                "ttl_seconds": grant.ttl_seconds,
            }
            if not not_expired:
                return GrantVerificationResult.failure("Grant has expired", checks)
        except GrantExpiredError as e:
            checks["expiry"] = {"valid": False, "error": str(e)}
            return GrantVerificationResult.failure(str(e), checks)

        # 3. Verify scope
        try:
            scope_valid = self.verify_scope(
                grant, surface=surface, action=action, resource=resource
            )
            checks["scope"] = {
                "valid": scope_valid,
                "grant_surface": grant.surface,
                "grant_action": grant.action,
                "grant_resource": grant.resource,
                "expected_surface": surface,
                "expected_action": action,
                "expected_resource": resource,
            }
            if not scope_valid:
                return GrantVerificationResult.failure("Scope mismatch", checks)
        except GrantScopeMismatchError as e:
            checks["scope"] = {"valid": False, "error": str(e)}
            return GrantVerificationResult.failure(str(e), checks)

        # 4. Verify constraints
        if execution_input:
            try:
                constraints_valid = self.verify_constraints(grant, execution_input)
                checks["constraints"] = {
                    "valid": constraints_valid,
                    "grant_constraints": grant.constraints.to_dict(),
                    "one_time_use": grant.constraints.one_time_use,
                }
                if not constraints_valid:
                    return GrantVerificationResult.failure(
                        "Constraint violation", checks
                    )
            except GrantConstraintViolationError as e:
                checks["constraints"] = {"valid": False, "error": str(e)}
                return GrantVerificationResult.failure(str(e), checks)
        else:
            checks["constraints"] = {"valid": True, "skipped": True}

        # All checks passed
        return GrantVerificationResult.success(checks)

    def verify_signature(self, grant: ActionGrant) -> bool:
        """
        Verify the grant's cryptographic signature.

        Args:
            grant: The Action Grant to verify

        Returns:
            True if signature is valid

        Raises:
            GrantSignatureError: If signature verification fails
        """
        if not grant.signature:
            raise GrantSignatureError("Grant has no signature")

        payload = grant.to_canonical_json().encode("utf-8")

        # Parse signature format
        if grant.signature.startswith("ed25519:"):
            return self._verify_ed25519(payload, grant.signature)
        elif grant.signature.startswith("hmac-sha256:"):
            return self._verify_hmac(payload, grant.signature)
        else:
            raise GrantSignatureError(
                f"Unknown signature format: {grant.signature[:20]}"
            )

    def _verify_ed25519(self, payload: bytes, signature: str) -> bool:
        """Verify Ed25519 signature."""
        if not HAS_ED25519:
            raise GrantSignatureError("Ed25519 not available (install cryptography)")

        if self._public_key is None:
            raise GrantSignatureError(
                "No public key configured for Ed25519 verification"
            )

        sig_bytes = base64.b64decode(signature[8:])  # Skip "ed25519:"

        try:
            self._public_key.verify(sig_bytes, payload)
            return True
        except InvalidSignature:
            return False

    def _verify_hmac(self, payload: bytes, signature: str) -> bool:
        """Verify HMAC-SHA256 signature."""
        if self._hmac_secret is None:
            raise GrantSignatureError("No HMAC secret configured")

        sig_bytes = base64.b64decode(signature[12:])  # Skip "hmac-sha256:"
        expected = hmac.new(self._hmac_secret, payload, hashlib.sha256).digest()

        return hmac.compare_digest(sig_bytes, expected)

    def verify_not_expired(
        self, grant: ActionGrant, now: Optional[datetime] = None
    ) -> bool:
        """
        Verify the grant has not expired.

        Args:
            grant: The Action Grant to check
            now: Current time (for testing)

        Returns:
            True if grant is still valid

        Raises:
            GrantExpiredError: If grant has expired
        """
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        expires = grant.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        if now > expires:
            raise GrantExpiredError(
                f"Grant expired at {expires.isoformat()}, current time is {now.isoformat()}"
            )

        return True

    def verify_scope(
        self,
        grant: ActionGrant,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
    ) -> bool:
        """
        Verify the grant scope matches the requested execution.

        Args:
            grant: The Action Grant to check
            surface: Expected execution surface
            action: Expected action
            resource: Expected resource (optional)

        Returns:
            True if scope matches

        Raises:
            GrantScopeMismatchError: If scope doesn't match
        """
        # Surface must match (case-insensitive)
        if grant.surface.lower() != surface.lower():
            raise GrantScopeMismatchError(
                f"Surface mismatch: grant authorizes '{grant.surface}', "
                f"but '{surface}' was requested"
            )

        # Action must match (case-insensitive)
        if grant.action.lower() != action.lower():
            raise GrantScopeMismatchError(
                f"Action mismatch: grant authorizes '{grant.action}', "
                f"but '{action}' was requested"
            )

        # Resource must match if grant specifies one
        if grant.resource is not None and resource is not None:
            if grant.resource != resource:
                raise GrantScopeMismatchError(
                    f"Resource mismatch: grant authorizes '{grant.resource}', "
                    f"but '{resource}' was requested"
                )

        return True

    def verify_constraints(
        self, grant: ActionGrant, execution_input: dict[str, Any]
    ) -> bool:
        """
        Verify execution input satisfies grant constraints.

        Args:
            grant: The Action Grant to check
            execution_input: The execution input values

        Returns:
            True if constraints are satisfied

        Raises:
            GrantConstraintViolationError: If a constraint is violated
        """
        constraints = grant.constraints

        # Check max_amount
        if constraints.max_amount is not None:
            amount = execution_input.get("amount")
            if amount is not None and amount > constraints.max_amount:
                raise GrantConstraintViolationError(
                    f"Amount {amount} exceeds max_amount {constraints.max_amount}"
                )

        # Check allowed_currency
        if constraints.allowed_currency is not None:
            currency = execution_input.get("currency")
            if currency is not None and currency != constraints.allowed_currency:
                raise GrantConstraintViolationError(
                    f"Currency '{currency}' not allowed, "
                    f"grant requires '{constraints.allowed_currency}'"
                )

        # Check allowed_command
        if constraints.allowed_command is not None:
            command = execution_input.get("command")
            if command is not None and command != constraints.allowed_command:
                raise GrantConstraintViolationError(
                    f"Command '{command}' not allowed, "
                    f"grant requires '{constraints.allowed_command}'"
                )

        # Check allowed_tool_args
        if constraints.allowed_tool_args is not None:
            tool_args = execution_input.get("tool_args", {})
            for key, expected_value in constraints.allowed_tool_args.items():
                actual_value = tool_args.get(key)
                if actual_value is not None and actual_value != expected_value:
                    raise GrantConstraintViolationError(
                        f"Tool arg '{key}' has value '{actual_value}', "
                        f"grant requires '{expected_value}'"
                    )

        # Check custom constraints
        for key, expected_value in constraints.custom.items():
            actual_value = execution_input.get(key)
            if actual_value is not None and actual_value != expected_value:
                raise GrantConstraintViolationError(
                    f"Custom constraint '{key}' has value '{actual_value}', "
                    f"grant requires '{expected_value}'"
                )

        return True
