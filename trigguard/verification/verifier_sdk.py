"""
TrigGuard Verifier SDK

Portable verification SDK for Action Grants.

This SDK can be used by any third-party executor to verify
Action Grants offline without calling TrigGuard services.

Features:
- Load key sets from public key discovery
- Verify grant signatures
- Check expiry
- Validate scope
- Enforce constraints
- No network calls required

Usage:
    from trigguard.verification import TrigGuardVerifierSDK, PublicKeySet

    # Fetch keys once (the only network call needed)
    key_set = fetch_keys_from_well_known()

    # Create SDK
    sdk = TrigGuardVerifierSDK()
    sdk.load_key_set(key_set)

    # Verify grants offline
    result = sdk.verify_grant_and_scope(
        grant,
        surface="SPEND",
        action="transfer_money",
        execution_input={"amount": 50},
    )

    if result.valid:
        execute_action()
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Union

from trigguard.grants.action_grant import ActionGrant
from trigguard.verification.public_keys import PublicKeyRecord, PublicKeySet

# Try to import cryptography for Ed25519
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False


@dataclass
class VerificationResult:
    """
    Result of SDK verification.

    Attributes:
        valid: Whether the grant is valid
        reason: Human-readable explanation
        checks: Details of individual verification checks
        issuer: Grant issuer (if verified)
        kid: Key ID used for verification (if applicable)
    """

    valid: bool
    reason: str
    checks: dict[str, Any] = field(default_factory=dict)
    issuer: Optional[str] = None
    kid: Optional[str] = None

    @classmethod
    def success(
        cls,
        issuer: str,
        kid: str,
        checks: Optional[dict[str, Any]] = None,
    ) -> "VerificationResult":
        """Create a successful verification result."""
        return cls(
            valid=True,
            reason="Grant verified successfully",
            checks=checks or {},
            issuer=issuer,
            kid=kid,
        )

    @classmethod
    def failure(
        cls,
        reason: str,
        checks: Optional[dict[str, Any]] = None,
        issuer: Optional[str] = None,
        kid: Optional[str] = None,
    ) -> "VerificationResult":
        """Create a failed verification result."""
        return cls(
            valid=False,
            reason=reason,
            checks=checks or {},
            issuer=issuer,
            kid=kid,
        )


class TrigGuardVerifierSDK:
    """
    Portable Verifier SDK for offline Action Grant verification.

    This SDK is designed for third-party executors who need to
    verify TrigGuard grants without network access to TrigGuard services.

    Workflow:
    1. Bootstrap: Fetch keys from /.well-known/trigguard-keys (once)
    2. Cache: Store the key set
    3. Verify: Use SDK to verify grants offline
    """

    def __init__(self) -> None:
        """Initialize an empty SDK."""
        self._key_sets: dict[str, PublicKeySet] = {}
        self._hmac_secrets: dict[str, bytes] = {}

    def load_key_set(self, key_set: Union[PublicKeySet, dict]) -> None:
        """
        Load a public key set from an issuer.

        Args:
            key_set: PublicKeySet or dict from API response
        """
        if isinstance(key_set, dict):
            key_set = PublicKeySet.from_dict(key_set)

        self._key_sets[key_set.issuer] = key_set

    def load_hmac_secret(self, issuer: str, secret: bytes) -> None:
        """
        Load an HMAC secret for an issuer (for HMAC-SHA256 verification).

        Args:
            issuer: Issuer identity
            secret: HMAC secret bytes
        """
        self._hmac_secrets[issuer] = secret

    def get_key(self, issuer: str, kid: str) -> Optional[PublicKeyRecord]:
        """
        Get a specific key by issuer and kid.

        Args:
            issuer: Issuer identity
            kid: Key ID

        Returns:
            PublicKeyRecord or None
        """
        key_set = self._key_sets.get(issuer)
        if key_set is None:
            return None
        return key_set.get_key(kid)

    def verify_signature(
        self,
        grant: ActionGrant,
        kid: Optional[str] = None,
    ) -> VerificationResult:
        """
        Verify only the signature of a grant.

        Args:
            grant: ActionGrant to verify
            kid: Key ID to use (optional, extracted from grant if present)

        Returns:
            VerificationResult
        """
        if not grant.signature:
            return VerificationResult.failure(
                "Missing signature",
                checks={"signature": {"valid": False, "reason": "no_signature"}},
            )

        issuer = grant.issuer
        grant_kid = getattr(grant, "kid", None) or kid

        # Determine signature type
        if grant.signature.startswith("hmac-sha256:"):
            return self._verify_hmac_signature(grant, issuer)
        elif grant.signature.startswith("ed25519:"):
            return self._verify_ed25519_signature(grant, issuer, grant_kid)
        else:
            return VerificationResult.failure(
                f"Unknown signature format: {grant.signature[:20]}...",
                checks={"signature": {"valid": False, "reason": "unknown_format"}},
            )

    def _verify_hmac_signature(
        self,
        grant: ActionGrant,
        issuer: str,
    ) -> VerificationResult:
        """Verify HMAC-SHA256 signature."""
        secret = self._hmac_secrets.get(issuer)
        if secret is None:
            return VerificationResult.failure(
                f"No HMAC secret for issuer: {issuer}",
                checks={"signature": {"valid": False, "reason": "no_secret"}},
                issuer=issuer,
            )

        try:
            # Extract signature
            sig_b64 = grant.signature.split(":", 1)[1]
            expected_sig = base64.b64decode(sig_b64)

            # Compute expected
            payload = grant.to_canonical_json()
            computed_sig = hmac.new(
                secret, payload.encode("utf-8"), hashlib.sha256
            ).digest()

            if hmac.compare_digest(expected_sig, computed_sig):
                return VerificationResult.success(
                    issuer=issuer,
                    kid="hmac",
                    checks={"signature": {"valid": True, "alg": "HMAC-SHA256"}},
                )
            else:
                return VerificationResult.failure(
                    "Invalid signature",
                    checks={"signature": {"valid": False, "reason": "mismatch"}},
                    issuer=issuer,
                )
        except Exception as e:
            return VerificationResult.failure(
                f"Signature verification error: {e}",
                checks={"signature": {"valid": False, "reason": str(e)}},
                issuer=issuer,
            )

    def _verify_ed25519_signature(
        self,
        grant: ActionGrant,
        issuer: str,
        kid: Optional[str],
    ) -> VerificationResult:
        """Verify Ed25519 signature."""
        if not HAS_ED25519:
            return VerificationResult.failure(
                "Ed25519 not available (install cryptography)",
                checks={"signature": {"valid": False, "reason": "no_ed25519"}},
                issuer=issuer,
            )

        if kid is None:
            return VerificationResult.failure(
                "No key ID (kid) for Ed25519 verification",
                checks={"signature": {"valid": False, "reason": "no_kid"}},
                issuer=issuer,
            )

        key_record = self.get_key(issuer, kid)
        if key_record is None:
            return VerificationResult.failure(
                f"Key not found: {issuer}/{kid}",
                checks={"signature": {"valid": False, "reason": "key_not_found"}},
                issuer=issuer,
                kid=kid,
            )

        try:
            # Get public key
            public_key_bytes = key_record.get_public_key_bytes()
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # Extract signature
            sig_b64 = grant.signature.split(":", 1)[1]
            signature_bytes = base64.b64decode(sig_b64)

            # Verify
            payload = grant.to_canonical_json()
            public_key.verify(signature_bytes, payload.encode("utf-8"))

            return VerificationResult.success(
                issuer=issuer,
                kid=kid,
                checks={"signature": {"valid": True, "alg": "Ed25519", "kid": kid}},
            )
        except InvalidSignature:
            return VerificationResult.failure(
                "Invalid signature",
                checks={"signature": {"valid": False, "reason": "invalid"}},
                issuer=issuer,
                kid=kid,
            )
        except Exception as e:
            return VerificationResult.failure(
                f"Signature verification error: {e}",
                checks={"signature": {"valid": False, "reason": str(e)}},
                issuer=issuer,
                kid=kid,
            )

    def verify_expiry(
        self,
        grant: ActionGrant,
        now: Optional[datetime] = None,
    ) -> VerificationResult:
        """
        Verify the grant has not expired.

        Args:
            grant: ActionGrant to verify
            now: Current time (for testing)

        Returns:
            VerificationResult
        """
        if now is None:
            now = datetime.now(timezone.utc)

        expires_at = grant.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            return VerificationResult.failure(
                f"Grant expired at {expires_at.isoformat()}",
                checks={
                    "expiry": {
                        "valid": False,
                        "expires_at": expires_at.isoformat(),
                        "now": now.isoformat(),
                    }
                },
                issuer=grant.issuer,
            )

        return VerificationResult.success(
            issuer=grant.issuer,
            kid=getattr(grant, "kid", None),
            checks={
                "expiry": {
                    "valid": True,
                    "expires_at": expires_at.isoformat(),
                    "ttl_seconds": (expires_at - now).total_seconds(),
                }
            },
        )

    def verify_scope(
        self,
        grant: ActionGrant,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
    ) -> VerificationResult:
        """
        Verify the grant scope matches the execution context.

        Args:
            grant: ActionGrant to verify
            surface: Expected surface
            action: Expected action
            resource: Expected resource (optional)

        Returns:
            VerificationResult
        """
        checks: dict[str, Any] = {"scope": {}}

        # Normalize for comparison (case-insensitive)
        grant_surface = grant.surface.lower()
        expected_surface = surface.lower()

        if grant_surface != expected_surface:
            return VerificationResult.failure(
                f"Surface mismatch: grant={grant.surface}, expected={surface}",
                checks={"scope": {"valid": False, "reason": "surface_mismatch"}},
                issuer=grant.issuer,
            )

        if grant.action != action:
            return VerificationResult.failure(
                f"Action mismatch: grant={grant.action}, expected={action}",
                checks={"scope": {"valid": False, "reason": "action_mismatch"}},
                issuer=grant.issuer,
            )

        if resource is not None and grant.resource != resource:
            return VerificationResult.failure(
                f"Resource mismatch: grant={grant.resource}, expected={resource}",
                checks={"scope": {"valid": False, "reason": "resource_mismatch"}},
                issuer=grant.issuer,
            )

        return VerificationResult.success(
            issuer=grant.issuer,
            kid=getattr(grant, "kid", None),
            checks={
                "scope": {
                    "valid": True,
                    "surface": grant.surface,
                    "action": grant.action,
                    "resource": grant.resource,
                }
            },
        )

    def verify_constraints(
        self,
        grant: ActionGrant,
        execution_input: dict[str, Any],
    ) -> VerificationResult:
        """
        Verify execution input satisfies grant constraints.

        Args:
            grant: ActionGrant to verify
            execution_input: Actual execution parameters

        Returns:
            VerificationResult
        """
        constraints = grant.constraints
        violations: list[str] = []

        # Check max_amount
        if constraints.max_amount is not None:
            amount = execution_input.get("amount")
            if amount is not None and amount > constraints.max_amount:
                violations.append(
                    f"amount {amount} exceeds max_amount {constraints.max_amount}"
                )

        # Check allowed_currency
        if constraints.allowed_currency is not None:
            currency = execution_input.get("currency")
            if currency is not None and currency != constraints.allowed_currency:
                violations.append(
                    f"currency {currency} != allowed_currency {constraints.allowed_currency}"
                )

        # Check allowed_command
        if constraints.allowed_command is not None:
            command = execution_input.get("command")
            if command is not None and command != constraints.allowed_command:
                violations.append(
                    f"command {command} != allowed_command {constraints.allowed_command}"
                )

        if violations:
            return VerificationResult.failure(
                f"Constraint violations: {', '.join(violations)}",
                checks={
                    "constraints": {
                        "valid": False,
                        "violations": violations,
                    }
                },
                issuer=grant.issuer,
            )

        return VerificationResult.success(
            issuer=grant.issuer,
            kid=getattr(grant, "kid", None),
            checks={
                "constraints": {
                    "valid": True,
                    "verified": list(constraints.to_dict().keys()),
                }
            },
        )

    def verify_grant(
        self,
        grant: ActionGrant,
        kid: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> VerificationResult:
        """
        Verify signature and expiry of a grant.

        Args:
            grant: ActionGrant to verify
            kid: Key ID for verification (optional)
            now: Current time (for testing)

        Returns:
            VerificationResult
        """
        # Verify signature
        sig_result = self.verify_signature(grant, kid)
        if not sig_result.valid:
            return sig_result

        # Verify expiry
        expiry_result = self.verify_expiry(grant, now)
        if not expiry_result.valid:
            expiry_result.checks.update(sig_result.checks)
            return expiry_result

        # Combine checks
        all_checks = {}
        all_checks.update(sig_result.checks)
        all_checks.update(expiry_result.checks)

        return VerificationResult.success(
            issuer=grant.issuer,
            kid=sig_result.kid,
            checks=all_checks,
        )

    def verify_grant_and_scope(
        self,
        grant: ActionGrant,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
        kid: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> VerificationResult:
        """
        Full verification of grant including scope and constraints.

        This is the primary verification method for executors.

        Args:
            grant: ActionGrant to verify
            surface: Expected surface
            action: Expected action
            resource: Expected resource (optional)
            execution_input: Execution parameters for constraint checking
            kid: Key ID for verification (optional)
            now: Current time (for testing)

        Returns:
            VerificationResult with all checks
        """
        all_checks: dict[str, Any] = {}

        # 1. Verify signature
        sig_result = self.verify_signature(grant, kid)
        all_checks.update(sig_result.checks)
        if not sig_result.valid:
            return VerificationResult.failure(
                sig_result.reason,
                checks=all_checks,
                issuer=grant.issuer,
                kid=sig_result.kid,
            )

        # 2. Verify expiry
        expiry_result = self.verify_expiry(grant, now)
        all_checks.update(expiry_result.checks)
        if not expiry_result.valid:
            return VerificationResult.failure(
                expiry_result.reason,
                checks=all_checks,
                issuer=grant.issuer,
                kid=sig_result.kid,
            )

        # 3. Verify scope
        scope_result = self.verify_scope(
            grant, surface=surface, action=action, resource=resource
        )
        all_checks.update(scope_result.checks)
        if not scope_result.valid:
            return VerificationResult.failure(
                scope_result.reason,
                checks=all_checks,
                issuer=grant.issuer,
                kid=sig_result.kid,
            )

        # 4. Verify constraints (if execution input provided)
        if execution_input:
            constraint_result = self.verify_constraints(grant, execution_input)
            all_checks.update(constraint_result.checks)
            if not constraint_result.valid:
                return VerificationResult.failure(
                    constraint_result.reason,
                    checks=all_checks,
                    issuer=grant.issuer,
                    kid=sig_result.kid,
                )

        return VerificationResult.success(
            issuer=grant.issuer,
            kid=sig_result.kid,
            checks=all_checks,
        )
