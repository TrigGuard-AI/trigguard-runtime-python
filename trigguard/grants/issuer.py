"""
Action Grant Issuer

Issues signed, short-lived Action Grants from PERMIT decisions.

The issuer:
1. Verifies the decision is PERMIT
2. Verifies the receipt is present and valid
3. Builds the ActionGrant payload
4. Signs with Ed25519
5. Returns the signed grant

Usage:
    issuer = ActionGrantIssuer(private_key)
    grant = issuer.issue_grant(
        decision=Decision.PERMIT,
        receipt=receipt,
        request=request,
        constraints=GrantConstraints(max_amount=100),
        ttl_seconds=30,
    )
"""

import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union
from uuid import uuid4

from trigguard.grants.action_grant import ActionGrant, GrantConstraints
from trigguard.grants.errors import GrantIssuanceError
from trigguard.protocol.decision_contracts import Decision, DecisionReceipt

# Try to import cryptography for Ed25519
# Fall back to HMAC-SHA256 if not available
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64

    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False


class ActionGrantIssuer:
    """
    Issues signed Action Grants from PERMIT decisions.

    The issuer only creates grants when:
    - Decision is PERMIT
    - Receipt is present and internally consistent
    - TTL is positive

    The issuer does NOT make policy decisions.
    It packages existing authorization into a portable format.
    """

    def __init__(
        self,
        private_key: Union[bytes, "Ed25519PrivateKey", None] = None,
        issuer_id: str = "trigguard-kernel",
        use_hmac: bool = False,
        hmac_secret: Optional[bytes] = None,
    ):
        """
        Initialize the issuer.

        Args:
            private_key: Ed25519 private key (32 bytes seed or key object)
            issuer_id: Identifier for this issuer
            use_hmac: Use HMAC-SHA256 instead of Ed25519 (for testing)
            hmac_secret: Secret for HMAC signing
        """
        self.issuer_id = issuer_id
        self.use_hmac = use_hmac or not HAS_ED25519

        if self.use_hmac:
            self._hmac_secret = hmac_secret or b"trigguard-dev-secret"
            self._private_key = None
        else:
            if private_key is None:
                # Generate ephemeral key for testing
                self._private_key = Ed25519PrivateKey.generate()
            elif isinstance(private_key, bytes):
                # Load from seed
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PrivateKey,
                )

                self._private_key = Ed25519PrivateKey.from_private_bytes(private_key)
            else:
                self._private_key = private_key
            self._hmac_secret = None

    def issue_grant(
        self,
        decision: Decision,
        receipt: DecisionReceipt,
        request: Any,
        *,
        subject: Optional[str] = None,
        resource: Optional[str] = None,
        constraints: Optional[GrantConstraints] = None,
        ttl_seconds: int = 30,
        metadata: Optional[dict[str, Any]] = None,
        kid: Optional[str] = None,
    ) -> ActionGrant:
        """
        Issue a signed Action Grant.

        Args:
            decision: The authorization decision (must be PERMIT)
            receipt: The DecisionReceipt from the authorization
            request: The original execution request
            subject: Agent/caller identity if known
            resource: Target resource identifier
            constraints: Explicit limits on execution
            ttl_seconds: Time-to-live in seconds (default: 30)
            metadata: Additional context
            kid: Key ID for signature verification (for key rotation)

        Returns:
            Signed ActionGrant

        Raises:
            GrantIssuanceError: If grant cannot be issued
        """
        # Validate preconditions
        if decision != Decision.PERMIT:
            raise GrantIssuanceError(
                f"Cannot issue grant for {decision.value} decision. "
                "Only PERMIT decisions can receive grants."
            )

        if receipt is None:
            raise GrantIssuanceError("Cannot issue grant without a DecisionReceipt.")

        if ttl_seconds <= 0:
            raise GrantIssuanceError(
                f"TTL must be positive, got {ttl_seconds} seconds."
            )

        # Validate receipt integrity
        if not hasattr(receipt, "receipt_hash") or not receipt.receipt_hash:
            raise GrantIssuanceError("Receipt must have a valid receipt_hash.")

        if not hasattr(receipt, "decision_hash") or not receipt.decision_hash:
            raise GrantIssuanceError("Receipt must have a valid decision_hash.")

        # Extract surface and action from request
        surface = self._extract_surface(request, receipt)
        action = self._extract_action(request)

        # Set defaults
        if constraints is None:
            constraints = GrantConstraints()
        if metadata is None:
            metadata = {}

        # Build grant
        now = datetime.now(timezone.utc)
        grant = ActionGrant(
            grant_id=uuid4(),
            issuer=self.issuer_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            subject=subject,
            surface=surface,
            action=action,
            resource=resource,
            constraints=constraints,
            policy_version=receipt.policy_version,
            decision_hash=receipt.decision_hash,
            receipt_hash=receipt.receipt_hash,
            kid=kid,
            metadata=metadata,
            signature=None,
        )

        # Sign the grant
        signature = self._sign(grant.to_canonical_json())
        grant.signature = signature

        return grant

    def _extract_surface(self, request: Any, receipt: DecisionReceipt) -> str:
        """Extract surface from request or receipt."""
        # Try request first
        if hasattr(request, "surface"):
            surface = request.surface
            if hasattr(surface, "value"):
                return surface.value
            return str(surface)

        # Fall back to receipt
        if hasattr(receipt, "surface"):
            surface = receipt.surface
            if hasattr(surface, "value"):
                return surface.value
            return str(surface)

        return "unknown"

    def _extract_action(self, request: Any) -> str:
        """Extract action from request."""
        if hasattr(request, "action"):
            return str(request.action)
        if isinstance(request, dict) and "action" in request:
            return str(request["action"])
        return "unknown"

    def _sign(self, payload: str) -> str:
        """Sign the payload and return base64-encoded signature."""
        payload_bytes = payload.encode("utf-8")

        if self.use_hmac:
            # HMAC-SHA256 fallback
            signature = hmac.new(
                self._hmac_secret, payload_bytes, hashlib.sha256
            ).digest()
            return f"hmac-sha256:{base64.b64encode(signature).decode('ascii')}"
        else:
            # Ed25519 signature
            signature = self._private_key.sign(payload_bytes)
            return f"ed25519:{base64.b64encode(signature).decode('ascii')}"

    def get_public_key(self) -> Optional[bytes]:
        """Get the public key for verification."""
        if self.use_hmac:
            return None

        public_key = self._private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_public_key_base64(self) -> Optional[str]:
        """Get the public key as base64 string."""
        pk = self.get_public_key()
        if pk is None:
            return None
        return base64.b64encode(pk).decode("ascii")
