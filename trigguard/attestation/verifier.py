"""
TrigGuard Surface Attestation Verifier

Verifies that execution surfaces match their expected code hashes.
This prevents silent code changes and ensures grant integrity.

Usage:
    from trigguard.attestation.verifier import SurfaceAttestationVerifier

    verifier = SurfaceAttestationVerifier()

    # Verify at execution time
    verifier.verify(
        surface_id="trigguard.spend.transfer",
        expected_hash="sha256:6ab3c...",
        registry=attestation_registry,
    )

The verifier can be integrated into the executor to enforce
attestation on every execution.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional
import logging

from trigguard.attestation import AttestationRegistry, SurfaceAttestation

logger = logging.getLogger(__name__)


class AttestationVerificationError(Exception):
    """Raised when attestation verification fails."""

    def __init__(
        self,
        surface_id: str,
        expected_hash: Optional[str],
        actual_hash: Optional[str],
        reason: str,
    ):
        self.surface_id = surface_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        self.reason = reason
        super().__init__(f"Attestation verification failed for {surface_id}: {reason}")


class SurfaceNotAttestedError(AttestationVerificationError):
    """Raised when a surface has no attestation."""

    def __init__(self, surface_id: str):
        super().__init__(
            surface_id=surface_id,
            expected_hash=None,
            actual_hash=None,
            reason="Surface has no attestation record",
        )


class HashMismatchError(AttestationVerificationError):
    """Raised when surface hash doesn't match expected."""

    def __init__(
        self,
        surface_id: str,
        expected_hash: str,
        actual_hash: str,
    ):
        super().__init__(
            surface_id=surface_id,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            reason=f"Hash mismatch: expected {expected_hash[:20]}..., got {actual_hash[:20]}...",
        )


@dataclass
class VerificationResult:
    """Result of attestation verification."""

    valid: bool
    surface_id: str
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    error: Optional[str] = None

    @property
    def reason(self) -> str:
        if self.valid:
            return "Verification passed"
        return self.error or "Unknown error"


class SurfaceAttestationVerifier:
    """
    Verifies surface attestations for execution integrity.

    Can operate in two modes:
    - strict: Raises on any verification failure
    - lenient: Returns VerificationResult for caller to handle
    """

    def __init__(
        self,
        *,
        strict: bool = True,
        require_attestation: bool = False,
        registry: Optional[AttestationRegistry] = None,
    ):
        """
        Initialize verifier.

        Args:
            strict: If True, raises exceptions on failure
            require_attestation: If True, surfaces without attestation fail
            registry: Attestation registry to use (defaults to global)
        """
        self.strict = strict
        self.require_attestation = require_attestation
        self._registry = registry

    @property
    def registry(self) -> AttestationRegistry:
        """Get the attestation registry."""
        if self._registry is None:
            return AttestationRegistry.get_global()
        return self._registry

    def verify(
        self,
        surface_id: str,
        expected_hash: Optional[str] = None,
        registry: Optional[AttestationRegistry] = None,
    ) -> VerificationResult:
        """
        Verify surface attestation.

        Args:
            surface_id: Surface to verify
            expected_hash: Expected code hash (from grant)
            registry: Optional registry override

        Returns:
            VerificationResult

        Raises:
            AttestationVerificationError: If strict mode and verification fails
        """
        reg = registry or self.registry
        attestation = reg.get(surface_id)

        # Check if attestation exists
        if attestation is None:
            if self.require_attestation:
                error = SurfaceNotAttestedError(surface_id)
                if self.strict:
                    raise error
                return VerificationResult(
                    valid=False,
                    surface_id=surface_id,
                    error=str(error),
                )
            # No attestation required, pass through
            return VerificationResult(
                valid=True,
                surface_id=surface_id,
            )

        # If expected_hash provided, verify it matches
        if expected_hash is not None:
            if attestation.code_hash != expected_hash:
                error = HashMismatchError(
                    surface_id=surface_id,
                    expected_hash=expected_hash,
                    actual_hash=attestation.code_hash,
                )
                if self.strict:
                    raise error
                return VerificationResult(
                    valid=False,
                    surface_id=surface_id,
                    expected_hash=expected_hash,
                    actual_hash=attestation.code_hash,
                    error=str(error),
                )

        # Verification passed
        return VerificationResult(
            valid=True,
            surface_id=surface_id,
            actual_hash=attestation.code_hash,
        )

    def verify_grant(
        self,
        grant: Any,
        registry: Optional[AttestationRegistry] = None,
    ) -> VerificationResult:
        """
        Verify attestation for a grant's surface.

        Extracts surface_id and expected hash from grant.

        Args:
            grant: ActionGrant to verify
            registry: Optional registry override

        Returns:
            VerificationResult
        """
        surface_id = getattr(grant, "surface", None) or getattr(
            grant, "surface_id", None
        )
        if not surface_id:
            return VerificationResult(
                valid=False,
                surface_id="unknown",
                error="Grant has no surface_id",
            )

        # Get expected hash from grant if present
        expected_hash = getattr(grant, "surface_hash", None)

        return self.verify(
            surface_id=surface_id,
            expected_hash=expected_hash,
            registry=registry,
        )

    def verify_batch(
        self,
        surface_hashes: Dict[str, str],
        registry: Optional[AttestationRegistry] = None,
    ) -> Dict[str, VerificationResult]:
        """
        Verify multiple surfaces at once.

        Args:
            surface_hashes: {surface_id: expected_hash} mapping
            registry: Optional registry override

        Returns:
            Dict of surface_id -> VerificationResult
        """
        results = {}
        for surface_id, expected_hash in surface_hashes.items():
            results[surface_id] = self.verify(
                surface_id=surface_id,
                expected_hash=expected_hash,
                registry=registry,
            )
        return results
