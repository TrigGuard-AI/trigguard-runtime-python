"""
Policy Verifier

Cryptographic verification of policy bundles.

This module ensures:
- Bundle integrity via SHA256
- Authenticity via cryptographic signature
- Compatibility with local signal taxonomy

IMPORTANT:
- Unsigned bundles MUST be rejected
- Tampered bundles MUST be rejected
- Incompatible bundles MUST be rejected
"""

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from trigguard.network.policy_bundle import PolicyBundle, BundleStatus


class VerificationStatus(str, Enum):
    """Result of bundle verification."""

    VALID = "valid"
    INVALID_HASH = "invalid_hash"
    INVALID_SIGNATURE = "invalid_signature"
    UNSIGNED = "unsigned"
    EXPIRED = "expired"
    INCOMPATIBLE_TAXONOMY = "incompatible_taxonomy"
    INCOMPATIBLE_KERNEL = "incompatible_kernel"


@dataclass
class VerificationResult:
    """Result of policy bundle verification."""

    status: VerificationStatus
    is_valid: bool
    message: str
    details: dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class PolicyVerifier:
    """
    Verifies cryptographic integrity and authenticity of policy bundles.

    Verification checks:
    1. Bundle hash matches content (integrity)
    2. Signature is valid (authenticity)
    3. Bundle is not expired
    4. Signal taxonomy is compatible
    5. Kernel version is compatible

    FAIL CLOSED: Any verification failure rejects the bundle.
    """

    def __init__(
        self,
        local_taxonomy_hash: str,
        kernel_version: str = "1.0.0",
        trusted_signers: Optional[list[str]] = None,
        signing_key: Optional[str] = None,
    ):
        """
        Initialize verifier.

        Args:
            local_taxonomy_hash: Hash of local signal taxonomy for compatibility
            kernel_version: Current kernel version
            trusted_signers: List of trusted signer identities
            signing_key: Key for HMAC verification (for demo/testing)
        """
        self.local_taxonomy_hash = local_taxonomy_hash
        self.kernel_version = kernel_version
        self.trusted_signers = trusted_signers or []
        self.signing_key = signing_key or "trigguard-default-key"

    def verify_bundle(self, bundle: PolicyBundle) -> VerificationResult:
        """
        Verify a policy bundle.

        Performs all verification checks in order.
        Fails fast on first error.

        Args:
            bundle: The PolicyBundle to verify

        Returns:
            VerificationResult with status and details
        """
        # Check 1: Bundle must have signature
        if not bundle.signature:
            bundle.set_status(BundleStatus.REJECTED)
            return VerificationResult(
                status=VerificationStatus.UNSIGNED,
                is_valid=False,
                message="Bundle is not signed",
            )

        # Check 2: Verify hash integrity
        hash_result = self._verify_hash(bundle)
        if not hash_result.is_valid:
            bundle.set_status(BundleStatus.REJECTED)
            return hash_result

        # Check 3: Verify signature
        sig_result = self._verify_signature(bundle)
        if not sig_result.is_valid:
            bundle.set_status(BundleStatus.REJECTED)
            return sig_result

        # Check 4: Check expiration
        exp_result = self._verify_expiration(bundle)
        if not exp_result.is_valid:
            bundle.set_status(BundleStatus.REJECTED)
            return exp_result

        # Check 5: Verify taxonomy compatibility
        tax_result = self._verify_taxonomy(bundle)
        if not tax_result.is_valid:
            bundle.set_status(BundleStatus.REJECTED)
            return tax_result

        # Check 6: Verify kernel version compatibility
        ver_result = self._verify_kernel_version(bundle)
        if not ver_result.is_valid:
            bundle.set_status(BundleStatus.REJECTED)
            return ver_result

        # All checks passed
        bundle.set_status(BundleStatus.VERIFIED)
        return VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            message="Bundle verified successfully",
            details={
                "version": bundle.version,
                "signed_by": bundle.signed_by,
                "bundle_hash": bundle.bundle_hash[:16] + "...",
            },
        )

    def _verify_hash(self, bundle: PolicyBundle) -> VerificationResult:
        """Verify bundle hash matches content."""
        expected_hash = bundle.compute_hash()

        if bundle.bundle_hash != expected_hash:
            return VerificationResult(
                status=VerificationStatus.INVALID_HASH,
                is_valid=False,
                message="Bundle hash does not match content (possible tampering)",
                details={
                    "expected": expected_hash[:16] + "...",
                    "actual": bundle.bundle_hash[:16] + "...",
                },
            )

        return VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            message="Hash verified",
        )

    def _verify_signature(self, bundle: PolicyBundle) -> VerificationResult:
        """
        Verify cryptographic signature.

        For demo/testing: Uses HMAC-SHA256
        In production: Would use RSA/ECDSA with public key
        """
        # Compute expected signature
        message = f"{bundle.bundle_hash}:{bundle.signed_by}"
        expected_sig = hmac.new(
            self.signing_key.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(bundle.signature, expected_sig):
            return VerificationResult(
                status=VerificationStatus.INVALID_SIGNATURE,
                is_valid=False,
                message="Invalid signature",
            )

        # Check if signer is trusted
        if self.trusted_signers and bundle.signed_by not in self.trusted_signers:
            return VerificationResult(
                status=VerificationStatus.INVALID_SIGNATURE,
                is_valid=False,
                message=f"Signer '{bundle.signed_by}' is not trusted",
            )

        return VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            message="Signature verified",
        )

    def _verify_expiration(self, bundle: PolicyBundle) -> VerificationResult:
        """Check if bundle has expired."""
        from datetime import datetime

        if bundle.expires_at and datetime.utcnow() > bundle.expires_at:
            return VerificationResult(
                status=VerificationStatus.EXPIRED,
                is_valid=False,
                message=f"Bundle expired at {bundle.expires_at.isoformat()}",
            )

        return VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            message="Bundle not expired",
        )

    def _verify_taxonomy(self, bundle: PolicyBundle) -> VerificationResult:
        """Verify signal taxonomy compatibility."""
        if bundle.signal_taxonomy_hash != self.local_taxonomy_hash:
            return VerificationResult(
                status=VerificationStatus.INCOMPATIBLE_TAXONOMY,
                is_valid=False,
                message="Bundle requires different signal taxonomy",
                details={
                    "bundle_taxonomy": bundle.signal_taxonomy_hash[:16] + "...",
                    "local_taxonomy": self.local_taxonomy_hash[:16] + "...",
                },
            )

        return VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            message="Taxonomy compatible",
        )

    def _verify_kernel_version(self, bundle: PolicyBundle) -> VerificationResult:
        """Verify kernel version compatibility."""
        if not self._version_compatible(self.kernel_version, bundle.min_kernel_version):
            return VerificationResult(
                status=VerificationStatus.INCOMPATIBLE_KERNEL,
                is_valid=False,
                message=f"Bundle requires kernel >= {bundle.min_kernel_version}",
                details={
                    "kernel_version": self.kernel_version,
                    "required": bundle.min_kernel_version,
                },
            )

        return VerificationResult(
            status=VerificationStatus.VALID,
            is_valid=True,
            message="Kernel version compatible",
        )

    def _version_compatible(self, current: str, required: str) -> bool:
        """Check if current version meets requirement."""

        def parse_version(v: str) -> tuple[int, ...]:
            # Handle 'v' prefix
            if v.startswith("v"):
                v = v[1:]
            return tuple(int(x) for x in v.split("."))

        try:
            current_parts = parse_version(current)
            required_parts = parse_version(required)
            return current_parts >= required_parts
        except ValueError:
            return False


def sign_bundle(
    bundle: PolicyBundle,
    signer_id: str,
    signing_key: str,
) -> PolicyBundle:
    """
    Sign a policy bundle.

    Computes hash and signature for the bundle.

    For demo/testing: Uses HMAC-SHA256
    In production: Would use RSA/ECDSA private key

    Args:
        bundle: The unsigned bundle
        signer_id: Identity of the signer
        signing_key: Key for signing

    Returns:
        Signed bundle
    """
    # Compute hash
    bundle.bundle_hash = bundle.compute_hash()
    bundle.signed_by = signer_id

    # Compute signature
    message = f"{bundle.bundle_hash}:{signer_id}"
    signature = hmac.new(
        signing_key.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()

    bundle.signature = signature

    return bundle


def compute_taxonomy_hash() -> str:
    """
    Compute hash of the local signal taxonomy.

    This is used for compatibility checking.
    """
    from trigguard.signals.signal_types import SignalType

    # Create deterministic representation of taxonomy
    signals = sorted([s.value for s in SignalType])
    taxonomy_str = ",".join(signals)

    return hashlib.sha256(taxonomy_str.encode()).hexdigest()
