"""
TrigGuard Attestation - Cryptographic Surface Verification

This module provides cryptographic binding between execution surfaces
and the code that implements them.

Surface Attestation ensures:
- Surfaces are tied to deterministic code fingerprints
- Decision receipts prove exact runtime state
- Audit trails are cryptographically verifiable
- Behavior changes are detectable

Usage:
    from trigguard.attestation import (
        compute_surface_hash,
        SurfaceAttestation,
        AttestationRegistry,
        verify_attestation,
    )

    # Compute hash for a function
    hash = compute_surface_hash(transfer_funds)

    # Create attestation
    attestation = SurfaceAttestation(
        surface_id="trigguard.spend.transfer",
        code_hash=hash,
        runtime_version="0.2.0",
    )

    # Verify attestation
    valid = verify_attestation(attestation, expected_hash)
"""

from trigguard.attestation.surface_hash import (
    compute_surface_hash,
    compute_module_hash,
    compute_class_hash,
    HashAlgorithm,
)
from trigguard.attestation.attestation import (
    SurfaceAttestation,
    AttestationRegistry,
    AttestationError,
    AttestationMismatchError,
    verify_attestation,
    get_runtime_attestation,
    attest_surface,
    get_surface_attestation,
)
from trigguard.attestation.verifier import (
    SurfaceAttestationVerifier,
    AttestationVerificationError,
    SurfaceNotAttestedError,
    HashMismatchError,
    VerificationResult,
)

__all__ = [
    # Hash computation
    "compute_surface_hash",
    "compute_module_hash",
    "compute_class_hash",
    "HashAlgorithm",
    # Attestation
    "SurfaceAttestation",
    "AttestationRegistry",
    "AttestationError",
    "AttestationMismatchError",
    "verify_attestation",
    "get_runtime_attestation",
    "attest_surface",
    "get_surface_attestation",
    # Verifier
    "SurfaceAttestationVerifier",
    "AttestationVerificationError",
    "SurfaceNotAttestedError",
    "HashMismatchError",
    "VerificationResult",
]
