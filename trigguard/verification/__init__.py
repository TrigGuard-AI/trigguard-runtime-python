"""
TrigGuard Verification Module

Public key discovery and portable verification SDK for Action Grants.

This module provides:
- PublicKeySet: Key set for public key discovery
- TrigGuardVerifierSDK: Portable verifier for offline grant verification

Usage:
    from trigguard.verification import TrigGuardVerifierSDK, PublicKeySet

    # Load keys from discovery endpoint
    key_set = PublicKeySet.from_dict(response_json)

    # Create verifier SDK
    sdk = TrigGuardVerifierSDK()
    sdk.load_key_set(key_set)

    # Verify grants offline
    result = sdk.verify_grant(grant)
"""

from trigguard.verification.public_keys import (
    PublicKeyRecord,
    PublicKeySet,
    build_public_key_set,
)
from trigguard.verification.verifier_sdk import (
    TrigGuardVerifierSDK,
    VerificationResult,
)

__all__ = [
    "PublicKeyRecord",
    "PublicKeySet",
    "build_public_key_set",
    "TrigGuardVerifierSDK",
    "VerificationResult",
]
