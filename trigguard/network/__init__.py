"""
TrigGuard Policy Network Layer

Distributes signed policy bundles to local kernels.

This layer does NOT make authorization decisions.
It only distributes policy intelligence.

Components:
- PolicyBundle: Signed, versioned policy package
- PolicyVerifier: Cryptographic verification
- PolicyClient: Fetches bundles from registry
- UpdateManager: Orchestrates safe updates
"""

from trigguard.network.policy_bundle import (
    PolicyBundle,
    BundleStatus,
    PolicyThreshold,
    PolicyRule,
)
from trigguard.network.policy_verifier import (
    PolicyVerifier,
    VerificationResult,
    VerificationStatus,
    sign_bundle,
    compute_taxonomy_hash,
)
from trigguard.network.policy_client import PolicyClient, FetchResult, FetchStatus
from trigguard.network.update_manager import UpdateManager, UpdateResult, UpdateStatus

__all__ = [
    "PolicyBundle",
    "BundleStatus",
    "PolicyThreshold",
    "PolicyRule",
    "PolicyVerifier",
    "VerificationResult",
    "VerificationStatus",
    "sign_bundle",
    "compute_taxonomy_hash",
    "PolicyClient",
    "FetchResult",
    "FetchStatus",
    "UpdateManager",
    "UpdateResult",
    "UpdateStatus",
]
