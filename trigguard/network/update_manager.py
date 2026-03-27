"""
Update Manager

Orchestrates safe policy updates for the TrigGuard kernel.

The UpdateManager ensures:
- Kernel continues using existing policy until verification passes
- Failed verification aborts update
- PolicyRegistry loads only verified bundles
- Rollback on activation failure

IMPORTANT:
- Never interrupt decision-making during updates
- Always verify before activation
- Always have fallback to local policy
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable, Any

from trigguard.network.policy_bundle import PolicyBundle, BundleStatus
from trigguard.network.policy_client import PolicyClient, FetchResult, FetchStatus
from trigguard.network.policy_verifier import (
    PolicyVerifier,
    VerificationResult,
    VerificationStatus,
    compute_taxonomy_hash,
)

logger = logging.getLogger(__name__)


class UpdateStatus(str, Enum):
    """Status of an update operation."""

    IDLE = "idle"
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    ACTIVATING = "activating"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLBACK = "rollback"


@dataclass
class UpdateResult:
    """Result of an update operation."""

    status: UpdateStatus
    success: bool
    message: str
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    bundle: Optional[PolicyBundle] = None
    error: Optional[str] = None


@dataclass
class UpdateState:
    """Current state of the update manager."""

    status: UpdateStatus = UpdateStatus.IDLE
    current_version: Optional[str] = None
    pending_bundle: Optional[PolicyBundle] = None
    last_check: Optional[datetime] = None
    last_update: Optional[datetime] = None
    consecutive_failures: int = 0


class UpdateManager:
    """
    Manages safe policy updates for the kernel.

    Update flow:
    1. check_for_updates() - Check if new policy available
    2. download_bundle() - Fetch the bundle
    3. verify_bundle() - Cryptographic verification
    4. activate_policy() - Load into PolicyRegistry

    Safety guarantees:
    - Kernel uses existing policy until new one is fully verified
    - Any failure aborts and keeps existing policy
    - Automatic rollback on activation failure
    """

    MAX_CONSECUTIVE_FAILURES = 5

    def __init__(
        self,
        client: Optional[PolicyClient] = None,
        verifier: Optional[PolicyVerifier] = None,
        policy_activator: Optional[Callable[[PolicyBundle], bool]] = None,
        kernel_version: str = "1.0.0",
    ):
        """
        Initialize update manager.

        Args:
            client: PolicyClient for fetching bundles
            verifier: PolicyVerifier for verification
            policy_activator: Callback to activate policy in registry
            kernel_version: Current kernel version
        """
        self.client = client or PolicyClient()

        # Compute local taxonomy hash for compatibility checking
        self.taxonomy_hash = compute_taxonomy_hash()
        self.kernel_version = kernel_version

        self.verifier = verifier or PolicyVerifier(
            local_taxonomy_hash=self.taxonomy_hash,
            kernel_version=kernel_version,
        )

        self.policy_activator = policy_activator
        self.state = UpdateState()

        # History for debugging
        self._update_history: list[UpdateResult] = []

    @property
    def current_status(self) -> UpdateStatus:
        """Get current update status."""
        return self.state.status

    def check_for_updates(self) -> Optional[str]:
        """
        Check if a policy update is available.

        Returns:
            New version string if available, None otherwise
        """
        self.state.status = UpdateStatus.CHECKING
        self.state.last_check = datetime.utcnow()

        try:
            current = self.state.current_version or "v0.0.0"
            new_version = self.client.check_for_update(current)

            if new_version:
                logger.info(f"Update available: {current} → {new_version}")
                return new_version

            logger.debug("No updates available")
            self.state.status = UpdateStatus.IDLE
            return None

        except Exception as e:
            logger.error(f"Update check failed: {e}")
            self.state.status = UpdateStatus.FAILED
            self.state.consecutive_failures += 1
            return None

    def download_bundle(self, version: Optional[str] = None) -> Optional[PolicyBundle]:
        """
        Download a policy bundle.

        Args:
            version: Specific version to download, or None for latest

        Returns:
            Downloaded bundle or None on failure
        """
        self.state.status = UpdateStatus.DOWNLOADING

        try:
            if version:
                result = self.client.fetch_policy(version)
            else:
                result = self.client.fetch_latest_policy()

            if not result.success:
                logger.error(f"Download failed: {result.message}")
                self.state.status = UpdateStatus.FAILED
                self.state.consecutive_failures += 1
                return None

            self.state.pending_bundle = result.bundle
            logger.info(f"Downloaded bundle version {result.bundle.version}")
            return result.bundle

        except Exception as e:
            logger.error(f"Download error: {e}")
            self.state.status = UpdateStatus.FAILED
            self.state.consecutive_failures += 1
            return None

    def verify_bundle(
        self,
        bundle: Optional[PolicyBundle] = None,
    ) -> VerificationResult:
        """
        Verify a policy bundle.

        Args:
            bundle: Bundle to verify, or use pending bundle

        Returns:
            VerificationResult
        """
        self.state.status = UpdateStatus.VERIFYING

        bundle = bundle or self.state.pending_bundle
        if not bundle:
            return VerificationResult(
                status=VerificationStatus.INVALID_HASH,
                is_valid=False,
                message="No bundle to verify",
            )

        try:
            result = self.verifier.verify_bundle(bundle)

            if not result.is_valid:
                logger.error(f"Verification failed: {result.message}")
                self.state.status = UpdateStatus.FAILED
                self.state.consecutive_failures += 1
                self.state.pending_bundle = None
            else:
                logger.info(f"Bundle {bundle.version} verified successfully")

            return result

        except Exception as e:
            logger.error(f"Verification error: {e}")
            self.state.status = UpdateStatus.FAILED
            self.state.consecutive_failures += 1
            return VerificationResult(
                status=VerificationStatus.INVALID_HASH,
                is_valid=False,
                message=f"Verification error: {str(e)}",
            )

    def activate_policy(
        self,
        bundle: Optional[PolicyBundle] = None,
    ) -> UpdateResult:
        """
        Activate a verified policy bundle.

        Args:
            bundle: Bundle to activate, or use pending bundle

        Returns:
            UpdateResult with success/failure details
        """
        self.state.status = UpdateStatus.ACTIVATING

        bundle = bundle or self.state.pending_bundle
        if not bundle:
            return UpdateResult(
                status=UpdateStatus.FAILED,
                success=False,
                message="No bundle to activate",
            )

        # Verify bundle is verified
        if bundle.status != BundleStatus.VERIFIED:
            return UpdateResult(
                status=UpdateStatus.FAILED,
                success=False,
                message=f"Bundle not verified (status: {bundle.status})",
            )

        old_version = self.state.current_version

        try:
            # Freeze bundle before activation
            bundle.freeze()

            # Call activator if provided
            if self.policy_activator:
                success = self.policy_activator(bundle)
                if not success:
                    raise RuntimeError("Policy activation callback failed")

            # Mark as active
            bundle.set_status(BundleStatus.ACTIVE)

            # Update state
            self.state.current_version = bundle.version
            self.state.pending_bundle = None
            self.state.last_update = datetime.utcnow()
            self.state.consecutive_failures = 0
            self.state.status = UpdateStatus.COMPLETED

            result = UpdateResult(
                status=UpdateStatus.COMPLETED,
                success=True,
                message=f"Policy updated from {old_version} to {bundle.version}",
                old_version=old_version,
                new_version=bundle.version,
                bundle=bundle,
            )

            self._update_history.append(result)
            logger.info(result.message)

            return result

        except Exception as e:
            logger.error(f"Activation failed: {e}")
            self.state.status = UpdateStatus.ROLLBACK
            self.state.consecutive_failures += 1

            result = UpdateResult(
                status=UpdateStatus.FAILED,
                success=False,
                message=f"Activation failed: {str(e)}",
                old_version=old_version,
                error=str(e),
            )

            self._update_history.append(result)
            return result

    def perform_update(self, version: Optional[str] = None) -> UpdateResult:
        """
        Perform a complete update cycle.

        Downloads, verifies, and activates a policy bundle.

        Args:
            version: Specific version to update to, or None for latest

        Returns:
            UpdateResult
        """
        # Check if too many consecutive failures
        if self.state.consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
            return UpdateResult(
                status=UpdateStatus.FAILED,
                success=False,
                message=f"Too many consecutive failures ({self.state.consecutive_failures})",
            )

        # Step 1: Download
        bundle = self.download_bundle(version)
        if not bundle:
            return UpdateResult(
                status=UpdateStatus.FAILED,
                success=False,
                message="Download failed",
            )

        # Step 2: Verify
        verification = self.verify_bundle(bundle)
        if not verification.is_valid:
            return UpdateResult(
                status=UpdateStatus.FAILED,
                success=False,
                message=f"Verification failed: {verification.message}",
            )

        # Step 3: Activate
        return self.activate_policy(bundle)

    def get_update_history(self) -> list[UpdateResult]:
        """Get history of update attempts."""
        return list(self._update_history)

    def reset_failure_count(self) -> None:
        """Reset consecutive failure counter."""
        self.state.consecutive_failures = 0

    def set_current_version(self, version: str) -> None:
        """Set current policy version (for initialization)."""
        self.state.current_version = version
