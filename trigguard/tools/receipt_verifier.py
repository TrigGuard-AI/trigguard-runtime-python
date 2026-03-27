"""
Receipt Verifier

Verifies the cryptographic integrity of DecisionReceipts.

This tool allows operators and auditors to verify that:
- Receipt hashes are valid
- Decisions have not been tampered with
- The chain of trust is intact

Usage:
    verifier = ReceiptVerifier()
    result = verifier.verify(receipt)
    if result.is_valid:
        print("Receipt is authentic")
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Any

from trigguard.protocol.decision_contracts import DecisionReceipt, SignalFrame
from trigguard.protocol.hash_utils import (
    hash_signal_frame,
    hash_decision,
    hash_receipt,
)


class VerificationLevel(str, Enum):
    """Level of verification performed."""

    HASH_ONLY = "hash_only"  # Verify hashes only
    FULL = "full"  # Verify hashes + frame integrity
    WITH_REPLAY = "with_replay"  # Full + replay decision


class ReceiptVerificationStatus(str, Enum):
    """Result of receipt verification."""

    VALID = "valid"
    INVALID_FRAME_HASH = "invalid_frame_hash"
    INVALID_DECISION_HASH = "invalid_decision_hash"
    INVALID_RECEIPT_HASH = "invalid_receipt_hash"
    MISSING_HASHES = "missing_hashes"
    REPLAY_MISMATCH = "replay_mismatch"


@dataclass
class ReceiptVerificationResult:
    """Result of receipt verification."""

    status: ReceiptVerificationStatus
    is_valid: bool
    message: str
    level: VerificationLevel
    checks_performed: list[str]
    checks_failed: list[str]
    details: dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class ReceiptVerifier:
    """
    Verifies the integrity of DecisionReceipts.

    Verification includes:
    1. Frame hash integrity (if frame provided)
    2. Decision hash integrity
    3. Receipt hash integrity (chain verification)

    The verifier does NOT make authorization decisions.
    It only validates that existing receipts are authentic.
    """

    def verify(
        self,
        receipt: DecisionReceipt,
        frame: Optional[SignalFrame] = None,
    ) -> ReceiptVerificationResult:
        """
        Verify a DecisionReceipt.

        Args:
            receipt: The receipt to verify
            frame: Optional SignalFrame for full verification

        Returns:
            ReceiptVerificationResult with status and details
        """
        checks_performed = []
        checks_failed = []

        # Check if receipt has required hashes
        if not receipt.has_valid_hashes:
            return ReceiptVerificationResult(
                status=ReceiptVerificationStatus.MISSING_HASHES,
                is_valid=False,
                message="Receipt is missing required hashes",
                level=VerificationLevel.HASH_ONLY,
                checks_performed=["hash_presence"],
                checks_failed=["hash_presence"],
                details={
                    "frame_hash_present": bool(receipt.frame_hash),
                    "decision_hash_present": bool(receipt.decision_hash),
                    "receipt_hash_present": bool(receipt.receipt_hash),
                },
            )

        # Determine verification level
        level = VerificationLevel.FULL if frame else VerificationLevel.HASH_ONLY

        # 1. Verify frame hash (if frame provided)
        if frame:
            checks_performed.append("frame_hash")
            frame_valid = self._verify_frame_hash(receipt, frame)
            if not frame_valid:
                checks_failed.append("frame_hash")
                return ReceiptVerificationResult(
                    status=ReceiptVerificationStatus.INVALID_FRAME_HASH,
                    is_valid=False,
                    message="Frame hash does not match",
                    level=level,
                    checks_performed=checks_performed,
                    checks_failed=checks_failed,
                    details={
                        "expected_frame_hash": hash_signal_frame(frame)[:16] + "..."
                    },
                )

        # 2. Verify decision hash
        checks_performed.append("decision_hash")
        decision_valid = self._verify_decision_hash(receipt)
        if not decision_valid:
            checks_failed.append("decision_hash")
            return ReceiptVerificationResult(
                status=ReceiptVerificationStatus.INVALID_DECISION_HASH,
                is_valid=False,
                message="Decision hash does not match",
                level=level,
                checks_performed=checks_performed,
                checks_failed=checks_failed,
            )

        # 3. Verify receipt hash (chain)
        checks_performed.append("receipt_hash")
        receipt_valid = self._verify_receipt_hash(receipt)
        if not receipt_valid:
            checks_failed.append("receipt_hash")
            return ReceiptVerificationResult(
                status=ReceiptVerificationStatus.INVALID_RECEIPT_HASH,
                is_valid=False,
                message="Receipt hash chain is invalid",
                level=level,
                checks_performed=checks_performed,
                checks_failed=checks_failed,
            )

        # All checks passed
        return ReceiptVerificationResult(
            status=ReceiptVerificationStatus.VALID,
            is_valid=True,
            message="Receipt verified successfully",
            level=level,
            checks_performed=checks_performed,
            checks_failed=[],
            details={
                "receipt_id": str(receipt.receipt_id),
                "decision": receipt.decision.value,
                "policy_version": receipt.policy_version,
            },
        )

    def _verify_frame_hash(
        self,
        receipt: DecisionReceipt,
        frame: SignalFrame,
    ) -> bool:
        """Verify frame hash matches."""
        expected = hash_signal_frame(frame)
        return receipt.frame_hash == expected

    def _verify_decision_hash(self, receipt: DecisionReceipt) -> bool:
        """Verify decision hash matches."""
        expected = hash_decision(
            decision=receipt.decision,
            reason=receipt.reason,
            surface=receipt.surface,
            risk_score=receipt.risk_score,
            signal_count=receipt.signal_count,
        )
        return receipt.decision_hash == expected

    def _verify_receipt_hash(self, receipt: DecisionReceipt) -> bool:
        """Verify receipt hash chain."""
        expected = hash_receipt(
            request_id=receipt.request_id,
            decision=receipt.decision,
            frame_hash=receipt.frame_hash,
            decision_hash=receipt.decision_hash,
            policy_version=receipt.policy_version,
            timestamp=receipt.evaluated_at,
        )
        return receipt.receipt_hash == expected

    def verify_chain(
        self,
        receipts: list[DecisionReceipt],
    ) -> list[ReceiptVerificationResult]:
        """
        Verify a chain of receipts.

        Useful for batch verification of audit logs.

        Args:
            receipts: List of receipts to verify

        Returns:
            List of verification results
        """
        return [self.verify(receipt) for receipt in receipts]

    def quick_verify(self, receipt: DecisionReceipt) -> bool:
        """
        Quick verification returning just bool.

        Args:
            receipt: Receipt to verify

        Returns:
            True if valid, False otherwise
        """
        result = self.verify(receipt)
        return result.is_valid


def verify_receipt(receipt: DecisionReceipt) -> ReceiptVerificationResult:
    """
    Convenience function to verify a receipt.

    Args:
        receipt: The receipt to verify

    Returns:
        VerificationResult
    """
    verifier = ReceiptVerifier()
    return verifier.verify(receipt)
