"""
Decision Replay

Replays authorization decisions to verify determinism.

This tool allows operators to:
- Re-run decisions with the same inputs
- Verify that the same frame produces the same decision
- Detect policy drift or non-determinism
- Audit historical decisions

The replay engine recreates the exact conditions of a decision
and verifies that the outcome matches.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Any
from uuid import UUID

from trigguard.protocol.decision_contracts import (
    Decision,
    DecisionReceipt,
    SignalFrame,
    ExecutionRequest,
    ExecutionSurface,
)
from trigguard.authority.decision_engine import DecisionEngine
from trigguard.policy.policy_registry import PolicyRegistry, get_policy_registry
from trigguard.tools.receipt_verifier import ReceiptVerifier, ReceiptVerificationResult


class ReplayStatus(str, Enum):
    """Result of a decision replay."""

    MATCH = "match"  # Replay matches original
    DECISION_MISMATCH = "decision_mismatch"  # Different decision
    REASON_MISMATCH = "reason_mismatch"  # Same decision, different reason
    POLICY_MISMATCH = "policy_mismatch"  # Different policy version
    HASH_MISMATCH = "hash_mismatch"  # Hashes don't match
    REPLAY_ERROR = "replay_error"  # Error during replay


@dataclass
class ReplayResult:
    """Result of a decision replay."""

    status: ReplayStatus
    matches: bool
    message: str
    original_decision: Decision
    replayed_decision: Decision
    original_policy: str
    replayed_policy: str
    differences: list[str]
    original_receipt: Optional[DecisionReceipt] = None
    replayed_receipt: Optional[DecisionReceipt] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "status": self.status.value,
            "matches": self.matches,
            "message": self.message,
            "original_decision": self.original_decision.value,
            "replayed_decision": self.replayed_decision.value,
            "original_policy": self.original_policy,
            "replayed_policy": self.replayed_policy,
            "differences": self.differences,
        }


class DecisionReplayEngine:
    """
    Replays authorization decisions for verification.

    The replay engine:
    1. Takes a historical SignalFrame and DecisionReceipt
    2. Re-runs the DecisionEngine with the same inputs
    3. Compares the result to the original decision

    This is critical for:
    - Audit compliance
    - Detecting policy drift
    - Verifying determinism guarantees
    - Debugging unexpected decisions

    IMPORTANT: Replay uses the CURRENT policy unless a specific
    policy version is loaded. For historical accuracy, the correct
    policy version must be available.
    """

    def __init__(
        self,
        engine: Optional[DecisionEngine] = None,
        policy_registry: Optional[PolicyRegistry] = None,
    ):
        """
        Initialize replay engine.

        Args:
            engine: DecisionEngine to use for replay
            policy_registry: PolicyRegistry for policy version info
        """
        self.engine = engine or DecisionEngine()
        self.policy_registry = policy_registry or get_policy_registry()
        self.verifier = ReceiptVerifier()

    def replay_decision(
        self,
        frame: SignalFrame,
        original_receipt: Optional[DecisionReceipt] = None,
        expected_policy_version: Optional[str] = None,
    ) -> ReplayResult:
        """
        Replay a decision using a historical SignalFrame.

        Args:
            frame: The original SignalFrame used for the decision
            original_receipt: Optional original receipt for comparison
            expected_policy_version: Expected policy version

        Returns:
            ReplayResult with match status and details
        """
        differences = []

        # Check policy version
        current_policy = self.policy_registry.version
        if expected_policy_version and current_policy != expected_policy_version:
            differences.append(
                f"Policy version mismatch: expected {expected_policy_version}, "
                f"current {current_policy}"
            )

        # Create execution request from frame
        request = ExecutionRequest(
            request_id=frame.request_id,
            surface=frame.surface,
        )

        try:
            # Replay the decision
            replayed_receipt = self.engine.authorize(
                request,
                signal_frame=frame,
            )

            # Compare with original if provided
            if original_receipt:
                return self._compare_decisions(
                    original_receipt,
                    replayed_receipt,
                    differences,
                )
            else:
                # No original to compare, just return the replay
                return ReplayResult(
                    status=ReplayStatus.MATCH,
                    matches=True,
                    message="Decision replayed (no original for comparison)",
                    original_decision=replayed_receipt.decision,
                    replayed_decision=replayed_receipt.decision,
                    original_policy=current_policy,
                    replayed_policy=current_policy,
                    differences=differences,
                    replayed_receipt=replayed_receipt,
                )

        except Exception as e:
            return ReplayResult(
                status=ReplayStatus.REPLAY_ERROR,
                matches=False,
                message=f"Replay error: {str(e)}",
                original_decision=(
                    original_receipt.decision if original_receipt else Decision.DENY
                ),
                replayed_decision=Decision.DENY,
                original_policy=(
                    original_receipt.policy_version if original_receipt else "unknown"
                ),
                replayed_policy=current_policy,
                differences=[f"Error: {str(e)}"],
            )

    def _compare_decisions(
        self,
        original: DecisionReceipt,
        replayed: DecisionReceipt,
        existing_differences: list[str],
    ) -> ReplayResult:
        """Compare original and replayed decisions."""
        differences = list(existing_differences)

        # Check decision match
        if original.decision != replayed.decision:
            differences.append(
                f"Decision mismatch: original={original.decision.value}, "
                f"replayed={replayed.decision.value}"
            )
            return ReplayResult(
                status=ReplayStatus.DECISION_MISMATCH,
                matches=False,
                message="Decision does not match original",
                original_decision=original.decision,
                replayed_decision=replayed.decision,
                original_policy=original.policy_version,
                replayed_policy=replayed.policy_version,
                differences=differences,
                original_receipt=original,
                replayed_receipt=replayed,
            )

        # Check reason match (for DENY)
        if original.decision == Decision.DENY:
            if original.reason != replayed.reason:
                differences.append(
                    f"Reason mismatch: original={original.reason}, "
                    f"replayed={replayed.reason}"
                )
                return ReplayResult(
                    status=ReplayStatus.REASON_MISMATCH,
                    matches=False,
                    message="DENY reason does not match original",
                    original_decision=original.decision,
                    replayed_decision=replayed.decision,
                    original_policy=original.policy_version,
                    replayed_policy=replayed.policy_version,
                    differences=differences,
                    original_receipt=original,
                    replayed_receipt=replayed,
                )

        # Check policy version
        if original.policy_version != replayed.policy_version:
            differences.append(
                f"Policy version changed: original={original.policy_version}, "
                f"replayed={replayed.policy_version}"
            )
            # Policy mismatch is a warning but decision still matches

        # Check hashes (frame hash should match if frame is same)
        if original.frame_hash != replayed.frame_hash:
            differences.append("Frame hash differs")

        # Decisions match
        return ReplayResult(
            status=ReplayStatus.MATCH,
            matches=len(differences) == 0,
            message=(
                "Decision matches original"
                if not differences
                else "Decision matches with notes"
            ),
            original_decision=original.decision,
            replayed_decision=replayed.decision,
            original_policy=original.policy_version,
            replayed_policy=replayed.policy_version,
            differences=differences,
            original_receipt=original,
            replayed_receipt=replayed,
        )

    def verify_and_replay(
        self,
        receipt: DecisionReceipt,
        frame: SignalFrame,
    ) -> tuple[ReceiptVerificationResult, ReplayResult]:
        """
        Verify receipt integrity AND replay the decision.

        This is the most thorough check available.

        Args:
            receipt: Original receipt to verify
            frame: Original frame used for decision

        Returns:
            Tuple of (VerificationResult, ReplayResult)
        """
        # First verify the receipt
        verification = self.verifier.verify(receipt, frame)

        # Then replay
        replay = self.replay_decision(
            frame,
            original_receipt=receipt,
            expected_policy_version=receipt.policy_version,
        )

        return verification, replay

    def batch_replay(
        self,
        frames_and_receipts: list[tuple[SignalFrame, DecisionReceipt]],
    ) -> list[ReplayResult]:
        """
        Replay multiple decisions.

        Args:
            frames_and_receipts: List of (frame, receipt) tuples

        Returns:
            List of ReplayResults
        """
        results = []
        for frame, receipt in frames_and_receipts:
            result = self.replay_decision(
                frame,
                original_receipt=receipt,
                expected_policy_version=receipt.policy_version,
            )
            results.append(result)
        return results


def replay_decision(
    frame: SignalFrame,
    policy_version: Optional[str] = None,
) -> ReplayResult:
    """
    Convenience function to replay a decision.

    Args:
        frame: SignalFrame to replay
        policy_version: Expected policy version

    Returns:
        ReplayResult
    """
    engine = DecisionReplayEngine()
    return engine.replay_decision(frame, expected_policy_version=policy_version)
