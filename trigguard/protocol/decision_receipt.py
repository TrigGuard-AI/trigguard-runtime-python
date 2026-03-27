"""
Decision Receipt Generator

Factory for creating DecisionReceipts with cryptographic integrity.

This module provides the canonical way to create receipts:
1. generate_receipt(frame, decision, ...) → DecisionReceipt

DO NOT create DecisionReceipts directly. Always use generate_receipt()
to ensure proper hash computation.
"""

from datetime import datetime
from typing import Optional, Any
from uuid import uuid4

from trigguard.protocol.decision_contracts import (
    DecisionReceipt,
    Decision,
    DenyReason,
    ExecutionSurface,
    Signal,
    SignalFrame,
)
from trigguard.protocol.hash_utils import (
    hash_signal_frame,
    hash_decision,
    hash_receipt,
)


def generate_receipt(
    frame: SignalFrame,
    decision: Decision,
    reason: Optional[DenyReason] = None,
    policy_version: str = "1.0.0",
    constraint_violations: int = 0,
    violations_summary: Optional[list[str]] = None,
    evaluation_time_ms: float = 0.0,
    metadata: Optional[dict[str, Any]] = None,
) -> DecisionReceipt:
    """
    Generate a DecisionReceipt with cryptographic integrity.

    This is the ONLY way to create a valid DecisionReceipt.
    Direct instantiation of DecisionReceipt will not have proper hashes.

    Args:
        frame: The SignalFrame that was evaluated
        decision: The authorization decision (PERMIT/DENY/SILENCE)
        reason: Reason for DENY decisions
        policy_version: Version of policy used for evaluation
        constraint_violations: Number of constraint violations found
        violations_summary: Summary of violations (top N)
        evaluation_time_ms: Time taken to evaluate
        metadata: Additional metadata to include

    Returns:
        DecisionReceipt with computed hashes

    Example:
        >>> frame = SignalFrame(request_id=uuid4())
        >>> receipt = generate_receipt(frame, Decision.PERMIT)
        >>> assert receipt.has_valid_hashes
    """
    # Set defaults
    if violations_summary is None:
        violations_summary = []
    if metadata is None:
        metadata = {}

    # Current timestamp
    evaluated_at = datetime.utcnow()

    # Compute frame hash
    frame_hash = hash_signal_frame(frame)

    # Compute decision hash
    decision_hash = hash_decision(
        decision=decision,
        reason=reason,
        surface=frame.surface,
        risk_score=frame.risk_score,
        signal_count=frame.signal_count,
    )

    # Compute receipt hash (chains frame + decision)
    receipt_hash = hash_receipt(
        request_id=frame.request_id,
        decision=decision,
        frame_hash=frame_hash,
        decision_hash=decision_hash,
        policy_version=policy_version,
        timestamp=evaluated_at,
    )

    # Create signals summary
    signals_summary = [
        f"{s.signal_type.value}:{s.severity.value}" for s in frame.signals[:5]  # Top 5
    ]

    # Create receipt
    receipt = DecisionReceipt(
        receipt_id=uuid4(),
        request_id=frame.request_id,
        decision=decision,
        reason=reason,
        surface=frame.surface,
        risk_score=frame.risk_score,
        signal_count=frame.signal_count,
        constraint_violations=constraint_violations,
        signals=list(frame.signals),
        frame_hash=frame_hash,
        decision_hash=decision_hash,
        receipt_hash=receipt_hash,
        evaluated_at=evaluated_at,
        evaluation_time_ms=evaluation_time_ms,
        policy_version=policy_version,
        signals_summary=signals_summary,
        violations_summary=violations_summary,
        metadata=metadata,
    )

    # Freeze the receipt to prevent modification
    receipt.freeze()

    return receipt


def verify_receipt(
    receipt: DecisionReceipt,
    frame: SignalFrame,
) -> tuple[bool, list[str]]:
    """
    Verify the integrity of a receipt against the original frame.

    This recomputes all hashes and compares them.
    Any mismatch indicates tampering or corruption.

    Args:
        receipt: The receipt to verify
        frame: The original SignalFrame

    Returns:
        Tuple of (is_valid, list of error messages)

    Example:
        >>> receipt = generate_receipt(frame, Decision.PERMIT)
        >>> is_valid, errors = verify_receipt(receipt, frame)
        >>> assert is_valid
    """
    return receipt.verify_integrity(frame)


def receipt_from_dict(data: dict[str, Any]) -> DecisionReceipt:
    """
    Reconstruct a DecisionReceipt from a dictionary.

    This is for deserializing receipts from storage.
    The receipt should be verified against the original frame
    after reconstruction.

    Args:
        data: Dictionary from receipt.to_canonical_dict() or storage

    Returns:
        DecisionReceipt (unfrozen, for verification)
    """
    from uuid import UUID
    from datetime import datetime

    return DecisionReceipt(
        receipt_id=UUID(data["receipt_id"]),
        request_id=UUID(data["request_id"]),
        decision=Decision(data["decision"]),
        reason=DenyReason(data["reason"]) if data.get("reason") else None,
        surface=ExecutionSurface(data["surface"]),
        risk_score=data["risk_score"],
        signal_count=data["signal_count"],
        constraint_violations=data.get("constraint_violations", 0),
        frame_hash=data.get("frame_hash", ""),
        decision_hash=data.get("decision_hash", ""),
        receipt_hash=data.get("receipt_hash", ""),
        evaluated_at=datetime.fromisoformat(data["evaluated_at"]),
        evaluation_time_ms=data.get("evaluation_time_ms", 0.0),
        policy_version=data.get("policy_version", "1.0.0"),
        signals_summary=data.get("signals_summary", []),
        violations_summary=data.get("violations_summary", []),
        metadata=data.get("metadata", {}),
    )
