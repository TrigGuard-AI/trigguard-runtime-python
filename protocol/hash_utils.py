"""
Deterministic Hashing Utilities

Provides cryptographic hashing for SignalFrames, Decisions, and Receipts.

These hashes ensure:
- Same input always produces same hash (deterministic)
- Any change to input produces different hash (tamper-evident)
- Hashes are stable across Python runtime restarts

IMPORTANT: All hashing uses canonical JSON serialization with sorted keys.
"""

import hashlib
import json
from datetime import datetime
from typing import Any, TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from protocol.decision_contracts import (
        SignalFrame,
        Decision,
        DecisionReceipt,
    )


def _to_json_serializable(obj: Any) -> Any:
    """
    Convert an object to JSON-serializable form.
    
    Handles common non-serializable types:
    - UUID -> str
    - datetime -> ISO format string
    - Enum -> value
    """
    if isinstance(obj, UUID):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, "value"):  # Enum
        return obj.value
    elif isinstance(obj, dict):
        return {k: _to_json_serializable(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, (list, tuple)):
        return [_to_json_serializable(item) for item in obj]
    return obj


def _canonical_json(data: dict[str, Any]) -> str:
    """
    Convert dict to canonical JSON string.
    
    Canonical properties:
    - Keys sorted alphabetically at all levels
    - No whitespace between separators
    - ASCII-safe encoding
    - Deterministic ordering
    """
    serializable = _to_json_serializable(data)
    return json.dumps(
        serializable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _sha256_hash(data: str) -> str:
    """
    Compute SHA-256 hash of string data.
    
    Returns lowercase hexadecimal digest.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_signal_frame(frame: "SignalFrame") -> str:
    """
    Compute deterministic hash of a SignalFrame.
    
    The hash covers:
    - request_id
    - surface
    - All signals (in order)
    - metadata
    - timestamp
    
    Args:
        frame: The SignalFrame to hash
        
    Returns:
        SHA-256 hex digest of the canonical representation
    """
    canonical = frame.to_canonical_json()
    return _sha256_hash(canonical)


def hash_decision(
    decision: "Decision",
    reason: Any = None,
    surface: Any = None,
    risk_score: float = 0.0,
    signal_count: int = 0,
) -> str:
    """
    Compute deterministic hash of a decision.
    
    The hash covers the decision outcome and its context:
    - decision (PERMIT/DENY/SILENCE)
    - reason (if DENY)
    - surface
    - risk_score
    - signal_count
    
    Args:
        decision: The Decision enum value
        reason: DenyReason if applicable
        surface: ExecutionSurface
        risk_score: Computed risk score
        signal_count: Number of signals in frame
        
    Returns:
        SHA-256 hex digest
    """
    data = {
        "decision": decision.value if hasattr(decision, "value") else str(decision),
        "reason": reason.value if reason and hasattr(reason, "value") else None,
        "risk_score": round(risk_score, 6),
        "signal_count": signal_count,
        "surface": surface.value if surface and hasattr(surface, "value") else None,
    }
    canonical = _canonical_json(data)
    return _sha256_hash(canonical)


def hash_receipt(
    request_id: UUID,
    decision: "Decision",
    frame_hash: str,
    decision_hash: str,
    policy_version: str,
    timestamp: datetime,
) -> str:
    """
    Compute deterministic hash of a DecisionReceipt.
    
    The receipt hash chains:
    - request_id
    - decision
    - frame_hash (links to SignalFrame)
    - decision_hash (links to decision details)
    - policy_version
    - timestamp
    
    This creates an audit chain where:
    - receipt_hash depends on decision_hash
    - receipt_hash depends on frame_hash
    - Any tampering changes the hash
    
    Args:
        request_id: The original request ID
        decision: The decision outcome
        frame_hash: Hash of the SignalFrame
        decision_hash: Hash of the decision
        policy_version: Version of policy used
        timestamp: When evaluation occurred
        
    Returns:
        SHA-256 hex digest
    """
    data = {
        "decision": decision.value if hasattr(decision, "value") else str(decision),
        "decision_hash": decision_hash,
        "frame_hash": frame_hash,
        "policy_version": policy_version,
        "request_id": str(request_id),
        "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
    }
    canonical = _canonical_json(data)
    return _sha256_hash(canonical)


def verify_receipt_chain(
    frame: "SignalFrame",
    receipt: "DecisionReceipt",
) -> tuple[bool, list[str]]:
    """
    Verify the integrity of a receipt chain.
    
    Checks that:
    - frame_hash matches actual frame
    - decision_hash matches decision details
    - receipt_hash matches recomputed hash
    
    Args:
        frame: The SignalFrame that was evaluated
        receipt: The DecisionReceipt to verify
        
    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors = []
    
    # Verify frame hash
    actual_frame_hash = hash_signal_frame(frame)
    if hasattr(receipt, 'frame_hash') and receipt.frame_hash != actual_frame_hash:
        errors.append(
            f"Frame hash mismatch: expected {receipt.frame_hash}, got {actual_frame_hash}"
        )
    
    # Verify decision hash
    actual_decision_hash = hash_decision(
        decision=receipt.decision,
        reason=receipt.reason,
        surface=receipt.surface,
        risk_score=receipt.risk_score,
        signal_count=receipt.signal_count,
    )
    if hasattr(receipt, 'decision_hash') and receipt.decision_hash != actual_decision_hash:
        errors.append(
            f"Decision hash mismatch: expected {receipt.decision_hash}, got {actual_decision_hash}"
        )
    
    # Verify receipt hash
    if hasattr(receipt, 'frame_hash') and hasattr(receipt, 'decision_hash'):
        actual_receipt_hash = hash_receipt(
            request_id=receipt.request_id,
            decision=receipt.decision,
            frame_hash=receipt.frame_hash,
            decision_hash=receipt.decision_hash,
            policy_version=receipt.policy_version,
            timestamp=receipt.evaluated_at,
        )
        if hasattr(receipt, 'receipt_hash') and receipt.receipt_hash != actual_receipt_hash:
            errors.append(
                f"Receipt hash mismatch: expected {receipt.receipt_hash}, got {actual_receipt_hash}"
            )
    
    return len(errors) == 0, errors


def compute_all_hashes(
    frame: "SignalFrame",
    decision: "Decision",
    reason: Any,
    surface: Any,
    risk_score: float,
    signal_count: int,
    policy_version: str,
    timestamp: datetime,
) -> dict[str, str]:
    """
    Compute all three hashes for a complete decision chain.
    
    Returns dict with:
    - frame_hash
    - decision_hash
    - receipt_hash
    
    This is the typical flow when generating a DecisionReceipt.
    """
    frame_hash = hash_signal_frame(frame)
    
    decision_hash = hash_decision(
        decision=decision,
        reason=reason,
        surface=surface,
        risk_score=risk_score,
        signal_count=signal_count,
    )
    
    receipt_hash = hash_receipt(
        request_id=frame.request_id,
        decision=decision,
        frame_hash=frame_hash,
        decision_hash=decision_hash,
        policy_version=policy_version,
        timestamp=timestamp,
    )
    
    return {
        "frame_hash": frame_hash,
        "decision_hash": decision_hash,
        "receipt_hash": receipt_hash,
    }
