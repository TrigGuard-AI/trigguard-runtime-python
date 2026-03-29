"""
TrigGuard Decision Receipts

Auditable records of authorization decisions for compliance and debugging.

Every decision produces a receipt that includes:
- Request details (surface, context)
- Decision outcome (PERMIT, DENY, SILENCE)
- Timing information
- Grant verification status
- Cryptographic proof (optional)

Usage:
    from trigguard.telemetry import DecisionReceipt, ReceiptStore

    # Receipts are generated automatically by the executor
    # Query them for auditing
    store = ReceiptStore.get_default()
    receipts = store.query(
        surface="trigguard.spend.*",
        decision="PERMIT",
        since=datetime(2026, 3, 1),
    )

    for receipt in receipts:
        print(f"{receipt.timestamp}: {receipt.decision} on {receipt.surface_id}")
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Iterator
import hashlib
import json
import uuid
import logging

from trigguard._version import __version__

logger = logging.getLogger(__name__)


class DecisionOutcome(Enum):
    """Possible decision outcomes."""

    PERMIT = "PERMIT"
    DENY = "DENY"
    SILENCE = "SILENCE"


@dataclass
class DecisionReceipt:
    """
    An auditable record of an authorization decision.

    Receipts are immutable once created and include all information
    needed to reconstruct why a decision was made.
    """

    # Identity
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Request details
    surface_id: str = ""
    action: str = ""
    context: Dict[str, Any] = field(default_factory=dict)

    # Decision
    decision: DecisionOutcome = DecisionOutcome.DENY
    reason: Optional[str] = None

    # Grant information
    grant_id: Optional[str] = None
    grant_issuer: Optional[str] = None
    grant_verified: bool = False

    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    decision_time_ms: float = 0.0

    # Risk
    risk_tier: Optional[str] = None

    # Attestation (Surface Attestation Protocol)
    surface_hash: Optional[str] = None  # Code fingerprint: sha256:...
    runtime_version: str = __version__  # TrigGuard runtime version

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Integrity
    _hash: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        """Compute integrity hash after initialization."""
        if self._hash is None:
            self._hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of receipt contents."""
        content = {
            "receipt_id": self.receipt_id,
            "surface_id": self.surface_id,
            "action": self.action,
            "decision": self.decision.value,
            "timestamp": self.timestamp.isoformat(),
            "grant_id": self.grant_id,
            "surface_hash": self.surface_hash,
            "runtime_version": self.runtime_version,
        }
        serialized = json.dumps(content, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()

    @property
    def integrity_hash(self) -> str:
        """Get the integrity hash for this receipt."""
        return self._hash or self._compute_hash()

    def verify_integrity(self) -> bool:
        """Verify that the receipt hasn't been tampered with."""
        return self._hash == self._compute_hash()

    def to_dict(self) -> Dict[str, Any]:
        """Export receipt as dictionary."""
        return {
            "receipt_id": self.receipt_id,
            "surface_id": self.surface_id,
            "action": self.action,
            "context": self.context,
            "decision": self.decision.value,
            "reason": self.reason,
            "grant_id": self.grant_id,
            "grant_issuer": self.grant_issuer,
            "grant_verified": self.grant_verified,
            "timestamp": self.timestamp.isoformat(),
            "decision_time_ms": self.decision_time_ms,
            "risk_tier": self.risk_tier,
            "surface_hash": self.surface_hash,
            "runtime_version": self.runtime_version,
            "metadata": self.metadata,
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionReceipt":
        """Create receipt from dictionary."""
        decision = DecisionOutcome(data.get("decision", "DENY"))
        timestamp = (
            datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.now(timezone.utc)
        )

        return cls(
            receipt_id=data.get("receipt_id", str(uuid.uuid4())),
            surface_id=data.get("surface_id", ""),
            action=data.get("action", ""),
            context=data.get("context", {}),
            decision=decision,
            reason=data.get("reason"),
            grant_id=data.get("grant_id"),
            grant_issuer=data.get("grant_issuer"),
            grant_verified=data.get("grant_verified", False),
            timestamp=timestamp,
            decision_time_ms=data.get("decision_time_ms", 0.0),
            risk_tier=data.get("risk_tier"),
            surface_hash=data.get("surface_hash"),
            runtime_version=data.get("runtime_version", __version__),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ReceiptQuery:
    """Query parameters for receipt search."""

    surface_pattern: Optional[str] = None  # Glob pattern like "trigguard.spend.*"
    decision: Optional[DecisionOutcome] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    grant_issuer: Optional[str] = None
    risk_tier: Optional[str] = None
    limit: int = 100
    offset: int = 0


class ReceiptStore:
    """
    Storage backend for decision receipts.

    Default implementation uses in-memory storage.
    Production deployments should use persistent backends.
    """

    _default_store: Optional["ReceiptStore"] = None

    def __init__(self, max_receipts: int = 10000):
        self._receipts: List[DecisionReceipt] = []
        self._max_receipts = max_receipts
        self._by_id: Dict[str, DecisionReceipt] = {}

    @classmethod
    def get_default(cls) -> "ReceiptStore":
        """Get the default receipt store."""
        if cls._default_store is None:
            cls._default_store = cls()
        return cls._default_store

    @classmethod
    def set_default(cls, store: "ReceiptStore") -> None:
        """Set the default receipt store."""
        cls._default_store = store

    def store(self, receipt: DecisionReceipt) -> None:
        """Store a decision receipt."""
        # Enforce max size (FIFO eviction)
        while len(self._receipts) >= self._max_receipts:
            old = self._receipts.pop(0)
            self._by_id.pop(old.receipt_id, None)

        self._receipts.append(receipt)
        self._by_id[receipt.receipt_id] = receipt
        logger.debug(f"Stored receipt: {receipt.receipt_id}")

    def get(self, receipt_id: str) -> Optional[DecisionReceipt]:
        """Get a receipt by ID."""
        return self._by_id.get(receipt_id)

    def query(
        self,
        surface: Optional[str] = None,
        decision: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[DecisionReceipt]:
        """
        Query receipts with filters.

        Args:
            surface: Surface pattern (supports * wildcard)
            decision: Filter by decision outcome
            since: Only receipts after this time
            until: Only receipts before this time
            limit: Maximum results

        Returns:
            Matching receipts, newest first
        """
        results = []

        for receipt in reversed(self._receipts):
            # Apply filters
            if surface and not self._match_surface(receipt.surface_id, surface):
                continue
            if decision and receipt.decision.value != decision:
                continue
            if since and receipt.timestamp < since:
                continue
            if until and receipt.timestamp > until:
                continue

            results.append(receipt)

            if len(results) >= limit:
                break

        return results

    def _match_surface(self, surface_id: str, pattern: str) -> bool:
        """Check if surface matches pattern (supports * wildcard)."""
        if "*" not in pattern:
            return surface_id == pattern

        # Convert glob to prefix match
        prefix = pattern.rstrip("*").rstrip(".")
        return surface_id.startswith(prefix)

    def count(
        self,
        decision: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> int:
        """Count receipts matching criteria."""
        count = 0
        for receipt in self._receipts:
            if decision and receipt.decision.value != decision:
                continue
            if since and receipt.timestamp < since:
                continue
            count += 1
        return count

    def stats(self) -> Dict[str, Any]:
        """Get receipt statistics."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)

        return {
            "total": len(self._receipts),
            "last_hour": {
                "permit": self.count("PERMIT", hour_ago),
                "deny": self.count("DENY", hour_ago),
                "silence": self.count("SILENCE", hour_ago),
            },
            "last_day": {
                "permit": self.count("PERMIT", day_ago),
                "deny": self.count("DENY", day_ago),
                "silence": self.count("SILENCE", day_ago),
            },
        }

    def export(self, format: str = "json") -> str:
        """Export all receipts."""
        if format == "json":
            return json.dumps([r.to_dict() for r in self._receipts], indent=2)
        elif format == "jsonl":
            return "\n".join(json.dumps(r.to_dict()) for r in self._receipts)
        else:
            raise ValueError(f"Unknown format: {format}")

    def clear(self) -> None:
        """Clear all receipts."""
        self._receipts.clear()
        self._by_id.clear()


def create_receipt(
    surface_id: str,
    decision: DecisionOutcome,
    reason: Optional[str] = None,
    grant_id: Optional[str] = None,
    grant_issuer: Optional[str] = None,
    grant_verified: bool = False,
    decision_time_ms: float = 0.0,
    context: Optional[Dict[str, Any]] = None,
    risk_tier: Optional[str] = None,
) -> DecisionReceipt:
    """
    Create and store a decision receipt.

    Convenience function that creates a receipt and stores it
    in the default store.
    """
    receipt = DecisionReceipt(
        surface_id=surface_id,
        decision=decision,
        reason=reason,
        grant_id=grant_id,
        grant_issuer=grant_issuer,
        grant_verified=grant_verified,
        decision_time_ms=decision_time_ms,
        context=context or {},
        risk_tier=risk_tier,
    )

    ReceiptStore.get_default().store(receipt)
    return receipt
