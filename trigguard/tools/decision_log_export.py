"""
TrigGuard Decision Log Export

Export decision logs in JSON Lines format for analysis.

Usage:
    from trigguard.tools.decision_log_export import DecisionLogExporter

    exporter = DecisionLogExporter()
    exporter.export_to_file("decisions.jsonl")

CLI:
    trigguard-audit export-decisions logs.jsonl
"""

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, TextIO
from pathlib import Path

from trigguard.protocol.decision_contracts import DecisionReceipt


@dataclass
class DecisionLogEntry:
    """A single decision log entry."""

    timestamp: str
    request_id: str
    surface: str
    decision: str
    reason: Optional[str]
    policy_version: str
    receipt_hash: str
    frame_hash: str
    signal_count: int
    risk_score: float
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_receipt(
        cls,
        receipt: DecisionReceipt,
        latency_ms: float = 0.0,
    ) -> "DecisionLogEntry":
        """Create log entry from DecisionReceipt."""
        return cls(
            timestamp=receipt.evaluated_at.isoformat(),
            request_id=str(receipt.request_id),
            surface=receipt.surface.value,
            decision=receipt.decision.value,
            reason=receipt.reason.value if receipt.reason else None,
            policy_version=receipt.policy_version,
            receipt_hash=receipt.receipt_hash,
            frame_hash=receipt.frame_hash,
            signal_count=receipt.signal_count,
            risk_score=receipt.risk_score,
            latency_ms=latency_ms,
        )


class DecisionLogExporter:
    """
    Export decision logs to various formats.

    Primary format: JSON Lines (.jsonl)
    - One JSON object per line
    - Streamable and appendable
    - Easy to process with standard tools
    """

    def __init__(self):
        self._buffer: List[DecisionLogEntry] = []

    def add(self, entry: DecisionLogEntry) -> None:
        """Add an entry to the buffer."""
        self._buffer.append(entry)

    def add_receipt(
        self,
        receipt: DecisionReceipt,
        latency_ms: float = 0.0,
    ) -> None:
        """Add a receipt to the buffer."""
        self.add(DecisionLogEntry.from_receipt(receipt, latency_ms))

    def export_to_file(
        self,
        filepath: str,
        append: bool = False,
    ) -> int:
        """
        Export buffered entries to JSON Lines file.

        Args:
            filepath: Output file path
            append: If True, append to existing file

        Returns:
            Number of entries written
        """
        mode = "a" if append else "w"
        count = 0

        with open(filepath, mode) as f:
            for entry in self._buffer:
                f.write(entry.to_json())
                f.write("\n")
                count += 1

        return count

    def export_to_stream(self, stream: TextIO) -> int:
        """Export buffered entries to a stream."""
        count = 0
        for entry in self._buffer:
            stream.write(entry.to_json())
            stream.write("\n")
            count += 1
        return count

    def clear(self) -> None:
        """Clear the buffer."""
        self._buffer.clear()

    @property
    def count(self) -> int:
        """Number of entries in buffer."""
        return len(self._buffer)


def load_decision_log(filepath: str) -> Iterator[DecisionLogEntry]:
    """
    Load decision log entries from JSON Lines file.

    Args:
        filepath: Path to .jsonl file

    Yields:
        DecisionLogEntry objects
    """
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                data = json.loads(line)
                yield DecisionLogEntry(**data)


def analyze_decision_log(filepath: str) -> Dict[str, Any]:
    """
    Analyze a decision log file.

    Args:
        filepath: Path to .jsonl file

    Returns:
        Analysis summary
    """
    total = 0
    by_decision: Dict[str, int] = {}
    by_surface: Dict[str, int] = {}
    latencies: List[float] = []

    for entry in load_decision_log(filepath):
        total += 1

        by_decision[entry.decision] = by_decision.get(entry.decision, 0) + 1
        by_surface[entry.surface] = by_surface.get(entry.surface, 0) + 1
        latencies.append(entry.latency_ms)

    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    sorted_latencies = sorted(latencies)
    p95_latency = (
        sorted_latencies[int(len(sorted_latencies) * 0.95)] if sorted_latencies else 0
    )

    return {
        "total_decisions": total,
        "by_decision": by_decision,
        "by_surface": by_surface,
        "avg_latency_ms": avg_latency,
        "p95_latency_ms": p95_latency,
        "permit_rate": by_decision.get("permit", 0) / total if total else 0,
        "deny_rate": by_decision.get("deny", 0) / total if total else 0,
    }


__all__ = [
    "DecisionLogEntry",
    "DecisionLogExporter",
    "load_decision_log",
    "analyze_decision_log",
]
