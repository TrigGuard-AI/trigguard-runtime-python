"""
TrigGuard Telemetry

Infrastructure metrics tracking for TrigGuard.

The Core Infrastructure Metric:
    Execution Gates Evaluated (Decisions Processed)

This is how infrastructure companies are measured:
    - Cloudflare → requests/sec
    - Stripe → payment volume
    - Datadog → events ingested
    - TrigGuard → gates evaluated

Secondary metrics:
    - Irreversible actions blocked
    - Policy evaluations/sec
    - Decision replay requests
    - Receipts verified
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from threading import Lock
import time


@dataclass
class MetricPoint:
    """A single metric observation."""

    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)


class Counter:
    """Thread-safe counter metric."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._value = 0
        self._lock = Lock()

    def inc(self, amount: int = 1) -> None:
        """Increment counter."""
        with self._lock:
            self._value += amount

    @property
    def value(self) -> int:
        """Current counter value."""
        with self._lock:
            return self._value

    def reset(self) -> None:
        """Reset counter to zero."""
        with self._lock:
            self._value = 0


class Gauge:
    """Thread-safe gauge metric."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._value = 0.0
        self._lock = Lock()

    def set(self, value: float) -> None:
        """Set gauge value."""
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0) -> None:
        """Increment gauge."""
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        """Decrement gauge."""
        with self._lock:
            self._value -= amount

    @property
    def value(self) -> float:
        """Current gauge value."""
        with self._lock:
            return self._value


class Histogram:
    """Simple histogram for latency tracking."""

    def __init__(
        self, name: str, description: str = "", buckets: Optional[List[float]] = None
    ):
        self.name = name
        self.description = description
        self.buckets = buckets or [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        self._counts: Dict[float, int] = {b: 0 for b in self.buckets}
        self._counts[float("inf")] = 0
        self._sum = 0.0
        self._count = 0
        self._lock = Lock()

    def observe(self, value: float) -> None:
        """Record an observation."""
        with self._lock:
            self._sum += value
            self._count += 1
            for bucket in self.buckets:
                if value <= bucket:
                    self._counts[bucket] += 1
            self._counts[float("inf")] += 1

    @property
    def count(self) -> int:
        """Total observations."""
        with self._lock:
            return self._count

    @property
    def sum(self) -> float:
        """Sum of all observations."""
        with self._lock:
            return self._sum

    @property
    def mean(self) -> float:
        """Mean of observations."""
        with self._lock:
            if self._count == 0:
                return 0.0
            return self._sum / self._count


class TrigGuardTelemetry:
    """
    Central telemetry collector for TrigGuard.

    Tracks the key infrastructure metrics that prove
    TrigGuard is becoming core infrastructure.

    Primary Metric:
        gates_evaluated_total

    Secondary Metrics:
        gates_denied_total
        irreversible_blocked_total
        decision_latency_seconds
        policy_version (gauge)
    """

    def __init__(self):
        # THE key metric: execution gates evaluated
        self.gates_evaluated = Counter(
            "trigguard_gates_evaluated_total",
            "Total number of execution gates evaluated",
        )

        # Decision outcomes
        self.decisions_permit = Counter(
            "trigguard_decisions_permit_total",
            "Total PERMIT decisions",
        )
        self.decisions_deny = Counter(
            "trigguard_decisions_deny_total",
            "Total DENY decisions",
        )
        self.decisions_silence = Counter(
            "trigguard_decisions_silence_total",
            "Total SILENCE decisions",
        )

        # Irreversible protection
        self.irreversible_blocked = Counter(
            "trigguard_irreversible_blocked_total",
            "Tier-1 irreversible actions blocked",
        )

        # Surface breakdown
        self._decisions_by_surface: Dict[str, Counter] = {}

        # Latency
        self.decision_latency = Histogram(
            "trigguard_decision_latency_seconds",
            "Decision evaluation latency",
            buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
        )

        # Replay and verification
        self.replays_total = Counter(
            "trigguard_replays_total",
            "Total decision replays performed",
        )
        self.receipts_verified = Counter(
            "trigguard_receipts_verified_total",
            "Total receipts verified",
        )

        # Policy
        self.policy_updates = Counter(
            "trigguard_policy_updates_total",
            "Policy bundle updates applied",
        )

        # Export hooks
        self._export_hooks: List[Callable[["TrigGuardTelemetry"], None]] = []

    def record_decision(
        self,
        surface: str,
        decision: str,
        latency_seconds: float,
        is_irreversible: bool = False,
    ) -> None:
        """
        Record a gate decision.

        This increments the core metric: gates_evaluated_total
        """
        # THE metric
        self.gates_evaluated.inc()

        # Outcome
        if decision == "permit":
            self.decisions_permit.inc()
        elif decision == "deny":
            self.decisions_deny.inc()
            if is_irreversible:
                self.irreversible_blocked.inc()
        elif decision == "silence":
            self.decisions_silence.inc()

        # By surface
        surface_key = surface.lower()
        if surface_key not in self._decisions_by_surface:
            self._decisions_by_surface[surface_key] = Counter(
                f"trigguard_decisions_{surface_key}_total",
                f"Decisions for {surface_key} surface",
            )
        self._decisions_by_surface[surface_key].inc()

        # Latency
        self.decision_latency.observe(latency_seconds)

    def record_replay(self) -> None:
        """Record a decision replay."""
        self.replays_total.inc()

    def record_verification(self) -> None:
        """Record a receipt verification."""
        self.receipts_verified.inc()

    def record_policy_update(self) -> None:
        """Record a policy update."""
        self.policy_updates.inc()

    def add_export_hook(self, hook: Callable[["TrigGuardTelemetry"], None]) -> None:
        """Add a hook for exporting metrics."""
        self._export_hooks.append(hook)

    def export(self) -> Dict[str, Any]:
        """
        Export all metrics as a dictionary.

        This is the data that demonstrates infrastructure adoption.

        Example output:
            {
                "gates_evaluated_total": 1234567,
                "decisions_permit_total": 1200000,
                "decisions_deny_total": 34567,
                "irreversible_blocked_total": 1234,
                "decision_latency_mean_seconds": 0.002,
                ...
            }
        """
        metrics = {
            # THE metric
            "gates_evaluated_total": self.gates_evaluated.value,
            # Outcomes
            "decisions_permit_total": self.decisions_permit.value,
            "decisions_deny_total": self.decisions_deny.value,
            "decisions_silence_total": self.decisions_silence.value,
            # Protection
            "irreversible_blocked_total": self.irreversible_blocked.value,
            # Latency
            "decision_latency_mean_seconds": self.decision_latency.mean,
            "decision_latency_count": self.decision_latency.count,
            # Audit
            "replays_total": self.replays_total.value,
            "receipts_verified_total": self.receipts_verified.value,
            # Policy
            "policy_updates_total": self.policy_updates.value,
            # By surface
            "decisions_by_surface": {
                k: v.value for k, v in self._decisions_by_surface.items()
            },
        }

        # Calculate rates
        total = self.gates_evaluated.value
        if total > 0:
            metrics["permit_rate"] = self.decisions_permit.value / total
            metrics["deny_rate"] = self.decisions_deny.value / total
        else:
            metrics["permit_rate"] = 0.0
            metrics["deny_rate"] = 0.0

        # Run export hooks
        for hook in self._export_hooks:
            try:
                hook(self)
            except Exception:
                pass  # Don't fail metrics export on hook errors

        return metrics

    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        self.gates_evaluated.reset()
        self.decisions_permit.reset()
        self.decisions_deny.reset()
        self.decisions_silence.reset()
        self.irreversible_blocked.reset()
        self._decisions_by_surface.clear()
        self.replays_total.reset()
        self.receipts_verified.reset()
        self.policy_updates.reset()


# Global telemetry instance
_telemetry: Optional[TrigGuardTelemetry] = None
_telemetry_lock = Lock()


def get_telemetry() -> TrigGuardTelemetry:
    """Get the global telemetry instance."""
    global _telemetry
    with _telemetry_lock:
        if _telemetry is None:
            _telemetry = TrigGuardTelemetry()
        return _telemetry


def reset_telemetry() -> None:
    """Reset global telemetry (for testing)."""
    global _telemetry
    with _telemetry_lock:
        _telemetry = None


class DecisionTimer:
    """
    Context manager for timing decision evaluation.

    Usage:
        with DecisionTimer() as timer:
            result = engine.evaluate(frame)

        telemetry.record_decision(
            surface="spend",
            decision="permit",
            latency_seconds=timer.elapsed,
        )
    """

    def __init__(self):
        self.start_time: float = 0
        self.end_time: float = 0

    def __enter__(self) -> "DecisionTimer":
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args) -> None:
        self.end_time = time.perf_counter()

    @property
    def elapsed(self) -> float:
        """Elapsed time in seconds."""
        return self.end_time - self.start_time


__all__ = [
    "TrigGuardTelemetry",
    "get_telemetry",
    "reset_telemetry",
    "Counter",
    "Gauge",
    "Histogram",
    "DecisionTimer",
    "MetricPoint",
]
