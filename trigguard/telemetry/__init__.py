"""
TrigGuard Telemetry

Infrastructure metrics tracking and decision receipts.

The Core Metric:
    gates_evaluated_total - Execution gates evaluated

Decision Receipts:
    Auditable records of every authorization decision.

Usage:
    from telemetry import get_telemetry

    telemetry = get_telemetry()
    print(f"Gates evaluated: {telemetry.gates_evaluated.value}")

    # Export all metrics
    metrics = telemetry.export()

    # Query decision receipts
    from trigguard.telemetry import ReceiptStore
    store = ReceiptStore.get_default()
    receipts = store.query(surface="trigguard.spend.*")
"""

from trigguard.telemetry.metrics import (
    TrigGuardTelemetry,
    get_telemetry,
    reset_telemetry,
    Counter,
    Gauge,
    Histogram,
    DecisionTimer,
    MetricPoint,
)
from trigguard.telemetry.receipts import (
    DecisionReceipt,
    DecisionOutcome,
    ReceiptStore,
    ReceiptQuery,
    create_receipt,
)

__all__ = [
    # Metrics
    "TrigGuardTelemetry",
    "get_telemetry",
    "reset_telemetry",
    "Counter",
    "Gauge",
    "Histogram",
    "DecisionTimer",
    "MetricPoint",
    # Receipts
    "DecisionReceipt",
    "DecisionOutcome",
    "ReceiptStore",
    "ReceiptQuery",
    "create_receipt",
]
