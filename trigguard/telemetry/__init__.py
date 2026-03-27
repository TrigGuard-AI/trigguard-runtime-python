"""
TrigGuard Telemetry

Infrastructure metrics tracking.

The Core Metric:
    gates_evaluated_total - Execution gates evaluated

This is how TrigGuard proves it's infrastructure.

Usage:
    from telemetry import get_telemetry

    telemetry = get_telemetry()
    print(f"Gates evaluated: {telemetry.gates_evaluated.value}")

    # Export all metrics
    metrics = telemetry.export()
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
