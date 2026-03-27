#!/usr/bin/env python3
"""
TrigGuard Quickstart Demo

Demonstrates TrigGuard protecting a dangerous action.

Run with:
    pip install trigguard
    python examples/quickstart.py
"""

from uuid import uuid4

# Import TrigGuard SDK
from trigguard import gate, guard

# =============================================================================
# DEMO 1: Simple Gate Check
# =============================================================================


def demo_simple_gate():
    """Demonstrate simple gate.check() API."""
    print("=" * 60)
    print("DEMO 1: Simple Gate Check")
    print("=" * 60)

    # Define a fake agent action
    def transfer_money(amount: float):
        print(f"  [ACTION] Transferring ${amount}")
        return True

    # Build execution request
    request = {
        "surface": "SPEND",
        "action": "transfer_money",
        "arguments": {"amount": 1000, "currency": "USD"},
    }

    print(f"\nRequest: {request}")

    # Call TrigGuard gate
    decision = gate.check(request)

    print(f"\nDecision: {decision.decision.value.upper()}")
    print(f"Permitted: {decision.permit}")

    if decision.receipt:
        print(f"Receipt hash: {decision.receipt.receipt_hash[:24]}...")

    # Allow or deny execution
    if decision.permit:
        print("\n[PERMITTED] Executing action...")
        transfer_money(1000)
    else:
        print(f"\n[DENIED] Execution blocked: {decision.reason}")

    print()


# =============================================================================
# DEMO 2: Guard Decorator
# =============================================================================


def demo_guard_decorator():
    """Demonstrate @guard decorator."""
    print("=" * 60)
    print("DEMO 2: Guard Decorator")
    print("=" * 60)

    @guard(surface="inference")
    def generate_response(prompt: str) -> str:
        """This function is protected by TrigGuard."""
        return f"AI response to: {prompt}"

    print("\nCalling guarded function...")

    try:
        result = generate_response("Hello, world!")
        print(f"Result: {result}")
    except Exception as e:
        print(f"Blocked: {e}")

    print()


# =============================================================================
# DEMO 3: High-Risk Action with Signals
# =============================================================================


def demo_high_risk_action():
    """Demonstrate high-risk action with signals."""
    print("=" * 60)
    print("DEMO 3: High-Risk Action with Signals")
    print("=" * 60)

    # Request with risk signals - using valid SignalType
    request = {
        "surface": "code_execution",
        "action": "run_shell_command",
        "arguments": {"cmd": "rm -rf /important/data"},
        "signals": [
            {
                "type": "tool_call_escalation",  # Valid SignalType
                "severity": "high",
                "confidence": 0.9,
                "source": "security_analyzer",
                "description": "Dangerous shell command detected",
            }
        ],
    }

    print(f"\nRequest: {request['action']}")
    print(f"Surface: {request['surface']}")
    print(f"Signals: {len(request['signals'])} signal(s)")

    decision = gate.check(request)

    print(f"\nDecision: {decision.decision.value.upper()}")

    if decision.permit:
        print("[WARNING] Dangerous action was permitted!")
    else:
        print(f"[BLOCKED] Action denied: {decision.reason}")

    print()


# =============================================================================
# DEMO 4: Metrics
# =============================================================================


def demo_metrics():
    """Demonstrate telemetry metrics."""
    print("=" * 60)
    print("DEMO 4: Infrastructure Metrics")
    print("=" * 60)

    from telemetry import get_telemetry

    # Run a few evaluations
    for i in range(5):
        gate.check({"surface": "inference", "action": f"test_{i}"})

    telemetry = get_telemetry()
    metrics = telemetry.export()

    print("\nTHE KEY INFRASTRUCTURE METRIC:")
    print(f"  Gates Evaluated: {metrics['gates_evaluated_total']}")
    print()
    print("Secondary Metrics:")
    print(f"  Permits: {metrics['decisions_permit_total']}")
    print(f"  Denies: {metrics['decisions_deny_total']}")
    print(f"  Avg Latency: {metrics['decision_latency_mean_seconds']*1000:.2f}ms")
    print()
    print("Decisions by Surface:")
    for surface, count in metrics["decisions_by_surface"].items():
        print(f"  {surface}: {count}")

    print()


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Run all demos."""
    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          TRIGGUARD QUICKSTART DEMONSTRATION                ║")
    print("║                                                            ║")
    print("║  TrigGuard is a deterministic authorization gate          ║")
    print("║  for AI actions.                                          ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    demo_simple_gate()
    demo_guard_decorator()
    demo_high_risk_action()
    demo_metrics()

    print("=" * 60)
    print("QUICKSTART COMPLETE")
    print("=" * 60)
    print()
    print("Learn more:")
    print("  docs/EXECUTION_GATE_ARCHITECTURE.md")
    print("  docs/THREAT_MODEL.md")
    print()


if __name__ == "__main__":
    main()
