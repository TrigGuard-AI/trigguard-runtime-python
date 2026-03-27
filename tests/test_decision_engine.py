"""
Test Decision Engine

Validates deterministic pre-execution authorization guarantees.
"""

import sys
from pathlib import Path

# Add kernel root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.decision_contracts import (
    Decision,
    DenyReason,
    ExecutionRequest,
    ExecutionSurface,
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
)
from authority.decision_engine import DecisionEngine


def test_deterministic_same_input_same_output():
    """Same input always yields same decision (determinism guarantee)."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="send_payment",
        surface=ExecutionSurface.SPEND,
        principal_id="user123",
    )

    # Build a signal frame with a high-risk signal
    frame = SignalFrame(request_id=request.request_id)
    frame.add_signal(Signal(
        signal_type=SignalType.PROMPT_OVERRIDE,
        severity=SignalSeverity.HIGH,
        confidence=0.9,
        source="test",
        description="Test override signal",
    ))

    # Run authorization multiple times
    results = []
    for _ in range(5):
        receipt = engine.authorize(request, signal_frame=frame)
        results.append((receipt.decision, receipt.reason))

    # All results must be identical
    assert all(r == results[0] for r in results)
    print("✓ Deterministic: same input yields same output")


def test_high_risk_signal_on_irreversible_surface_denied():
    """High-risk signals on irreversible surfaces produce DENY."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="transfer_funds",
        surface=ExecutionSurface.SPEND,
    )

    frame = SignalFrame(request_id=request.request_id)
    frame.add_signal(Signal(
        signal_type=SignalType.JAILBREAK_ATTEMPT,
        severity=SignalSeverity.CRITICAL,
        confidence=0.85,
        source="jailbreak_detector",
        description="Jailbreak detected",
    ))

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.DENY
    assert receipt.is_denied
    print("✓ High-risk signal on irreversible surface → DENY")


def test_clean_request_permitted():
    """Clean requests with no signals are permitted."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="generate_text",
        surface=ExecutionSurface.GENERATION,
    )

    # Empty signal frame (no threats)
    frame = SignalFrame(request_id=request.request_id)

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.PERMIT
    assert receipt.is_permitted
    print("✓ Clean request → PERMIT")


def test_unknown_surface_fails_closed():
    """Unknown surfaces fail closed (DENY)."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="something_unknown",
        surface=ExecutionSurface.UNKNOWN,
    )

    frame = SignalFrame(request_id=request.request_id)

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.DENY
    assert receipt.reason == DenyReason.SURFACE_NOT_ALLOWED
    print("✓ Unknown surface → DENY (fail closed)")


def test_risk_threshold_exceeded_denied():
    """Risk score exceeding threshold produces DENY."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="call_external_api",
        surface=ExecutionSurface.EXTERNAL_API,  # Tier 2
    )

    # Add multiple signals to exceed threshold
    frame = SignalFrame(request_id=request.request_id)
    frame.add_signal(Signal(
        signal_type=SignalType.PROMPT_OVERRIDE,
        severity=SignalSeverity.HIGH,
        confidence=0.9,
        source="test",
        description="Override 1",
    ))
    frame.add_signal(Signal(
        signal_type=SignalType.TOOL_CALL_ESCALATION,
        severity=SignalSeverity.HIGH,
        confidence=0.85,
        source="test",
        description="Escalation",
    ))

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.DENY
    assert receipt.risk_score > 0.6  # Should exceed tier 2 threshold
    print("✓ Risk threshold exceeded → DENY")


def test_forbidden_signal_on_irreversible_denied():
    """Forbidden signals on irreversible surfaces produce DENY."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="export_data",
        surface=ExecutionSurface.EXPORT,  # Irreversible
    )

    frame = SignalFrame(request_id=request.request_id)
    frame.add_signal(Signal(
        signal_type=SignalType.ROLE_ESCALATION,  # Forbidden on irreversible
        severity=SignalSeverity.HIGH,
        confidence=0.8,
        source="test",
        description="Role escalation attempt",
    ))

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.DENY
    # May be FORBIDDEN_SIGNAL or CONSTRAINT_VIOLATION
    assert receipt.reason in [DenyReason.FORBIDDEN_SIGNAL, DenyReason.CONSTRAINT_VIOLATION]
    print("✓ Forbidden signal on irreversible → DENY")


def test_probing_attack_silenced():
    """Probing attacks get SILENCE response."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="get_info",
        surface=ExecutionSurface.INFERENCE,
    )

    frame = SignalFrame(request_id=request.request_id)
    frame.add_signal(Signal(
        signal_type=SignalType.MODEL_ENUMERATION,
        severity=SignalSeverity.MEDIUM,
        confidence=0.85,
        source="test",
        description="Model probing detected",
    ))

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.SILENCE
    print("✓ Probing attack → SILENCE")


def test_surface_classification():
    """Verify surface classification works correctly."""
    engine = DecisionEngine()

    test_cases = [
        ("send_payment", ExecutionSurface.SPEND),
        ("transfer_money", ExecutionSurface.SPEND),
        ("export_report", ExecutionSurface.EXPORT),
        ("download_file", ExecutionSurface.EXPORT),
        ("run_command", ExecutionSurface.CODE_EXECUTION),
        ("exec_script", ExecutionSurface.CODE_EXECUTION),
        ("delegate_access", ExecutionSurface.DELEGATION),
        ("generate_text", ExecutionSurface.GENERATION),
    ]

    for action, expected_surface in test_cases:
        request = ExecutionRequest(action=action)
        surface = engine.surface_classifier.classify(request)
        assert surface == expected_surface, f"Failed for {action}: got {surface}"

    print("✓ Surface classification working correctly")


def test_decision_receipt_audit_trail():
    """Decision receipts contain proper audit information."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="read_data",
        surface=ExecutionSurface.STATE_READ,
        principal_id="user456",
    )

    frame = SignalFrame(request_id=request.request_id)

    receipt = engine.authorize(request, signal_frame=frame)

    # Check receipt has audit fields
    assert receipt.receipt_id is not None
    assert receipt.request_id == request.request_id
    assert receipt.policy_version == "1.0.0"
    assert receipt.evaluation_time_ms >= 0
    assert receipt.evaluated_at is not None

    # Check audit dict works
    audit = receipt.to_audit_dict()
    assert "decision" in audit
    assert "surface" in audit
    assert "risk_score" in audit

    print("✓ Decision receipt has proper audit trail")


def test_detectors_cannot_bypass_policy():
    """Verify that detector outputs alone cannot produce PERMIT on dangerous surfaces."""
    engine = DecisionEngine()

    # Even with no signals, irreversible surface with unknown classification fails
    request = ExecutionRequest(
        action="do_something_unknown",
        # Surface is UNKNOWN
    )

    frame = SignalFrame(request_id=request.request_id)

    receipt = engine.authorize(request, signal_frame=frame)

    # Should DENY because surface is unknown (fail closed)
    assert receipt.decision == Decision.DENY
    print("✓ Unknown actions fail closed (detectors cannot bypass)")


def test_multiple_constraint_violations():
    """Multiple constraint violations all result in DENY."""
    engine = DecisionEngine()

    request = ExecutionRequest(
        action="delegate_authority",
        surface=ExecutionSurface.DELEGATION,  # Irreversible
    )

    frame = SignalFrame(request_id=request.request_id)
    # Add multiple forbidden signals
    frame.add_signal(Signal(
        signal_type=SignalType.PROMPT_OVERRIDE,
        severity=SignalSeverity.HIGH,
        confidence=0.9,
        source="test",
        description="Override",
    ))
    frame.add_signal(Signal(
        signal_type=SignalType.ROLE_ESCALATION,
        severity=SignalSeverity.CRITICAL,
        confidence=0.95,
        source="test",
        description="Escalation",
    ))

    receipt = engine.authorize(request, signal_frame=frame)

    assert receipt.decision == Decision.DENY
    assert receipt.constraint_violations >= 1
    print("✓ Multiple violations → DENY")


if __name__ == "__main__":
    print("Running Decision Engine Tests\n")
    print("=" * 50)

    test_deterministic_same_input_same_output()
    test_high_risk_signal_on_irreversible_surface_denied()
    test_clean_request_permitted()
    test_unknown_surface_fails_closed()
    test_risk_threshold_exceeded_denied()
    test_forbidden_signal_on_irreversible_denied()
    test_probing_attack_silenced()
    test_surface_classification()
    test_decision_receipt_audit_trail()
    test_detectors_cannot_bypass_policy()
    test_multiple_constraint_violations()

    print("=" * 50)
    print("\n✓ All decision engine tests passed!")
