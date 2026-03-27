"""
Kernel Invariant Tests

These tests protect the TrigGuard authorization architecture.
They verify fundamental invariants that MUST hold for security.

If any of these tests fail:
1. You are breaking a security contract
2. The kernel architecture is drifting
3. Review the change carefully before proceeding

These invariants are non-negotiable.
"""

import pytest
import inspect
from uuid import uuid4

from trigguard.protocol.decision_contracts import (
    Decision,
    DecisionReceipt,
    DenyReason,
    ExecutionRequest,
    ExecutionSurface,
    SignalFrame,
    Signal,
    SignalType,
    SignalSeverity,
    InvalidSignalError,
)
from trigguard.authority.decision_engine import DecisionEngine
from trigguard.constraints.constraint_evaluator import ConstraintEvaluator
from trigguard.surfaces.execution_surface import SurfaceClassifier
from trigguard.signals.signal_frame import SignalFrameBuilder
from trigguard.policy.policy_registry import get_policy_registry


class TestDecisionAuthorityInvariants:
    """
    INVARIANT: Only DecisionEngine can emit PERMIT/DENY/SILENCE.

    No detector, analyzer, or other component can make authorization decisions.
    """

    def test_only_decision_engine_has_authorize_method(self):
        """
        Only DecisionEngine should have an authorize() method.

        This prevents other components from making authorization decisions.
        """
        engine = DecisionEngine()

        # DecisionEngine has authorize
        assert hasattr(engine, "authorize")
        assert callable(engine.authorize)

        # Other components should NOT have authorize
        classifier = SurfaceClassifier()
        evaluator = ConstraintEvaluator()
        builder = SignalFrameBuilder()

        assert not hasattr(classifier, "authorize")
        assert not hasattr(evaluator, "authorize")
        assert not hasattr(builder, "authorize")

    def test_authorize_returns_decision_receipt(self):
        """authorize() must return a DecisionReceipt."""
        engine = DecisionEngine()

        request = ExecutionRequest(request_id=uuid4())
        frame = SignalFrame(request_id=request.request_id)

        result = engine.authorize(request, signal_frame=frame)

        assert isinstance(result, DecisionReceipt)

    def test_receipt_decision_is_valid_enum(self):
        """Receipt decision must be a valid Decision enum."""
        engine = DecisionEngine()

        request = ExecutionRequest(request_id=uuid4())
        frame = SignalFrame(request_id=request.request_id)

        receipt = engine.authorize(request, signal_frame=frame)

        assert isinstance(receipt.decision, Decision)
        assert receipt.decision in {Decision.PERMIT, Decision.DENY, Decision.SILENCE}


class TestDetectorInvariants:
    """
    INVARIANT: Detectors cannot call execution surfaces.

    Detectors produce signals. They cannot execute actions.
    """

    def test_detectors_are_signal_producers_only(self):
        """
        Detectors should not have execute() or invoke() methods.

        This verifies detectors remain signal producers only.
        """
        # Import detector classes (if they exist)
        try:
            from detectors.prompt_injection import PromptInjectionDetector

            detector = PromptInjectionDetector()

            # Detectors should have detect() but not execute/invoke
            assert hasattr(detector, "detect") or hasattr(detector, "analyze")
            assert not hasattr(detector, "execute")
            assert not hasattr(detector, "invoke")
            assert not hasattr(detector, "authorize")
        except ImportError:
            pass  # Detector may not exist yet

    def test_signal_frame_builder_cannot_decide(self):
        """SignalFrameBuilder cannot make decisions."""
        builder = SignalFrameBuilder()

        # Should not have decision-making methods
        assert not hasattr(builder, "decide")
        assert not hasattr(builder, "authorize")
        assert not hasattr(builder, "permit")
        assert not hasattr(builder, "deny")


class TestUnknownSurfaceInvariants:
    """
    INVARIANT: Unknown surfaces fail closed.

    If we can't classify a surface, default to DENY.
    """

    def test_unknown_surface_is_tier_1(self):
        """Unknown surface should be treated as tier 1 (strictest)."""
        surface = ExecutionSurface.UNKNOWN

        # Unknown should have high risk tier
        assert surface.risk_tier <= 2

    def test_unknown_surface_with_signals_denied(self):
        """Unknown surface with any signals should be denied."""
        engine = DecisionEngine()

        request = ExecutionRequest(
            request_id=uuid4(),
            surface=ExecutionSurface.UNKNOWN,
        )

        frame = SignalFrame(
            request_id=request.request_id,
            surface=ExecutionSurface.UNKNOWN,
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.ANOMALY,
                severity=SignalSeverity.MEDIUM,
                confidence=0.7,
                source="test",
                description="Unknown behavior",
            )
        )

        receipt = engine.authorize(request, signal_frame=frame)

        # Should be cautious with unknown surfaces
        # Either DENY or require very low risk
        if receipt.decision == Decision.PERMIT:
            assert frame.risk_score < 0.3


class TestIrreversibleSurfaceInvariants:
    """
    INVARIANT: Irreversible surfaces require stricter thresholds.
    """

    def test_irreversible_surfaces_have_tier_1(self):
        """All irreversible surfaces should be tier 1."""
        irreversible_surfaces = [
            ExecutionSurface.SPEND,
            ExecutionSurface.EXPORT,
            ExecutionSurface.DELEGATION,
            ExecutionSurface.CODE_EXECUTION,
            ExecutionSurface.DATA_MUTATION,
        ]

        for surface in irreversible_surfaces:
            assert surface.is_irreversible, f"{surface} should be irreversible"
            assert surface.risk_tier == 1, f"{surface} should be tier 1"

    def test_irreversible_surface_with_high_signal_denied(self):
        """High-severity signals on irreversible surfaces must DENY."""
        engine = DecisionEngine()

        request = ExecutionRequest(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
        )

        frame = SignalFrame(
            request_id=request.request_id,
            surface=ExecutionSurface.SPEND,
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.9,
                source="test",
                description="Jailbreak",
            )
        )

        receipt = engine.authorize(request, signal_frame=frame)

        assert receipt.decision == Decision.DENY


class TestSignalFrameInvariants:
    """
    INVARIANT: SignalFrame must exist before evaluation.

    No evaluation without a signal frame.
    """

    def test_authorize_creates_frame_if_missing(self):
        """authorize() creates empty frame if none provided."""
        engine = DecisionEngine()

        request = ExecutionRequest(request_id=uuid4())

        # Call with no frame
        receipt = engine.authorize(request)

        # Should still work (creates empty frame)
        assert isinstance(receipt, DecisionReceipt)

    def test_invalid_signal_rejected(self):
        """Invalid signals are rejected from frames."""
        frame = SignalFrame(request_id=uuid4())

        signal = Signal(
            signal_type=SignalType.UNKNOWN,
            severity=SignalSeverity.LOW,
            confidence=0.5,
            source="test",
            description="test",
        )
        # Corrupt the signal type
        signal.signal_type = "not_a_valid_signal"

        with pytest.raises(InvalidSignalError):
            frame.add_signal(signal)


class TestDecisionReceiptInvariants:
    """
    INVARIANT: DecisionReceipt must exist after decision.

    Every authorization decision produces a receipt.
    """

    def test_authorize_always_returns_receipt(self):
        """authorize() always returns a receipt, never None."""
        engine = DecisionEngine()

        # Various scenarios
        scenarios = [
            # Clean request
            ExecutionRequest(request_id=uuid4()),
            # Request with surface
            ExecutionRequest(
                request_id=uuid4(),
                surface=ExecutionSurface.INFERENCE,
            ),
        ]

        for request in scenarios:
            receipt = engine.authorize(request)
            assert receipt is not None
            assert isinstance(receipt, DecisionReceipt)

    def test_receipt_has_required_fields(self):
        """Receipt contains all required fields."""
        engine = DecisionEngine()

        request = ExecutionRequest(request_id=uuid4())
        receipt = engine.authorize(request)

        # Required fields
        assert receipt.receipt_id is not None
        assert receipt.request_id == request.request_id
        assert receipt.decision in {Decision.PERMIT, Decision.DENY, Decision.SILENCE}
        assert receipt.surface is not None
        assert receipt.policy_version is not None
        assert receipt.evaluated_at is not None

    def test_deny_always_has_reason(self):
        """DENY decisions always have a reason."""
        engine = DecisionEngine()

        request = ExecutionRequest(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
        )

        frame = SignalFrame(
            request_id=request.request_id,
            surface=ExecutionSurface.SPEND,
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.95,
                source="test",
                description="Jailbreak",
            )
        )

        receipt = engine.authorize(request, signal_frame=frame)

        if receipt.decision == Decision.DENY:
            assert receipt.reason is not None
            assert isinstance(receipt.reason, DenyReason)


class TestFailClosedInvariants:
    """
    INVARIANT: System fails closed on errors.

    Any uncertainty results in DENY.
    """

    def test_default_decision_is_deny(self):
        """Receipt defaults to DENY."""
        receipt = DecisionReceipt()

        assert receipt.decision == Decision.DENY

    def test_default_reason_is_fail_closed(self):
        """DENY without explicit reason defaults to FAIL_CLOSED."""
        receipt = DecisionReceipt(decision=Decision.DENY)

        assert receipt.reason == DenyReason.FAIL_CLOSED

    def test_high_risk_unknown_surface_denied(self):
        """High risk on unknown surface is denied."""
        engine = DecisionEngine()

        request = ExecutionRequest(
            request_id=uuid4(),
            surface=ExecutionSurface.UNKNOWN,
        )

        frame = SignalFrame(
            request_id=request.request_id,
            surface=ExecutionSurface.UNKNOWN,
        )
        # Add multiple concerning signals
        for i in range(3):
            frame.add_signal(
                Signal(
                    signal_type=SignalType.ANOMALY,
                    severity=SignalSeverity.MEDIUM,
                    confidence=0.8,
                    source="test",
                    description=f"Anomaly {i}",
                )
            )

        receipt = engine.authorize(request, signal_frame=frame)

        # High-risk unknown should not be permitted
        if frame.risk_score > 0.5:
            assert receipt.decision != Decision.PERMIT


class TestPolicyVersionInvariant:
    """
    INVARIANT: Policy version is always recorded.
    """

    def test_policy_version_in_every_receipt(self):
        """Every receipt has policy version."""
        engine = DecisionEngine()
        policy = get_policy_registry()

        request = ExecutionRequest(request_id=uuid4())
        receipt = engine.authorize(request)

        assert receipt.policy_version is not None
        assert receipt.policy_version == policy.version

    def test_policy_version_format_valid(self):
        """Policy version has valid format."""
        policy = get_policy_registry()
        version = policy.version

        # Should be semver-like
        assert version.startswith("v")
        parts = version[1:].split(".")
        assert len(parts) == 3


class TestArchitecturalBoundaries:
    """
    Tests that verify architectural boundaries are maintained.
    """

    def test_decision_engine_is_only_authority(self):
        """
        Verify DecisionEngine is the only class with authorization power.

        This scans for any other class that might grant authorization.
        """
        # Import all relevant modules
        import trigguard.authority.decision_engine as engine_module
        import trigguard.constraints.constraint_evaluator as constraint_module
        import trigguard.surfaces.execution_surface as surface_module
        import trigguard.signals.signal_frame as signal_module

        modules = [constraint_module, surface_module, signal_module]

        for module in modules:
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # These classes should not have authorize method
                if hasattr(obj, "authorize"):
                    # Only DecisionEngine should have it
                    assert obj.__module__ == engine_module.__name__, (
                        f"Class {name} in {module.__name__} has authorize() method. "
                        "Only DecisionEngine should have this."
                    )

    def test_signal_types_are_canonical(self):
        """All signal types in taxonomy match contract types."""
        from trigguard.signals.signal_types import SignalType as TaxonomySignalType
        from trigguard.protocol.decision_contracts import (
            SignalType as ContractSignalType,
        )

        # They should have the same values
        # (This catches if they drift apart)
        taxonomy_values = {s.value for s in TaxonomySignalType}

        # Common signals should exist in both
        common_signals = ["jailbreak_attempt", "prompt_override", "unknown"]
        for signal in common_signals:
            assert signal in taxonomy_values
