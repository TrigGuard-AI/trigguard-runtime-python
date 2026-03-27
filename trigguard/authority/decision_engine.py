"""
Decision Engine

THE SOLE DETERMINISTIC DECISION AUTHORITY.

This is the core of TrigGuard. The Decision Engine is the only component
that can emit authorization decisions (PERMIT / DENY / SILENCE).

No detector, analyzer, or other component can make authorization decisions.
All signals flow TO this engine. Decisions flow OUT.

Flow:
ExecutionRequest
→ Surface Classification
→ Signal Collection
→ Constraint Evaluation
→ Policy Evaluation
→ Decision (PERMIT / DENY / SILENCE)
→ DecisionReceipt
"""

import time
from typing import Any, Optional
from uuid import UUID

from trigguard.protocol.decision_contracts import (
    Decision,
    DecisionReceipt,
    DenyReason,
    ExecutionRequest,
    ExecutionSurface,
    SignalFrame,
    SignalSeverity,
    ConstraintEvaluation,
)
from trigguard.surfaces.execution_surface import SurfaceClassifier
from trigguard.signals.signal_frame import SignalFrameBuilder, SignalAggregator
from trigguard.constraints.constraint_evaluator import ConstraintEvaluator
from trigguard.policy.policy_registry import get_policy_registry, PolicyRegistry


class DecisionEngine:
    """
    The deterministic pre-execution authorization engine.

    This engine:
    1. Classifies the execution surface
    2. Collects and aggregates signals
    3. Evaluates constraints
    4. Makes a deterministic decision
    5. Produces an immutable DecisionReceipt

    GUARANTEES:
    - Same input always yields same decision (deterministic)
    - Detectors cannot bypass this engine
    - High-risk signals on irreversible surfaces produce DENY
    - Missing required signals fail closed (DENY)
    - Only PERMIT / DENY / SILENCE outputs

    Policy is loaded from PolicyRegistry.
    Policy version is embedded in every DecisionReceipt.
    """

    def __init__(
        self,
        surface_classifier: Optional[SurfaceClassifier] = None,
        signal_aggregator: Optional[SignalAggregator] = None,
        constraint_evaluator: Optional[ConstraintEvaluator] = None,
        policy_registry: Optional[PolicyRegistry] = None,
    ):
        self.surface_classifier = surface_classifier or SurfaceClassifier()
        self.signal_aggregator = signal_aggregator or SignalAggregator()
        self.constraint_evaluator = constraint_evaluator or ConstraintEvaluator()
        self.policy = policy_registry or get_policy_registry()

    @property
    def policy_version(self) -> str:
        """Get current policy version from registry."""
        return self.policy.version

    def authorize(
        self,
        request: ExecutionRequest,
        detections: Optional[list[Any]] = None,
        signal_frame: Optional[SignalFrame] = None,
    ) -> DecisionReceipt:
        """
        Authorize an execution request.

        This is the main entry point for authorization decisions.

        Args:
            request: The execution request to authorize.
            detections: Detection objects from detectors (optional).
            signal_frame: Pre-built SignalFrame (optional, takes precedence).

        Returns:
            DecisionReceipt with the deterministic decision.
        """
        start_time = time.perf_counter()

        # Step 1: Classify execution surface
        surface = self.surface_classifier.classify(request)
        request.surface = surface

        # Step 2: Build or use signal frame
        if signal_frame is None:
            if detections:
                signal_frame = self.signal_aggregator.aggregate(
                    request.request_id, detections
                )
            else:
                signal_frame = SignalFrameBuilder.create_empty_frame(request.request_id)

        # Step 3: Evaluate constraints
        constraint_eval = self.constraint_evaluator.evaluate(request, signal_frame)

        # Step 4: Make deterministic decision
        decision, reason = self._make_decision(request, signal_frame, constraint_eval)

        # Step 5: Build receipt
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        receipt = DecisionReceipt(
            request_id=request.request_id,
            decision=decision,
            reason=reason,
            surface=surface,
            risk_score=signal_frame.risk_score,
            signal_count=signal_frame.signal_count,
            constraint_violations=len(constraint_eval.violations),
            signals=list(signal_frame.signals),
            evaluation_time_ms=elapsed_ms,
            policy_version=self.policy_version,
            signals_summary=[
                f"{s.signal_type.value}:{s.severity.value}"
                for s in signal_frame.signals[:5]  # Top 5 signals
            ],
            violations_summary=[
                f"{v.constraint_name}:{v.severity.value}"
                for v in constraint_eval.violations[:5]  # Top 5 violations
            ],
        )

        return receipt

    def _make_decision(
        self,
        request: ExecutionRequest,
        signal_frame: SignalFrame,
        constraint_eval: ConstraintEvaluation,
    ) -> tuple[Decision, Optional[DenyReason]]:
        """
        Make the deterministic authorization decision.

        Decision logic:
        1. If any constraint violated → DENY
        2. If probing attack detected → SILENCE
        3. If risk acceptable → PERMIT
        4. Default → DENY (fail closed)

        This method is deterministic: same inputs always yield same outputs.
        """
        # Rule 1: Constraint violations → DENY
        if not constraint_eval.satisfied:
            # Check for critical violations
            critical = constraint_eval.critical_violations
            if critical:
                return Decision.DENY, DenyReason.CONSTRAINT_VIOLATION

            # Check violation types
            for violation in constraint_eval.violations:
                if violation.constraint_type.value == "forbidden_signal":
                    return Decision.DENY, DenyReason.FORBIDDEN_SIGNAL
                if violation.constraint_type.value == "risk_threshold":
                    return Decision.DENY, DenyReason.RISK_THRESHOLD_EXCEEDED
                if violation.constraint_type.value == "surface_restriction":
                    return Decision.DENY, DenyReason.SURFACE_NOT_ALLOWED
                if violation.constraint_type.value == "invariant":
                    return Decision.DENY, DenyReason.INVARIANT_VIOLATION

            return Decision.DENY, DenyReason.CONSTRAINT_VIOLATION

        # Rule 2: Known probing attacks → SILENCE
        if self._is_probing_attack(signal_frame):
            return Decision.SILENCE, None

        # Rule 3: Irreversible surface with any high signals → DENY
        if request.surface.is_irreversible:
            if signal_frame.max_severity in {
                SignalSeverity.CRITICAL,
                SignalSeverity.HIGH,
            }:
                return Decision.DENY, DenyReason.POLICY_DENIAL

        # Rule 4: Check risk threshold passed
        threshold = self.constraint_evaluator.get_risk_threshold(request.surface)
        if signal_frame.risk_score <= threshold:
            return Decision.PERMIT, None

        # Rule 5: Default fail closed
        return Decision.DENY, DenyReason.FAIL_CLOSED

    def _is_probing_attack(self, signal_frame: SignalFrame) -> bool:
        """
        Detect if this looks like a probing attack.

        Uses SILENCE_TRIGGERS from the policy registry.

        Probing attacks should get SILENCE (no response) to avoid
        leaking information about the system's detection capabilities.
        """
        for signal in signal_frame.signals:
            if self.policy.triggers_silence(signal.signal_type):
                if signal.confidence > 0.7:
                    return True

        return False

    def evaluate_only(
        self,
        request: ExecutionRequest,
        signal_frame: SignalFrame,
    ) -> ConstraintEvaluation:
        """
        Evaluate constraints without making a decision.

        Useful for testing and debugging.
        """
        request.surface = self.surface_classifier.classify(request)
        return self.constraint_evaluator.evaluate(request, signal_frame)
