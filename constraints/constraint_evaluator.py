"""
Constraint Evaluator

Evaluates constraints against execution requests and signal frames.
Constraints are rules that must be satisfied for execution to be permitted.

Types of constraints:
- Required signals (must be present)
- Forbidden signals (must NOT be present)
- Risk thresholds (score must be below)
- Surface restrictions (certain surfaces not allowed)
- Invariants (system rules that must hold)
"""

from dataclasses import dataclass, field
from typing import Callable, Optional
from uuid import UUID

from protocol.decision_contracts import (
    ConstraintEvaluation,
    ConstraintViolation,
    ConstraintType,
    ExecutionRequest,
    ExecutionSurface,
    SignalFrame,
    SignalType,
    SignalSeverity,
)


@dataclass
class Constraint:
    """A single constraint definition."""
    name: str
    constraint_type: ConstraintType
    evaluator: Callable[[ExecutionRequest, SignalFrame], Optional[ConstraintViolation]]
    description: str = ""
    severity: SignalSeverity = SignalSeverity.HIGH


class ConstraintEvaluator:
    """
    Evaluates all constraints against an execution request.
    
    The evaluator checks:
    1. Required signals are present
    2. Forbidden signals are absent
    3. Risk thresholds are not exceeded
    4. Surface restrictions are respected
    5. System invariants hold
    
    Any violation results in DENY.
    """

    # Default risk thresholds by surface tier
    DEFAULT_RISK_THRESHOLDS = {
        1: 0.3,  # Irreversible surfaces: strict
        2: 0.6,  # Medium-risk surfaces: moderate
        3: 0.8,  # Low-risk surfaces: lenient
    }

    # Signals that are forbidden on irreversible surfaces
    IRREVERSIBLE_FORBIDDEN_SIGNALS = {
        SignalType.PROMPT_OVERRIDE,
        SignalType.JAILBREAK_ATTEMPT,
        SignalType.ROLE_ESCALATION,
        SignalType.DELEGATION_ATTEMPT,
        SignalType.FUNCTION_CALL_INJECTION,
    }

    def __init__(self):
        self._constraints: list[Constraint] = []
        self._setup_default_constraints()

    def _setup_default_constraints(self) -> None:
        """Setup default constraint set."""
        self._constraints = [
            # Forbidden signals on irreversible surfaces
            Constraint(
                name="forbidden_signals_irreversible",
                constraint_type=ConstraintType.FORBIDDEN_SIGNAL,
                evaluator=self._check_forbidden_signals_irreversible,
                description="High-risk signals forbidden on irreversible surfaces",
                severity=SignalSeverity.CRITICAL,
            ),
            # Risk threshold check
            Constraint(
                name="risk_threshold",
                constraint_type=ConstraintType.RISK_THRESHOLD,
                evaluator=self._check_risk_threshold,
                description="Risk score must not exceed surface threshold",
                severity=SignalSeverity.HIGH,
            ),
            # Critical signals always block
            Constraint(
                name="critical_signal_block",
                constraint_type=ConstraintType.FORBIDDEN_SIGNAL,
                evaluator=self._check_critical_signals,
                description="Critical severity signals block execution",
                severity=SignalSeverity.CRITICAL,
            ),
            # Unknown surface fail-closed
            Constraint(
                name="unknown_surface_block",
                constraint_type=ConstraintType.SURFACE_RESTRICTION,
                evaluator=self._check_unknown_surface,
                description="Unknown surfaces are not permitted",
                severity=SignalSeverity.HIGH,
            ),
            # Jailbreak always blocks
            Constraint(
                name="jailbreak_block",
                constraint_type=ConstraintType.INVARIANT,
                evaluator=self._check_jailbreak,
                description="Jailbreak attempts always blocked",
                severity=SignalSeverity.CRITICAL,
            ),
        ]

    def evaluate(
        self,
        request: ExecutionRequest,
        signal_frame: SignalFrame,
    ) -> ConstraintEvaluation:
        """
        Evaluate all constraints against the request and signals.
        
        Args:
            request: The execution request.
            signal_frame: The aggregated signals.
            
        Returns:
            ConstraintEvaluation with any violations found.
        """
        evaluation = ConstraintEvaluation(request_id=request.request_id)

        for constraint in self._constraints:
            violation = constraint.evaluator(request, signal_frame)
            if violation:
                evaluation.violations.append(violation)

        return evaluation

    def add_constraint(self, constraint: Constraint) -> None:
        """Add a custom constraint."""
        self._constraints.append(constraint)

    def _check_forbidden_signals_irreversible(
        self,
        request: ExecutionRequest,
        frame: SignalFrame,
    ) -> Optional[ConstraintViolation]:
        """Check for forbidden signals on irreversible surfaces."""
        if not request.surface.is_irreversible:
            return None

        for signal in frame.signals:
            if signal.signal_type in self.IRREVERSIBLE_FORBIDDEN_SIGNALS:
                return ConstraintViolation(
                    constraint_type=ConstraintType.FORBIDDEN_SIGNAL,
                    constraint_name="forbidden_signals_irreversible",
                    description=f"Signal {signal.signal_type.value} forbidden on {request.surface.value}",
                    severity=SignalSeverity.CRITICAL,
                    metadata={
                        "signal_type": signal.signal_type.value,
                        "surface": request.surface.value,
                        "signal_source": signal.source,
                    },
                )

        return None

    def _check_risk_threshold(
        self,
        request: ExecutionRequest,
        frame: SignalFrame,
    ) -> Optional[ConstraintViolation]:
        """Check if risk score exceeds threshold for this surface."""
        threshold = self.DEFAULT_RISK_THRESHOLDS.get(
            request.surface.risk_tier, 0.5
        )

        if frame.risk_score > threshold:
            return ConstraintViolation(
                constraint_type=ConstraintType.RISK_THRESHOLD,
                constraint_name="risk_threshold",
                description=f"Risk score {frame.risk_score:.2f} exceeds threshold {threshold}",
                severity=SignalSeverity.HIGH,
                metadata={
                    "risk_score": frame.risk_score,
                    "threshold": threshold,
                    "surface_tier": request.surface.risk_tier,
                },
            )

        return None

    def _check_critical_signals(
        self,
        request: ExecutionRequest,
        frame: SignalFrame,
    ) -> Optional[ConstraintViolation]:
        """Any critical severity signal blocks execution."""
        for signal in frame.signals:
            if signal.severity == SignalSeverity.CRITICAL:
                return ConstraintViolation(
                    constraint_type=ConstraintType.FORBIDDEN_SIGNAL,
                    constraint_name="critical_signal_block",
                    description=f"Critical signal detected: {signal.signal_type.value}",
                    severity=SignalSeverity.CRITICAL,
                    metadata={
                        "signal_type": signal.signal_type.value,
                        "source": signal.source,
                        "confidence": signal.confidence,
                    },
                )

        return None

    def _check_unknown_surface(
        self,
        request: ExecutionRequest,
        frame: SignalFrame,
    ) -> Optional[ConstraintViolation]:
        """Unknown surfaces fail closed."""
        if request.surface == ExecutionSurface.UNKNOWN:
            return ConstraintViolation(
                constraint_type=ConstraintType.SURFACE_RESTRICTION,
                constraint_name="unknown_surface_block",
                description="Cannot authorize execution on unknown surface",
                severity=SignalSeverity.HIGH,
                metadata={"action": request.action},
            )

        return None

    def _check_jailbreak(
        self,
        request: ExecutionRequest,
        frame: SignalFrame,
    ) -> Optional[ConstraintViolation]:
        """Jailbreak attempts always blocked."""
        if frame.has_signal_type(SignalType.JAILBREAK_ATTEMPT):
            jailbreak_signals = frame.get_signals_by_type(SignalType.JAILBREAK_ATTEMPT)
            highest_confidence = max(s.confidence for s in jailbreak_signals)
            
            return ConstraintViolation(
                constraint_type=ConstraintType.INVARIANT,
                constraint_name="jailbreak_block",
                description="Jailbreak attempt detected",
                severity=SignalSeverity.CRITICAL,
                metadata={
                    "confidence": highest_confidence,
                    "signal_count": len(jailbreak_signals),
                },
            )

        return None

    def get_risk_threshold(self, surface: ExecutionSurface) -> float:
        """Get the risk threshold for a surface."""
        return self.DEFAULT_RISK_THRESHOLDS.get(surface.risk_tier, 0.5)
