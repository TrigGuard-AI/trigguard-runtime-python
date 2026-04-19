"""
TrigGuard Execution Gate SDK

Drop-in integration for protecting automated actions.

Usage:
    from trigguard.sdk.gate import gate, guard

    # Simple check
    decision = gate.check(request)
    if decision.permit:
        execute_action()

    # Decorator middleware
    @guard(surface="CODE_EXEC")
    def run_code():
        ...

This is the primary integration point for TrigGuard.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from uuid import UUID, uuid4
import time

from trigguard.protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionSurface,
    Decision,
    DecisionReceipt,
    ExecutionRequest as ProtocolExecutionRequest,
)
from trigguard.authority.decision_engine import DecisionEngine
from trigguard.policy.policy_registry import get_policy_registry
from trigguard.telemetry.metrics import get_telemetry


class GateDecision(Enum):
    """Simplified decision enum for SDK users."""

    PERMIT = "permit"
    DENY = "deny"
    SILENCE = "silence"


@dataclass
class GateResult:
    """
    Result from an execution gate check.

    This is the primary return type for SDK users.
    Provides simple boolean checks plus full audit trail.
    """

    decision: GateDecision
    request_id: UUID
    surface: ExecutionSurface
    reason: str
    signals: List[Signal] = field(default_factory=list)
    receipt: Optional[DecisionReceipt] = None

    @property
    def permit(self) -> bool:
        """True if action is permitted."""
        return self.decision == GateDecision.PERMIT

    @property
    def deny(self) -> bool:
        """True if action is denied."""
        return self.decision == GateDecision.DENY

    @property
    def silence(self) -> bool:
        """True if action requires human review."""
        return self.decision == GateDecision.SILENCE

    def __bool__(self) -> bool:
        """Gate result is truthy only if permitted."""
        return self.permit


# Surface aliases accepted at ingress.
#
# The map below is the *single ingress-normalization layer* required by
# trigguard-authority docs/governance/SURFACE_RUNTIME_MIGRATION_PLAN.md §12.
# Legacy surface names (and authority-side dot-namespaced canonical names)
# are accepted at this boundary and resolved to the kernel's canonical
# `ExecutionSurface` value. After this layer no legacy name propagates
# downstream — receipts, logs, metrics, traces, and caches MUST contain
# only the canonical enum value.
#
# Three groups:
#   1. Convenience SDK aliases (kernel-internal short names).
#   2. Legacy snake_case execution-surface names from
#      trigguard-authority's migration table (§9h). Mapping rationale per
#      entry below.
#   3. Authority-side dot-namespaced canonical names. The authority advertises
#      `data.export`, `tool.invoke`, `identity.assert`, `authority.delegate`,
#      etc. The kernel accepts those at ingress and resolves them to the
#      kernel's enum value, which is what downstream code uses.
SURFACE_ALIASES = {
    "code_exec": "code_execution",
    "cli": "tool_invocation",
    "api": "external_api",
    "data_export": "export",
    "spend_commit": "spend",
    "time_commit": "data_mutation",
    "social_commit": "unknown",
    "identity_assertion": "identity",
    "data.export": "export",
    "tool.invoke": "tool_invocation",
    "identity.assert": "identity",
    "authority.delegate": "delegation",
}


def discover_surface(surface_or_alias: str) -> Optional[str]:
    """
    Discover and normalize a surface to its canonical ID.

    Uses the global surface registry for alias resolution.

    Args:
        surface_or_alias: Surface name, alias, or ID

    Returns:
        Canonical surface ID or None if not found
    """
    from trigguard.registry.surface_registry import get_global_surface_registry

    registry = get_global_surface_registry()
    surface_def = registry.resolve(surface_or_alias)
    if surface_def:
        return surface_def.surface_id
    return None


def get_surface_risk_tier(surface_or_alias: str) -> Optional[str]:
    """
    Get the risk tier for a surface.

    Args:
        surface_or_alias: Surface name, alias, or ID

    Returns:
        Risk tier string ("low", "medium", "high", "irreversible") or None
    """
    from trigguard.registry.surface_registry import get_global_surface_registry

    registry = get_global_surface_registry()
    tier = registry.get_risk_tier(surface_or_alias)
    return tier.value if tier else None


@dataclass
class ExecutionRequest:
    """
    Request to execute an action through TrigGuard.

    This is the input format for gate.check().
    """

    surface: Union[str, ExecutionSurface]
    action: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[UUID] = None
    signals: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.request_id is None:
            self.request_id = uuid4()
        if isinstance(self.surface, str):
            # Normalize and handle aliases
            surface_str = self.surface.lower().strip()
            surface_str = SURFACE_ALIASES.get(surface_str, surface_str)
            try:
                self.surface = ExecutionSurface(surface_str)
            except ValueError:
                # Fallback to UNKNOWN if not recognized
                self.surface = ExecutionSurface.UNKNOWN


class TrigGuardGate:
    """
    The TrigGuard Execution Gate.

    This is the main entry point for all authorization decisions.
    It sits before any irreversible action and determines
    whether execution is permitted.

    Architecture:
        Agent / Application
              ↓
        TrigGuard.gate.check(request)
              ↓
        PERMIT | DENY | SILENCE
              ↓
        Execute action (or block)

    Usage:
        from trigguard.sdk.gate import gate

        decision = gate.check({
            "surface": "SPEND",
            "action": "transfer_funds",
            "arguments": {"amount": 1000, "currency": "USD"}
        })

        if decision.permit:
            transfer_funds(**args)
        else:
            log_blocked_action(decision)
    """

    def __init__(self):
        self._engine = DecisionEngine()
        self._policy = get_policy_registry()
        self._metrics = GateMetrics()

    def check(
        self,
        request: Union[ExecutionRequest, Dict[str, Any]],
        signals: Optional[List[Signal]] = None,
    ) -> GateResult:
        """
        Check if an execution request is permitted.

        FAIL-CLOSED: If evaluation fails for any reason, execution is DENIED.

        This is the primary API for TrigGuard integration.

        Args:
            request: ExecutionRequest or dict with request details
            signals: Optional pre-computed signals to include

        Returns:
            GateResult with decision and audit trail

        Example:
            result = gate.check({
                "surface": "CODE_EXEC",
                "action": "run_shell_command",
                "arguments": {"cmd": "rm -rf /tmp/cache"}
            })

            if result.permit:
                run_shell_command(cmd)
        """
        try:
            return self._evaluate_request(request, signals)
        except Exception as e:
            # FAIL-CLOSED: Any error results in DENY
            return self._fail_closed(request, str(e))

    def _fail_closed(
        self,
        request: Union[ExecutionRequest, Dict[str, Any]],
        error_message: str,
    ) -> GateResult:
        """
        Return a DENY decision when evaluation fails.

        This is the fail-closed behavior that makes TrigGuard
        safe infrastructure. If we cannot evaluate, we DENY.
        """
        # Normalize request for error response
        if isinstance(request, dict):
            try:
                request = ExecutionRequest(**request)
            except Exception:
                # Can't even parse request, create minimal
                request = ExecutionRequest(surface="unknown", action="unknown")

        reason = f"FAIL_CLOSED: {error_message}"

        # Track the fail-closed decision
        self._metrics.record_decision(
            surface=request.surface,
            decision=Decision.DENY,
            signal_count=0,
        )

        return GateResult(
            decision=GateDecision.DENY,
            request_id=request.request_id,
            surface=request.surface,
            reason=reason,
            signals=[],
            receipt=None,  # No receipt on fail-closed
        )

    def _evaluate_request(
        self,
        request: Union[ExecutionRequest, Dict[str, Any]],
        signals: Optional[List[Signal]] = None,
    ) -> GateResult:
        """
        Internal evaluation logic. Exceptions trigger fail-closed.
        """
        # Normalize SDK request
        if isinstance(request, dict):
            request = ExecutionRequest(**request)

        # Build protocol ExecutionRequest
        protocol_request = ProtocolExecutionRequest(
            request_id=request.request_id,
            action=request.action,
            surface=request.surface,
            parameters=request.arguments,
            metadata=request.context,
        )

        # Build SignalFrame
        frame = SignalFrame(
            request_id=request.request_id,
            surface=request.surface,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "action": request.action,
                "arguments": request.arguments,
                **request.context,
            },
        )

        # Add any pre-computed signals
        if signals:
            for signal in signals:
                frame.add_signal(signal)

        # Add signals from request
        for sig_data in request.signals:
            signal = Signal(
                signal_type=SignalType(
                    sig_data.get("type", sig_data.get("signal_type"))
                ),
                severity=SignalSeverity(sig_data.get("severity", "medium")),
                confidence=sig_data.get("confidence", 0.8),
                source=sig_data.get("source", "request"),
                description=sig_data.get("description", ""),
                evidence=sig_data.get("evidence"),
            )
            frame.add_signal(signal)

        # Authorize with timing
        start_time = time.perf_counter()
        receipt = self._engine.authorize(protocol_request, signal_frame=frame)
        latency = time.perf_counter() - start_time

        # Track local metrics
        self._metrics.record_decision(
            surface=request.surface,
            decision=receipt.decision,
            signal_count=len(frame.signals),
        )

        # Track global telemetry (THE infrastructure metric).
        #
        # `is_irreversible` is sourced from the enum, not a hardcoded set.
        # An earlier hardcoded set leaked legacy surface names
        # (`data_export`, `code_exec`, `identity_assertion`) that never
        # match the post-ingress-normalization canonical values
        # (`export`, `code_execution`, `identity`); the comparison
        # silently never fired. Anti-pattern documented in
        # SURFACE_RUNTIME_MIGRATION_PLAN.md §12.6.
        telemetry = get_telemetry()
        telemetry.record_decision(
            surface=request.surface.value,
            decision=receipt.decision.value,
            latency_seconds=latency,
            is_irreversible=request.surface.is_irreversible,
        )

        # Map to SDK decision
        gate_decision = {
            Decision.PERMIT: GateDecision.PERMIT,
            Decision.DENY: GateDecision.DENY,
            Decision.SILENCE: GateDecision.SILENCE,
        }[receipt.decision]

        # Build reason string
        reason_str = ""
        if receipt.reason:
            reason_str = receipt.reason.value
        elif receipt.violations_summary:
            reason_str = "; ".join(receipt.violations_summary[:3])

        return GateResult(
            decision=gate_decision,
            request_id=request.request_id,
            surface=request.surface,
            reason=reason_str,
            signals=list(frame.signals),
            receipt=receipt,
        )

    def evaluate(
        self,
        surface: Union[str, ExecutionSurface],
        action: str = "",
        **kwargs,
    ) -> GateResult:
        """
        Convenience method for quick evaluation.

        Args:
            surface: Execution surface (SPEND, CODE_EXEC, etc.)
            action: Action name
            **kwargs: Additional context

        Returns:
            GateResult

        Example:
            result = gate.evaluate("SPEND", "transfer", amount=1000)
        """
        return self.check(
            ExecutionRequest(
                surface=surface,
                action=action,
                arguments=kwargs,
            )
        )

    @property
    def metrics(self) -> "GateMetrics":
        """Access gate metrics."""
        return self._metrics

    @property
    def policy_version(self) -> str:
        """Current policy version."""
        return self._policy.version


class GateMetrics:
    """
    Metrics tracking for the execution gate.

    The key infrastructure metric:
    - Execution gates evaluated (decisions processed)

    Secondary metrics:
    - Irreversible actions blocked
    - Decisions per surface
    - Decision replay requests
    """

    def __init__(self):
        self._total_decisions = 0
        self._decisions_by_surface: Dict[str, int] = {}
        self._decisions_by_outcome: Dict[str, int] = {
            "permit": 0,
            "deny": 0,
            "silence": 0,
        }
        self._irreversible_blocked = 0
        # Tier-1 surface set is derived from the enum's `is_irreversible`
        # property to avoid the post-ingress-normalization-leak bug
        # documented in SURFACE_RUNTIME_MIGRATION_PLAN.md §12.6 (the
        # previous hardcoded set used legacy names like `data_export`
        # and `code_exec` that never matched the canonical post-normalized
        # values `export` and `code_execution`, so tier-1-blocked counts
        # never incremented).
        self._tier1_surfaces = {
            s.value.lower() for s in ExecutionSurface if s.is_irreversible
        }

    def record_decision(
        self,
        surface: ExecutionSurface,
        decision: Decision,
        signal_count: int = 0,
    ) -> None:
        """Record a decision for metrics."""
        surface_name = surface.value.lower()
        decision_name = decision.value.lower()

        # Core metric: total decisions
        self._total_decisions += 1

        # By surface
        self._decisions_by_surface[surface_name] = (
            self._decisions_by_surface.get(surface_name, 0) + 1
        )

        # By outcome
        self._decisions_by_outcome[decision_name] += 1

        # Irreversible blocked
        if surface_name in self._tier1_surfaces and decision == Decision.DENY:
            self._irreversible_blocked += 1

    @property
    def total_decisions(self) -> int:
        """Total execution gates evaluated - THE key metric."""
        return self._total_decisions

    @property
    def decisions_by_surface(self) -> Dict[str, int]:
        """Decisions broken down by surface."""
        return dict(self._decisions_by_surface)

    @property
    def decisions_by_outcome(self) -> Dict[str, int]:
        """Decisions broken down by outcome."""
        return dict(self._decisions_by_outcome)

    @property
    def irreversible_blocked(self) -> int:
        """Tier-1 irreversible actions that were blocked."""
        return self._irreversible_blocked

    @property
    def permit_rate(self) -> float:
        """Percentage of decisions that were permits."""
        if self._total_decisions == 0:
            return 0.0
        return self._decisions_by_outcome["permit"] / self._total_decisions

    @property
    def deny_rate(self) -> float:
        """Percentage of decisions that were denies."""
        if self._total_decisions == 0:
            return 0.0
        return self._decisions_by_outcome["deny"] / self._total_decisions

    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as dictionary."""
        return {
            "total_decisions": self._total_decisions,
            "decisions_by_surface": self._decisions_by_surface,
            "decisions_by_outcome": self._decisions_by_outcome,
            "irreversible_blocked": self._irreversible_blocked,
            "permit_rate": self.permit_rate,
            "deny_rate": self.deny_rate,
        }

    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        self._total_decisions = 0
        self._decisions_by_surface.clear()
        self._decisions_by_outcome = {"permit": 0, "deny": 0, "silence": 0}
        self._irreversible_blocked = 0


# Type variable for decorator
F = TypeVar("F", bound=Callable[..., Any])


class GateDeniedError(Exception):
    """Raised when TrigGuard denies execution."""

    def __init__(self, result: GateResult):
        self.result = result
        super().__init__(f"TrigGuard denied execution: {result.reason}")


def guard(
    surface: Union[str, ExecutionSurface],
    *,
    raise_on_deny: bool = True,
    signals: Optional[List[Dict[str, Any]]] = None,
) -> Callable[[F], F]:
    """
    Decorator for guarding function execution with TrigGuard.

    This is the zero-friction integration point.
    Wrap any function that performs an irreversible action.

    NOTE: For CODE_EXEC, SPEND, and other irreversible surfaces,
    prefer using core.protected_actions functions which provide
    additional safety guarantees and audit trails.

    Args:
        surface: Execution surface (SPEND, CODE_EXEC, etc.)
        raise_on_deny: If True, raise GateDeniedError on deny
        signals: Static signals to always include

    Returns:
        Decorated function that checks TrigGuard before execution

    Example:
        @guard(surface="SPEND")
        def transfer_money(amount: float, recipient: str):
            '''This function is protected by TrigGuard.'''
            bank.transfer(amount, recipient)

        # Now calling transfer_money() will first check TrigGuard
        # If denied, raises GateDeniedError
        transfer_money(100.0, "vendor@example.com")

    Preferred approach for CODE_EXEC:
        # Use protected_code_exec from trigguard.core.protected_actions instead
        from trigguard.core.protected_actions import protected_code_exec

        result = protected_code_exec(
            code="print('hello')",
            language="python",
            exec_callable=lambda: exec("print('hello')"),
        )
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Build request from function call
            request = ExecutionRequest(
                surface=surface,
                action=func.__name__,
                arguments=kwargs if kwargs else {"args": args},
                signals=signals or [],
            )

            # Check gate
            result = gate.check(request)

            if result.deny or result.silence:
                if raise_on_deny:
                    raise GateDeniedError(result)
                return result

            # Permitted - execute
            return func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


# Global gate instance - the primary entry point
gate = TrigGuardGate()


# Convenience exports
__all__ = [
    "gate",
    "guard",
    "TrigGuardGate",
    "GateResult",
    "GateDecision",
    "GateDeniedError",
    "ExecutionRequest",
    "GateMetrics",
]
