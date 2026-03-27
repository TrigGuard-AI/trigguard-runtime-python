"""
TrigGuard Execution Adapter

THE CANONICAL EXECUTION LAYER FOR ALL PROTECTED ACTIONS.

This module provides the single authorized execution path for dangerous
or irreversible actions. All protected actions MUST go through the
ExecutionAdapter to ensure TrigGuard authorization.

Architecture:
    Agent / Application
          ↓
    ExecutionAdapter.execute_if_permitted()
          ↓
    ExecutionGate.evaluate()
          ↓
    DecisionEngine.authorize()
          ↓
    PERMIT → Execute action_callable with receipt attachment
    DENY → Raise ExecutionDenied (action_callable NEVER called)

INVARIANTS:
1. No action executes without passing through ExecutionAdapter
2. ExecutionAdapter ONLY calls ExecutionGate (no custom policy logic)
3. Denied actions NEVER call the underlying callable
4. All execution results are traceable via DecisionReceipt
5. Any failure results in DENY (fail-closed)

WARNING: Do not create alternative execution paths.
WARNING: Do not add permit/deny logic outside DecisionEngine.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from uuid import UUID, uuid4

from trigguard.protocol.decision_contracts import (
    Decision,
    DecisionReceipt,
    ExecutionSurface,
)
from trigguard.sdk.gate import gate, GateResult, ExecutionRequest

logger = logging.getLogger("trigguard.execution_adapter")


# ============================================================================
# Exceptions
# ============================================================================


class ExecutionError(Exception):
    """Base exception for execution errors."""

    pass


class ExecutionDenied(ExecutionError):
    """
    Raised when TrigGuard denies execution.

    This exception carries the full audit trail for logging/debugging.
    The action_callable was NEVER called when this is raised.
    """

    def __init__(
        self,
        result: GateResult,
        surface: Union[str, ExecutionSurface],
        action: str = "",
        message: Optional[str] = None,
    ):
        self.result = result
        self.surface = surface
        self.action = action
        self.receipt = result.receipt
        self.reason = result.reason

        msg = message or (
            f"EXECUTION_DENIED: surface={surface}, action={action}, "
            f"reason={result.reason}"
        )
        super().__init__(msg)


class FailClosedError(ExecutionError):
    """
    Raised when evaluation fails and we fail-closed.

    This indicates a system error, not a policy denial.
    """

    def __init__(
        self,
        surface: Union[str, ExecutionSurface],
        action: str,
        error: Exception,
    ):
        self.surface = surface
        self.action = action
        self.original_error = error

        msg = (
            f"FAIL_CLOSED_EVALUATION_ERROR: surface={surface}, action={action}, "
            f"error={type(error).__name__}: {error}"
        )
        super().__init__(msg)


class UnguardedExecutionBlocked(ExecutionError):
    """
    Raised when code attempts to bypass TrigGuard.

    This is a hard failure indicating an architectural violation.
    """

    def __init__(self, path_description: str):
        msg = f"UNGUARDED_EXECUTION_PATH_BLOCKED: {path_description}"
        super().__init__(msg)


# ============================================================================
# Execution Result
# ============================================================================


@dataclass
class ExecutionResult:
    """
    Result of a permitted and executed action.

    Contains both the action result and full audit trail.
    """

    success: bool
    result: Any
    surface: ExecutionSurface
    action: str
    decision: Decision
    receipt_hash: str
    policy_version: str
    execution_time_ms: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: UUID = field(default_factory=uuid4)

    def to_audit_dict(self) -> Dict[str, Any]:
        """Export for audit logging."""
        return {
            "success": self.success,
            "surface": (
                self.surface.value
                if hasattr(self.surface, "value")
                else str(self.surface)
            ),
            "action": self.action,
            "decision": self.decision.value,
            "receipt_hash": self.receipt_hash,
            "policy_version": self.policy_version,
            "execution_time_ms": self.execution_time_ms,
            "timestamp": self.timestamp.isoformat(),
            "request_id": str(self.request_id),
        }


# ============================================================================
# Execution Adapter
# ============================================================================


class ExecutionAdapter:
    """
    THE CANONICAL EXECUTION LAYER FOR PROTECTED ACTIONS.

    This adapter is the ONLY authorized path for executing dangerous
    or irreversible actions. It:

    1. Builds ExecutionRequest from parameters
    2. Calls ExecutionGate.evaluate()
    3. If DENY: raises ExecutionDenied (callable NEVER executes)
    4. If PERMIT: executes callable and attaches receipt

    CRITICAL INVARIANTS:
    - ExecutionAdapter does NOT invent policy logic
    - ExecutionAdapter ONLY enforces DecisionEngine decisions
    - All execution is traceable via receipt_hash
    - Any error results in DENY (fail-closed)

    Usage:
        adapter = ExecutionAdapter()

        # Execute with protection
        result = adapter.execute_if_permitted(
            surface="SPEND",
            action="transfer_funds",
            action_callable=lambda: bank.transfer(100, "vendor"),
            arguments={"amount": 100, "recipient": "vendor"}
        )

        # Result contains both action result and audit trail
        print(f"Transfer result: {result.result}")
        print(f"Receipt: {result.receipt_hash}")
    """

    def __init__(self):
        # Note: We access gate dynamically via module to support testing/mocking
        self._execution_count = 0
        self._denied_count = 0

    @property
    def _gate(self):
        """Access gate dynamically to support testing."""
        from trigguard.sdk.gate import gate as _gate

        return _gate

    def execute_if_permitted(
        self,
        surface: Union[str, ExecutionSurface],
        action: str,
        action_callable: Callable[..., Any],
        *args,
        arguments: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        signals: Optional[List[Dict[str, Any]]] = None,
        **kwargs,
    ) -> ExecutionResult:
        """
        Execute an action if and only if TrigGuard permits.

        This is THE authorized execution path for protected actions.

        Args:
            surface: Execution surface (SPEND, CODE_EXEC, etc.)
            action: Action identifier
            action_callable: Function to execute if permitted
            *args: Positional arguments for action_callable
            arguments: Optional dict of arguments for audit
            context: Optional execution context
            signals: Optional pre-computed signals
            **kwargs: Keyword arguments for action_callable

        Returns:
            ExecutionResult with action result and audit trail

        Raises:
            ExecutionDenied: If TrigGuard denies execution
            FailClosedError: If evaluation fails

        GUARANTEE: If this method raises ExecutionDenied or FailClosedError,
                   action_callable was NEVER called.
        """
        request_id = uuid4()
        start_time = time.perf_counter()

        # Phase 1: Evaluation (fail-closed on errors)
        try:
            # Build execution request
            request = ExecutionRequest(
                surface=surface,
                action=action,
                arguments=arguments or {},
                context=context or {},
                request_id=request_id,
                signals=signals or [],
            )

            # Evaluate through gate - THIS is where policy is applied
            result = self._gate.check(request)

            # CRITICAL: Check decision
            if not result.permit:
                self._denied_count += 1

                logger.warning(
                    f"EXECUTION_DENIED: surface={surface}, action={action}, "
                    f"reason={result.reason}, request_id={request_id}"
                )

                raise ExecutionDenied(
                    result=result,
                    surface=surface,
                    action=action,
                )

        except ExecutionDenied:
            # Re-raise denial
            raise
        except Exception as e:
            # FAIL-CLOSED: Any error during evaluation = DENY
            logger.error(f"FAIL_CLOSED: surface={surface}, action={action}, error={e}")
            raise FailClosedError(surface, action, e)

        # Phase 2: Execution (permit was granted, let action errors propagate)
        self._execution_count += 1

        try:
            action_result = action_callable(*args, **kwargs)
        except Exception as e:
            # Action execution failed, but TrigGuard permitted
            # Log with receipt for traceability, then let exception propagate
            logger.error(
                f"ACTION_EXECUTION_FAILED: surface={surface}, action={action}, "
                f"receipt_hash={result.receipt.receipt_hash if result.receipt else 'N/A'}, "
                f"error={e}"
            )
            raise  # Let the original exception propagate

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Log successful permitted execution
        receipt_hash = result.receipt.receipt_hash if result.receipt else "N/A"
        policy_version = self._gate.policy_version

        logger.info(
            f"EXECUTION_PERMITTED: surface={surface}, action={action}, "
            f"receipt_hash={receipt_hash}, policy_version={policy_version}"
        )

        return ExecutionResult(
            success=True,
            result=action_result,
            surface=result.surface,
            action=action,
            decision=Decision.PERMIT,
            receipt_hash=receipt_hash,
            policy_version=policy_version,
            execution_time_ms=elapsed_ms,
            request_id=request_id,
        )

    def protected(
        self,
        surface: Union[str, ExecutionSurface],
        action: str = "",
        extract_args: Optional[Callable] = None,
    ) -> Callable:
        """
        Decorator for protecting functions with TrigGuard.

        Args:
            surface: Execution surface
            action: Action name (default: function name)
            extract_args: Optional function to extract arguments for audit

        Returns:
            Decorator function

        Example:
            adapter = ExecutionAdapter()

            @adapter.protected(surface="SPEND", action="transfer")
            def transfer_money(amount: float, recipient: str):
                return bank.transfer(amount, recipient)

            # Calling transfer_money now goes through TrigGuard
            result = transfer_money(100.0, "vendor@example.com")
        """

        def decorator(func: Callable) -> Callable:
            func_action = action or func.__name__

            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract arguments for audit logging
                if extract_args:
                    arguments = extract_args(*args, **kwargs)
                else:
                    arguments = kwargs.copy()

                # Create a closure that captures args and kwargs
                def bound_callable():
                    return func(*args, **kwargs)

                return self.execute_if_permitted(
                    surface=surface,
                    action=func_action,
                    action_callable=bound_callable,
                    arguments=arguments,
                )

            return wrapper

        return decorator

    @property
    def stats(self) -> Dict[str, int]:
        """Get execution statistics."""
        return {
            "executions": self._execution_count,
            "denials": self._denied_count,
        }


# ============================================================================
# Global Adapter Instance
# ============================================================================

_adapter: Optional[ExecutionAdapter] = None


def get_execution_adapter() -> ExecutionAdapter:
    """Get the global ExecutionAdapter instance."""
    global _adapter
    if _adapter is None:
        _adapter = ExecutionAdapter()
    return _adapter


def execute_if_permitted(
    surface: Union[str, ExecutionSurface],
    action: str,
    action_callable: Callable[..., Any],
    *args,
    **kwargs,
) -> ExecutionResult:
    """
    Convenience function for protected execution.

    Uses the global ExecutionAdapter instance.

    Example:
        from trigguard.core.execution_adapter import execute_if_permitted

        result = execute_if_permitted(
            surface="SPEND",
            action="transfer",
            action_callable=lambda: bank.transfer(100),
            arguments={"amount": 100}
        )
    """
    return get_execution_adapter().execute_if_permitted(
        surface=surface,
        action=action,
        action_callable=action_callable,
        *args,
        **kwargs,
    )


def protected(
    surface: Union[str, ExecutionSurface],
    action: str = "",
) -> Callable:
    """
    Convenience decorator for protected functions.

    Example:
        from trigguard.core.execution_adapter import protected

        @protected(surface="CODE_EXEC")
        def run_code(code: str):
            exec(code)
    """
    return get_execution_adapter().protected(surface=surface, action=action)


__all__ = [
    # Exceptions
    "ExecutionError",
    "ExecutionDenied",
    "FailClosedError",
    "UnguardedExecutionBlocked",
    # Results
    "ExecutionResult",
    # Adapter
    "ExecutionAdapter",
    "get_execution_adapter",
    # Convenience functions
    "execute_if_permitted",
    "protected",
]
