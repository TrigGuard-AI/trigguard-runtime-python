"""
TrigGuard SDK

Drop-in execution gate for protecting automated actions.

Quick Start:
    from sdk import gate, guard

    # Simple check
    decision = gate.check({
        "surface": "SPEND",
        "action": "transfer_funds",
        "arguments": {"amount": 1000}
    })

    if decision.permit:
        transfer_funds()

    # Or use decorator
    @guard(surface="SPEND")
    def transfer_funds(amount: float):
        bank.transfer(amount)

Preferred approach for dangerous actions:
    # For CODE_EXEC, SPEND, DATA_EXPORT, use protected_* functions
    from trigguard.core.protected_actions import protected_code_exec, protected_spend

    result = protected_spend(
        amount=1000,
        recipient="vendor",
        transfer_callable=lambda: bank.transfer(1000),
    )

    result = protected_code_exec(
        code="print('hello')",
        language="python",
        exec_callable=lambda: exec("print('hello')"),
    )

Architecture:
    AI Agent / Application
              ↓
        TrigGuard Gate
              ↓
        PERMIT | DENY
              ↓
        Execute Action

TrigGuard is a deterministic authorization gate for AI actions.
"""

from trigguard.sdk.gate import (
    # Primary API
    gate,
    guard,
    # Classes
    TrigGuardGate,
    GateResult,
    GateDecision,
    GateDeniedError,
    ExecutionRequest,
    GateMetrics,
)
from trigguard.sdk.decorators import (
    requires_grant,
    requires_grant_async,
    GrantVerificationError,
    MissingGrantError,
    is_protected,
    get_protected_surface,
    get_protected_action,
)
from trigguard.sdk.agent_integrations import (
    protect_tools,
    protect_tool,
    infer_surface,
    protect_langchain_tools,
    protect_openai_functions,
    ProtectionResult,
)

__all__ = [
    # Primary API
    "gate",
    "guard",
    # Grant decorator
    "requires_grant",
    "requires_grant_async",
    # Agent integrations
    "protect_tools",
    "protect_tool",
    "infer_surface",
    "protect_langchain_tools",
    "protect_openai_functions",
    "ProtectionResult",
    # Classes
    "TrigGuardGate",
    "GateResult",
    "GateDecision",
    "GateDeniedError",
    "ExecutionRequest",
    "GateMetrics",
    # Decorator exceptions
    "GrantVerificationError",
    "MissingGrantError",
    # Introspection
    "is_protected",
    "get_protected_surface",
    "get_protected_action",
]

__version__ = "0.1.0"
