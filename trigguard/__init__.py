"""
TrigGuard - Execution Authorization Infrastructure for AI Agents

TrigGuard is a deterministic authorization gate that decides whether
automated systems are allowed to execute real-world actions.

Quick Start:
    from trigguard import guard

    @guard(surface="SPEND")
    def transfer_money(amount):
        bank.transfer(amount)

    # TrigGuard will authorize or block the execution
    transfer_money(100)

Core Concepts:
    - gate: The execution gate for checking authorization
    - guard: Decorator for protecting functions
    - ExecutionAdapter: Canonical execution path for protected actions
    - ExecutionSurface: Classification of action types

NO REAL-WORLD ACTION MAY EXECUTE WITHOUT TRIGGUARD AUTHORIZATION.
"""

from trigguard.sdk.gate import gate, guard
from trigguard.sdk.decorators import (
    requires_grant,
    requires_grant_async,
    GrantVerificationError,
    MissingGrantError,
)
from trigguard.core.execution_adapter import (
    ExecutionAdapter,
    execute_if_permitted,
    protected,
    ExecutionDenied,
    FailClosedError,
)
from trigguard.protocol.decision_contracts import ExecutionSurface, Decision
from trigguard.grants.verifier import ActionGrantVerifier
from trigguard.verification.verifier_sdk import TrigGuardVerifierSDK
from trigguard.registry.surface_registry import (
    ExecutionSurfaceRegistry,
    get_global_surface_registry,
)
from trigguard.registry.surface_types import (
    SurfaceRiskTier,
    ExecutionSurfaceDefinition,
)
from trigguard.sdk.agent_integrations import (
    protect_tools,
    protect_tool,
)

__version__ = "0.2.0"

__all__ = [
    # Primary API
    "gate",
    "guard",
    # Grant decorator (simplest integration)
    "requires_grant",
    "requires_grant_async",
    # Agent integrations (protect all tools at once)
    "protect_tools",
    "protect_tool",
    # Execution Adapter
    "ExecutionAdapter",
    "execute_if_permitted",
    "protected",
    # Verification SDK
    "ActionGrantVerifier",
    "TrigGuardVerifierSDK",
    # Surface Registry
    "ExecutionSurfaceRegistry",
    "get_global_surface_registry",
    "SurfaceRiskTier",
    "ExecutionSurfaceDefinition",
    # Exceptions
    "ExecutionDenied",
    "FailClosedError",
    "GrantVerificationError",
    "MissingGrantError",
    # Types
    "ExecutionSurface",
    "Decision",
    # Version
    "__version__",
]
