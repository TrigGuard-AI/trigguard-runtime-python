"""
TrigGuard Core

Core components for TrigGuard execution authorization.

NO REAL-WORLD ACTION MAY EXECUTE WITHOUT PASSING THROUGH TRIGGUARD.

Key Components:
    - ExecutionAdapter: Canonical execution layer (execute_if_permitted)
    - protected_*: Wrapped functions for each irreversible surface
    - surfaces: Execution surface classification and risk tiers

Usage:
    from core import execute_if_permitted, protected_spend

    # Protected execution
    result = protected_spend(
        amount=100,
        recipient="vendor",
        transfer_callable=lambda: bank.transfer(100),
    )
"""

from trigguard.core.surfaces import (
    # Surface constants
    SPEND,
    DATA_EXPORT,
    CODE_EXEC,
    DELEGATION,
    IDENTITY_ASSERTION,
    TIME_COMMIT,
    # Surface sets
    IRREVERSIBLE_SURFACES,
    TIER1_SURFACES,
    TIER2_SURFACES,
    TIER3_SURFACES,
    # Functions
    is_irreversible,
    get_risk_tier,
    requires_strict_evaluation,
    parse_surface,
)

from trigguard.core.execution_adapter import (
    # Exceptions
    ExecutionError,
    ExecutionDenied,
    FailClosedError,
    UnguardedExecutionBlocked,
    # Results
    ExecutionResult,
    # Adapter
    ExecutionAdapter,
    get_execution_adapter,
    # Convenience functions
    execute_if_permitted,
    protected,
)

from trigguard.core.protected_actions import (
    # SPEND Surface
    protected_spend,
    protected_payment,
    # DATA_EXPORT Surface
    protected_data_export,
    protected_api_request,
    # CODE_EXECUTION Surface
    protected_code_exec,
    protected_shell_command,
    # DELEGATION Surface
    protected_delegation,
    protected_permission_grant,
    # IDENTITY_ASSERTION Surface
    protected_identity_assertion,
    protected_signature,
    # DATA_MUTATION Surface
    protected_data_mutation,
    protected_delete,
)

__all__ = [
    # Surface constants
    "SPEND",
    "DATA_EXPORT",
    "CODE_EXEC",
    "DELEGATION",
    "IDENTITY_ASSERTION",
    "TIME_COMMIT",
    # Surface sets
    "IRREVERSIBLE_SURFACES",
    "TIER1_SURFACES",
    "TIER2_SURFACES",
    "TIER3_SURFACES",
    # Surface functions
    "is_irreversible",
    "get_risk_tier",
    "requires_strict_evaluation",
    "parse_surface",
    # Execution Adapter
    "ExecutionError",
    "ExecutionDenied",
    "FailClosedError",
    "UnguardedExecutionBlocked",
    "ExecutionResult",
    "ExecutionAdapter",
    "get_execution_adapter",
    "execute_if_permitted",
    "protected",
    # Protected Actions - SPEND
    "protected_spend",
    "protected_payment",
    # Protected Actions - DATA_EXPORT
    "protected_data_export",
    "protected_api_request",
    # Protected Actions - CODE_EXECUTION
    "protected_code_exec",
    "protected_shell_command",
    # Protected Actions - DELEGATION
    "protected_delegation",
    "protected_permission_grant",
    # Protected Actions - IDENTITY_ASSERTION
    "protected_identity_assertion",
    "protected_signature",
    # Protected Actions - DATA_MUTATION
    "protected_data_mutation",
    "protected_delete",
]
