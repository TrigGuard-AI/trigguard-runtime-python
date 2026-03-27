"""
TrigGuard Executor

Runtime enforcement layer that verifies Action Grants before execution.

The executor is the boundary between authorization and action.
It ensures that only valid, unexpired grants with matching scope
can trigger real-world actions.

This module provides:
- TrigGuardExecutor: Simple executor that wraps verifier
- ExecutionResult: Result of executor.execute()
- ExecutorVerificationContract: Explicit verification before execution
- ExecutorDecision: Decision result with audit fields
- ExecutorExecutionContext: Execution context for logging

Usage (Simple):
    from trigguard.executor import TrigGuardExecutor
    from trigguard.grants import ActionGrantVerifier

    verifier = ActionGrantVerifier(public_key=trusted_key)
    executor = TrigGuardExecutor(verifier)

    result = executor.execute(
        grant,
        transfer_money,
        amount=100,
        currency="GBP",
    )

Usage (Protocol Contract):
    from trigguard.executor import ExecutorVerificationContract
    from trigguard.verification import TrigGuardVerifierSDK

    sdk = TrigGuardVerifierSDK()
    sdk.load_key_set(cached_keys)

    contract = ExecutorVerificationContract(sdk)

    decision = contract.verify_before_execute(
        grant,
        surface="SPEND",
        action="transfer_money",
    )

    if decision.allowed:
        execute_action()
"""

from trigguard.executor.executor import TrigGuardExecutor, ExecutionResult
from trigguard.executor.contract import (
    ExecutorVerificationContract,
    ExecutorDecision,
    ExecutorExecutionContext,
)

__all__ = [
    "TrigGuardExecutor",
    "ExecutionResult",
    "ExecutorVerificationContract",
    "ExecutorDecision",
    "ExecutorExecutionContext",
]
