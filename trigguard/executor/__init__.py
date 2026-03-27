"""
TrigGuard Executor

Runtime enforcement layer that verifies Action Grants before execution.

The executor is the boundary between authorization and action.
It ensures that only valid, unexpired grants with matching scope
can trigger real-world actions.

Usage:
    from trigguard.executor import TrigGuardExecutor
    from trigguard.grants import ActionGrantVerifier

    verifier = ActionGrantVerifier(public_key=trusted_key)
    executor = TrigGuardExecutor(verifier)

    # Only executes if grant is valid
    result = executor.execute(
        grant,
        transfer_money,
        amount=100,
        currency="GBP",
    )
"""

from trigguard.executor.executor import TrigGuardExecutor, ExecutionResult

__all__ = [
    "TrigGuardExecutor",
    "ExecutionResult",
]
