"""
TrigGuard Executor

Runtime enforcement layer that:
1. Verifies grant signature
2. Checks expiry
3. Validates scope matches
4. Enforces constraints
5. Verifies surface attestation
6. Only then executes the action

This is the execution boundary - the point where authorization
becomes real-world action.

IMPORTANT: The executor does NOT make policy decisions.
It only enforces grants that were already issued.

Architecture:
    DecisionEngine (kernel) → DecisionReceipt → ActionGrant → Executor → Action

The kernel never imports executor. The executor imports grants.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypeVar, Generic
import logging

from trigguard.grants.action_grant import ActionGrant
from trigguard.grants.verifier import ActionGrantVerifier, GrantVerificationResult
from trigguard.grants.errors import (
    GrantExpiredError,
    GrantSignatureError,
    GrantScopeMismatchError,
    GrantConstraintViolationError,
    GrantVerificationError,
)
from trigguard.attestation.verifier import (
    SurfaceAttestationVerifier,
    AttestationVerificationError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ExecutionDeniedError(Exception):
    """Raised when execution is denied due to invalid grant."""

    def __init__(
        self,
        message: str,
        verification_result: Optional[GrantVerificationResult] = None,
    ):
        super().__init__(message)
        self.verification_result = verification_result


@dataclass
class ExecutionResult(Generic[T]):
    """
    Result of an executor.execute() call.

    Fields:
        success: Whether the action executed successfully
        result: Return value of the action (if success)
        error: Exception that occurred (if failure)
        grant_id: ID of the grant used
        executed_at: When execution occurred
        verification_checks: Dict of verification checks performed
    """

    success: bool
    result: Optional[T]
    error: Optional[Exception]
    grant_id: str
    executed_at: datetime
    verification_checks: dict[str, bool]

    @property
    def failed(self) -> bool:
        return not self.success


class TrigGuardExecutor:
    """
    Runtime enforcement layer for Action Grants.

    The executor sits between grant issuance and action execution.
    It verifies every grant before allowing the action to proceed.

    Usage:
        verifier = ActionGrantVerifier(public_key=trusted_key)
        executor = TrigGuardExecutor(verifier)

        # Execute with grant verification
        result = executor.execute(
            grant=grant,
            func=transfer_money,
            surface="SPEND",
            action="transfer_money",
            execution_input={"amount": 100, "currency": "GBP"},
            amount=100,
            currency="GBP",
        )

        if result.success:
            print(f"Transferred: {result.result}")
        else:
            print(f"Denied: {result.error}")
    """

    def __init__(
        self,
        verifier: ActionGrantVerifier,
        *,
        strict_mode: bool = True,
        log_executions: bool = True,
        verify_attestation: bool = False,
        require_attestation: bool = False,
    ):
        """
        Initialize executor with a grant verifier.

        Args:
            verifier: ActionGrantVerifier with trusted public key
            strict_mode: If True, any verification failure raises immediately
            log_executions: If True, log all execution attempts
            verify_attestation: If True, verify surface attestation before execution
            require_attestation: If True, surfaces must have attestation records
        """
        self.verifier = verifier
        self.strict_mode = strict_mode
        self.log_executions = log_executions
        self.verify_attestation = verify_attestation
        self._attestation_verifier = (
            SurfaceAttestationVerifier(
                strict=strict_mode,
                require_attestation=require_attestation,
            )
            if verify_attestation
            else None
        )
        self.log_executions = log_executions

    def execute(
        self,
        grant: ActionGrant,
        func: Callable[..., T],
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> ExecutionResult[T]:
        """
        Execute a function only if the grant is valid.

        Args:
            grant: The ActionGrant to verify
            func: The function to execute
            surface: Expected surface (must match grant)
            action: Expected action (must match grant)
            resource: Expected resource (if applicable)
            execution_input: Input values for constraint checking
            **kwargs: Arguments to pass to func

        Returns:
            ExecutionResult with success/failure and result/error

        Raises:
            ExecutionDeniedError: If strict_mode and grant is invalid
        """
        executed_at = datetime.now(timezone.utc)
        grant_id = str(grant.grant_id)

        if self.log_executions:
            logger.info(
                f"Execution attempt: grant={grant_id}, "
                f"surface={surface}, action={action}"
            )

        # Verify the grant
        verification = self.verifier.verify_grant(
            grant=grant,
            surface=surface,
            action=action,
            resource=resource,
            execution_input=execution_input or {},
        )

        verification_checks = verification.checks if verification else {}

        if not verification.valid:
            error = ExecutionDeniedError(
                f"Grant verification failed: {verification.reason}",
                verification_result=verification,
            )

            if self.log_executions:
                logger.warning(
                    f"Execution denied: grant={grant_id}, "
                    f"reason={verification.reason}"
                )

            if self.strict_mode:
                raise error

            return ExecutionResult(
                success=False,
                result=None,
                error=error,
                grant_id=grant_id,
                executed_at=executed_at,
                verification_checks=verification_checks,
            )

        # Verify surface attestation if enabled
        if self._attestation_verifier:
            try:
                expected_hash = getattr(grant, "surface_hash", None)
                attestation_result = self._attestation_verifier.verify(
                    surface_id=surface,
                    expected_hash=expected_hash,
                )
                verification_checks["attestation_verified"] = attestation_result.valid
                if not attestation_result.valid:
                    error = ExecutionDeniedError(
                        f"Attestation verification failed: {attestation_result.reason}",
                    )
                    if self.strict_mode:
                        raise error
                    return ExecutionResult(
                        success=False,
                        result=None,
                        error=error,
                        grant_id=grant_id,
                        executed_at=executed_at,
                        verification_checks=verification_checks,
                    )
            except AttestationVerificationError as e:
                verification_checks["attestation_verified"] = False
                if self.log_executions:
                    logger.warning(f"Attestation verification failed: {e}")
                raise ExecutionDeniedError(str(e))

        # Grant is valid - execute the action
        try:
            result = func(**kwargs)

            if self.log_executions:
                logger.info(f"Execution succeeded: grant={grant_id}")

            return ExecutionResult(
                success=True,
                result=result,
                error=None,
                grant_id=grant_id,
                executed_at=executed_at,
                verification_checks=verification_checks,
            )

        except Exception as e:
            if self.log_executions:
                logger.error(f"Execution failed: grant={grant_id}, error={e}")

            return ExecutionResult(
                success=False,
                result=None,
                error=e,
                grant_id=grant_id,
                executed_at=executed_at,
                verification_checks=verification_checks,
            )

    def execute_unsafe(
        self,
        grant: ActionGrant,
        func: Callable[..., T],
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> T:
        """
        Execute and return result directly, raising on any failure.

        This is a convenience method for when you want exceptions
        to propagate rather than checking ExecutionResult.

        Raises:
            ExecutionDeniedError: If grant verification fails
            Any exception raised by func
        """
        result = self.execute(
            grant=grant,
            func=func,
            surface=surface,
            action=action,
            resource=resource,
            execution_input=execution_input,
            **kwargs,
        )

        if result.failed:
            if result.error:
                raise result.error
            raise ExecutionDeniedError("Execution failed with no error details")

        return result.result  # type: ignore

    def verify_only(
        self,
        grant: ActionGrant,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
    ) -> GrantVerificationResult:
        """
        Verify a grant without executing anything.

        Useful for pre-flight checks before committing to execution.
        """
        return self.verifier.verify_grant(
            grant=grant,
            surface=surface,
            action=action,
            resource=resource,
            execution_input=execution_input or {},
        )
