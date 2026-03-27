"""
Executor Verification Contract

Explicit verification contract for executor-side grant validation.

This module defines how an executor should verify Action Grants
before performing any real-world action.

The contract:
1. Receives an ActionGrant
2. Verifies via VerifierSDK
3. If invalid: denies execution
4. If valid: produces ExecutorDecision allowing execution
5. Includes audit-safe fields for logging and forensics

This is the boundary between authorization and execution.

Usage:
    from trigguard.executor.contract import ExecutorVerificationContract
    from trigguard.verification import TrigGuardVerifierSDK

    # Setup
    sdk = TrigGuardVerifierSDK()
    sdk.load_key_set(cached_keys)
    contract = ExecutorVerificationContract(sdk)

    # Before executing any action
    decision = contract.verify_before_execute(
        grant,
        surface="SPEND",
        action="transfer_money",
        execution_input={"amount": 100},
    )

    if decision.allowed:
        execute_the_action()
        log_audit(decision.to_audit_dict())
    else:
        reject(decision.reason)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from trigguard.grants.action_grant import ActionGrant
from trigguard.verification.verifier_sdk import TrigGuardVerifierSDK, VerificationResult


@dataclass
class ExecutorDecision:
    """
    Decision from executor verification contract.

    This is what the contract produces after verifying a grant.

    Fields:
        allowed: Whether execution is allowed
        reason: Human-readable explanation
        grant_id: ID of the grant (for audit)
        receipt_hash: Hash of origin receipt (for audit)
        decision_hash: Hash of origin decision (for audit)
        verified_at: When verification occurred
        issuer: Grant issuer
        kid: Key ID used for verification
        checks: Verification check details
    """

    allowed: bool
    reason: str
    grant_id: Optional[str] = None
    receipt_hash: Optional[str] = None
    decision_hash: Optional[str] = None
    verified_at: Optional[str] = None
    issuer: Optional[str] = None
    kid: Optional[str] = None
    checks: dict[str, Any] = field(default_factory=dict)

    def to_audit_dict(self) -> dict[str, Any]:
        """
        Convert to audit-safe dictionary.

        This can be logged for forensics and compliance.
        Does not include sensitive execution details.
        """
        return {
            "allowed": self.allowed,
            "decision_hash": self.decision_hash,
            "grant_id": self.grant_id,
            "issuer": self.issuer,
            "kid": self.kid,
            "reason": self.reason,
            "receipt_hash": self.receipt_hash,
            "verified_at": self.verified_at,
        }

    @classmethod
    def allow(
        cls,
        grant: ActionGrant,
        kid: Optional[str] = None,
        checks: Optional[dict[str, Any]] = None,
    ) -> "ExecutorDecision":
        """Create an allow decision from a verified grant."""
        return cls(
            allowed=True,
            reason="Grant verified successfully",
            grant_id=str(grant.grant_id),
            receipt_hash=grant.receipt_hash,
            decision_hash=grant.decision_hash,
            verified_at=datetime.now(timezone.utc).isoformat(),
            issuer=grant.issuer,
            kid=kid,
            checks=checks or {},
        )

    @classmethod
    def deny(
        cls,
        reason: str,
        grant: Optional[ActionGrant] = None,
        checks: Optional[dict[str, Any]] = None,
    ) -> "ExecutorDecision":
        """Create a deny decision."""
        return cls(
            allowed=False,
            reason=reason,
            grant_id=str(grant.grant_id) if grant else None,
            receipt_hash=grant.receipt_hash if grant else None,
            decision_hash=grant.decision_hash if grant else None,
            verified_at=datetime.now(timezone.utc).isoformat(),
            issuer=grant.issuer if grant else None,
            kid=None,
            checks=checks or {},
        )


@dataclass
class ExecutorExecutionContext:
    """
    Execution context for an action.

    Captures what is being executed and under what grant.

    Fields:
        surface: Execution surface
        action: Action being executed
        resource: Target resource (if applicable)
        execution_input: Parameters for execution
        grant: The ActionGrant authorizing execution
        decision: The ExecutorDecision from verification
    """

    surface: str
    action: str
    resource: Optional[str]
    execution_input: dict[str, Any]
    grant: ActionGrant
    decision: ExecutorDecision

    def to_audit_dict(self) -> dict[str, Any]:
        """
        Convert to audit-safe dictionary.

        Includes context without sensitive execution details.
        """
        return {
            "action": self.action,
            "decision": self.decision.to_audit_dict(),
            "grant_id": str(self.grant.grant_id),
            "resource": self.resource,
            "surface": self.surface,
        }


class ExecutorVerificationContract:
    """
    Verification contract for executor-side grant validation.

    This contract defines the explicit steps an executor must perform
    before executing any action:

    1. Receive ActionGrant
    2. Verify signature (offline)
    3. Verify expiry
    4. Verify scope matches execution context
    5. Verify constraints are satisfied
    6. Produce ExecutorDecision

    The contract is stateless - it does not track grants or executions.
    It only verifies and produces decisions.

    Usage:
        contract = ExecutorVerificationContract(verifier_sdk)

        decision = contract.verify_before_execute(
            grant,
            surface="SPEND",
            action="transfer_money",
            execution_input={"amount": 100},
        )

        if decision.allowed:
            # Safe to execute
            execute_action()
        else:
            # Do not execute
            log_rejection(decision)
    """

    def __init__(self, verifier_sdk: TrigGuardVerifierSDK) -> None:
        """
        Initialize the contract with a verifier SDK.

        Args:
            verifier_sdk: Configured TrigGuardVerifierSDK with loaded keys
        """
        self._sdk = verifier_sdk

    def verify_before_execute(
        self,
        grant: ActionGrant,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
        kid: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ExecutorDecision:
        """
        Verify a grant before execution.

        This is the primary contract method. Call this before
        executing any action to get an ExecutorDecision.

        Args:
            grant: ActionGrant to verify
            surface: Execution surface
            action: Action to execute
            resource: Target resource (optional)
            execution_input: Execution parameters for constraint checking
            kid: Key ID for verification (optional)
            now: Current time (for testing)

        Returns:
            ExecutorDecision - check .allowed before executing
        """
        result = self._sdk.verify_grant_and_scope(
            grant,
            surface=surface,
            action=action,
            resource=resource,
            execution_input=execution_input or {},
            kid=kid,
            now=now,
        )

        if result.valid:
            return ExecutorDecision.allow(
                grant=grant,
                kid=result.kid,
                checks=result.checks,
            )
        else:
            return ExecutorDecision.deny(
                reason=result.reason,
                grant=grant,
                checks=result.checks,
            )

    def build_execution_context(
        self,
        grant: ActionGrant,
        decision: ExecutorDecision,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
        execution_input: Optional[dict[str, Any]] = None,
    ) -> ExecutorExecutionContext:
        """
        Build an execution context for audit purposes.

        This captures the full context of an execution for logging.

        Args:
            grant: The ActionGrant
            decision: The ExecutorDecision from verification
            surface: Execution surface
            action: Action
            resource: Resource
            execution_input: Execution parameters

        Returns:
            ExecutorExecutionContext
        """
        return ExecutorExecutionContext(
            surface=surface,
            action=action,
            resource=resource,
            execution_input=execution_input or {},
            grant=grant,
            decision=decision,
        )

    def to_audit_dict(
        self,
        grant: ActionGrant,
        decision: ExecutorDecision,
        *,
        surface: str,
        action: str,
        resource: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create an audit dictionary for logging.

        This is a convenience method for creating audit logs
        from a grant and decision.

        Args:
            grant: The ActionGrant
            decision: The ExecutorDecision
            surface: Execution surface
            action: Action
            resource: Resource

        Returns:
            Audit-safe dictionary
        """
        return {
            "action": action,
            "decision_hash": decision.decision_hash,
            "grant_id": decision.grant_id,
            "issuer": decision.issuer,
            "receipt_hash": decision.receipt_hash,
            "resource": resource,
            "result": "allow" if decision.allowed else "deny",
            "surface": surface,
            "verified_at": decision.verified_at,
        }
