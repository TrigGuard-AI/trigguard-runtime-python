"""
TrigGuard Action Grants

Portable, signed execution permissions for AI actions.

Action Grants are NOT a second decision engine.
They package and sign scoped execution permissions
issued only after a PERMIT decision.

Architecture:
    DecisionEngine decides → Receipt proves → Grant authorizes execution

Usage:
    from trigguard.grants import ActionGrantIssuer, ActionGrantVerifier

    # Issue a grant from a PERMIT decision
    issuer = ActionGrantIssuer(private_key)
    grant = issuer.issue_grant(decision, receipt, request)

    # Verify a grant before execution
    verifier = ActionGrantVerifier(public_key)
    result = verifier.verify_grant(grant, surface="SPEND", action="transfer")

    if result.valid:
        execute_action()
"""

from trigguard.grants.action_grant import ActionGrant, GrantConstraints
from trigguard.grants.issuer import ActionGrantIssuer
from trigguard.grants.verifier import ActionGrantVerifier, GrantVerificationResult
from trigguard.grants.errors import (
    GrantError,
    GrantIssuanceError,
    GrantVerificationError,
    GrantExpiredError,
    GrantSignatureError,
    GrantScopeMismatchError,
    GrantConstraintViolationError,
)

__all__ = [
    # Data models
    "ActionGrant",
    "GrantConstraints",
    "GrantVerificationResult",
    # Issuer and Verifier
    "ActionGrantIssuer",
    "ActionGrantVerifier",
    # Errors
    "GrantError",
    "GrantIssuanceError",
    "GrantVerificationError",
    "GrantExpiredError",
    "GrantSignatureError",
    "GrantScopeMismatchError",
    "GrantConstraintViolationError",
]
