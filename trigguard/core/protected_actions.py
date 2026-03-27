"""
TrigGuard Protected Actions

CANONICAL WRAPPERS FOR ALL DANGEROUS/IRREVERSIBLE ACTIONS.

This module provides protected wrappers for all actions that MUST
go through TrigGuard authorization. These are the ONLY authorized
functions for performing dangerous operations.

Architecture:
    Application code
          ↓
    protected_*() functions (THIS MODULE)
          ↓
    ExecutionAdapter.execute_if_permitted()
          ↓
    ExecutionGate.evaluate()
          ↓
    DecisionEngine.authorize()
          ↓
    PERMIT → Execute underlying action
    DENY → Raise ExecutionDenied

USAGE RULES:
1. NEVER import the underlying dangerous libraries directly
2. ALWAYS use these protected_* functions
3. Add new protected_* functions for any new dangerous capabilities
4. Static analysis scans should flag direct usage of dangerous APIs

IRREVERSIBLE SURFACES:
    - SPEND: Financial transactions
    - DATA_EXPORT: Sending data externally
    - CODE_EXECUTION: Running arbitrary code
    - DELEGATION: Granting capabilities
    - IDENTITY_ASSERTION: Acting as identity
    - DATA_MUTATION: Irreversible data changes

WARNING: Bypassing these functions is an architectural violation.
"""

import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

from trigguard.core.execution_adapter import (
    ExecutionAdapter,
    ExecutionResult,
    ExecutionDenied,
    get_execution_adapter,
)
from trigguard.protocol.decision_contracts import ExecutionSurface

logger = logging.getLogger("trigguard.protected_actions")


# ============================================================================
# Internal Helpers
# ============================================================================


def _get_adapter() -> ExecutionAdapter:
    """Get the execution adapter."""
    return get_execution_adapter()


# ============================================================================
# SPEND Surface - Financial Transactions
# ============================================================================


def protected_spend(
    amount: float,
    recipient: str,
    currency: str = "USD",
    transfer_callable: Optional[Callable[..., Any]] = None,
    *,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected financial transaction.

    ALL financial transactions MUST go through this function.

    Args:
        amount: Transaction amount
        recipient: Recipient identifier
        currency: Currency code
        transfer_callable: The actual transfer function to execute
        context: Optional additional context

    Returns:
        ExecutionResult with transfer result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the transaction

    Example:
        result = protected_spend(
            amount=100.00,
            recipient="vendor@example.com",
            currency="USD",
            transfer_callable=lambda: stripe.transfer(100, "vendor@example.com"),
        )
    """
    if transfer_callable is None:
        raise ValueError("transfer_callable is required")

    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.SPEND,
        action="financial_transfer",
        action_callable=transfer_callable,
        arguments={
            "amount": amount,
            "recipient": recipient,
            "currency": currency,
        },
        context=context or {},
    )


def protected_payment(
    payment_method: str,
    amount: float,
    description: str,
    payment_callable: Callable[..., Any],
    *,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected payment processing.

    Args:
        payment_method: Payment method identifier
        amount: Payment amount
        description: Payment description
        payment_callable: The actual payment function
        context: Optional additional context

    Returns:
        ExecutionResult with payment result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the payment
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.SPEND,
        action="payment",
        action_callable=payment_callable,
        arguments={
            "payment_method": payment_method,
            "amount": amount,
            "description": description,
        },
        context=context or {},
    )


# ============================================================================
# DATA_EXPORT Surface - External Data Transmission
# ============================================================================


def protected_data_export(
    destination: str,
    data_type: str,
    export_callable: Callable[..., Any],
    *,
    data_summary: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected data export to external system.

    ALL data exports MUST go through this function.

    Args:
        destination: External destination URL or identifier
        data_type: Type of data being exported
        export_callable: The actual export function
        data_summary: Brief summary of data (NOT the actual data)
        context: Optional additional context

    Returns:
        ExecutionResult with export result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the export

    Example:
        result = protected_data_export(
            destination="https://partner.com/api",
            data_type="customer_records",
            export_callable=lambda: requests.post(url, json=data),
            data_summary="50 customer records"
        )
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.DATA_EXPORT,
        action="data_export",
        action_callable=export_callable,
        arguments={
            "destination": destination,
            "data_type": data_type,
            "data_summary": data_summary,
        },
        context=context or {},
    )


def protected_api_request(
    method: str,
    url: str,
    request_callable: Callable[..., Any],
    *,
    contains_sensitive_data: bool = False,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected external API request.

    Use for any HTTP request that sends data externally.

    Args:
        method: HTTP method (POST, PUT, etc.)
        url: Target URL
        request_callable: The actual request function
        contains_sensitive_data: Whether request contains sensitive data
        context: Optional additional context

    Returns:
        ExecutionResult with request result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the request
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.DATA_EXPORT,
        action=f"api_request_{method.lower()}",
        action_callable=request_callable,
        arguments={
            "method": method,
            "url": url,
            "contains_sensitive_data": contains_sensitive_data,
        },
        context=context or {},
    )


# ============================================================================
# CODE_EXECUTION Surface - Arbitrary Code Execution
# ============================================================================


def protected_code_exec(
    code: str,
    language: str,
    exec_callable: Callable[..., Any],
    *,
    trusted_source: bool = False,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected code execution.

    ALL arbitrary code execution MUST go through this function.

    Args:
        code: Code to execute (for audit, may be truncated)
        language: Programming language
        exec_callable: The actual execution function
        trusted_source: Whether code comes from trusted source
        context: Optional additional context

    Returns:
        ExecutionResult with execution result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies execution

    WARNING: This is a high-risk surface. Most policies will deny
             code execution from untrusted sources.

    Example:
        result = protected_code_exec(
            code="print('hello')",
            language="python",
            exec_callable=lambda: exec("print('hello')"),
            trusted_source=False
        )
    """
    # Truncate code for logging (don't log full code)
    code_preview = code[:100] + "..." if len(code) > 100 else code

    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.CODE_EXECUTION,
        action="code_execution",
        action_callable=exec_callable,
        arguments={
            "code_preview": code_preview,
            "language": language,
            "code_length": len(code),
            "trusted_source": trusted_source,
        },
        context=context or {},
    )


def protected_shell_command(
    command: Union[str, List[str]],
    command_callable: Optional[Callable[..., Any]] = None,
    *,
    shell: bool = False,
    cwd: Optional[str] = None,
    capture_output: bool = True,
    timeout: Optional[int] = None,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected shell command execution.

    ALL subprocess/shell execution MUST go through this function.

    Args:
        command: Command to execute
        command_callable: Custom callable (defaults to subprocess.run)
        shell: Whether to use shell execution
        cwd: Working directory
        capture_output: Whether to capture stdout/stderr
        timeout: Command timeout in seconds
        context: Optional additional context

    Returns:
        ExecutionResult with command result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies execution

    Example:
        result = protected_shell_command(
            command=["git", "clone", repo_url],
            cwd="/tmp"
        )
    """
    # Normalize command for audit
    cmd_str = command if isinstance(command, str) else " ".join(command)

    # Default callable uses subprocess.run
    if command_callable is None:

        def default_subprocess():
            return subprocess.run(
                command,
                shell=shell,  # nosec B602 - intentional: TrigGuard controls execution
                cwd=cwd,
                capture_output=capture_output,
                timeout=timeout,
            )

        command_callable = default_subprocess

    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.CODE_EXECUTION,
        action="shell_command",
        action_callable=command_callable,
        arguments={
            "command": cmd_str,
            "shell": shell,
            "cwd": cwd,
        },
        context=context or {},
    )


# ============================================================================
# DELEGATION Surface - Capability Granting
# ============================================================================


def protected_delegation(
    target: str,
    capability: str,
    delegation_callable: Callable[..., Any],
    *,
    scope: Optional[str] = None,
    duration: Optional[int] = None,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected capability delegation.

    ALL capability grants MUST go through this function.

    Args:
        target: Target receiving the capability
        capability: Capability being granted
        delegation_callable: The actual delegation function
        scope: Scope of the capability
        duration: Duration in seconds (None = permanent)
        context: Optional additional context

    Returns:
        ExecutionResult with delegation result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the delegation

    Example:
        result = protected_delegation(
            target="agent-123",
            capability="read:customer_data",
            delegation_callable=lambda: auth.grant(agent, capability),
            scope="workspace:proj-1"
        )
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.DELEGATION,
        action="capability_delegation",
        action_callable=delegation_callable,
        arguments={
            "target": target,
            "capability": capability,
            "scope": scope,
            "duration_seconds": duration,
            "permanent": duration is None,
        },
        context=context or {},
    )


def protected_permission_grant(
    principal: str,
    permission: str,
    resource: str,
    grant_callable: Callable[..., Any],
    *,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected permission grant.

    Args:
        principal: Principal receiving permission
        permission: Permission being granted
        resource: Resource the permission applies to
        grant_callable: The actual grant function
        context: Optional additional context

    Returns:
        ExecutionResult with grant result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the grant
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.DELEGATION,
        action="permission_grant",
        action_callable=grant_callable,
        arguments={
            "principal": principal,
            "permission": permission,
            "resource": resource,
        },
        context=context or {},
    )


# ============================================================================
# IDENTITY_ASSERTION Surface - Acting as Identity
# ============================================================================


def protected_identity_assertion(
    identity: str,
    assertion_type: str,
    assertion_callable: Callable[..., Any],
    *,
    audience: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected identity assertion.

    ALL identity assertions MUST go through this function.

    Args:
        identity: Identity being asserted
        assertion_type: Type of assertion (e.g., "claim", "sign")
        assertion_callable: The actual assertion function
        audience: Intended audience for the assertion
        context: Optional additional context

    Returns:
        ExecutionResult with assertion result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the assertion

    Example:
        result = protected_identity_assertion(
            identity="org:acme",
            assertion_type="sign_contract",
            assertion_callable=lambda: crypto.sign(contract, key),
            audience="vendor"
        )
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.IDENTITY_ASSERTION,
        action="identity_assertion",
        action_callable=assertion_callable,
        arguments={
            "identity": identity,
            "assertion_type": assertion_type,
            "audience": audience,
        },
        context=context or {},
    )


def protected_signature(
    identity: str,
    document_type: str,
    signature_callable: Callable[..., Any],
    *,
    document_hash: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected digital signature.

    Args:
        identity: Signing identity
        document_type: Type of document being signed
        signature_callable: The actual signature function
        document_hash: Hash of document (for audit)
        context: Optional additional context

    Returns:
        ExecutionResult with signature result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the signature
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.IDENTITY_ASSERTION,
        action="digital_signature",
        action_callable=signature_callable,
        arguments={
            "identity": identity,
            "document_type": document_type,
            "document_hash": document_hash,
        },
        context=context or {},
    )


# ============================================================================
# DATA_MUTATION Surface - Irreversible Data Changes
# ============================================================================


def protected_data_mutation(
    resource: str,
    mutation_type: str,
    mutation_callable: Callable[..., Any],
    *,
    affected_records: Optional[int] = None,
    reversible: bool = False,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected data mutation.

    ALL irreversible data changes MUST go through this function.

    Args:
        resource: Resource being mutated
        mutation_type: Type of mutation (delete, truncate, etc.)
        mutation_callable: The actual mutation function
        affected_records: Number of affected records
        reversible: Whether mutation is reversible
        context: Optional additional context

    Returns:
        ExecutionResult with mutation result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the mutation

    Example:
        result = protected_data_mutation(
            resource="customers",
            mutation_type="bulk_delete",
            mutation_callable=lambda: db.execute(delete_query),
            affected_records=1000,
            reversible=False
        )
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.DATA_MUTATION,
        action=f"data_mutation_{mutation_type}",
        action_callable=mutation_callable,
        arguments={
            "resource": resource,
            "mutation_type": mutation_type,
            "affected_records": affected_records,
            "reversible": reversible,
        },
        context=context or {},
    )


def protected_delete(
    resource: str,
    identifier: str,
    delete_callable: Callable[..., Any],
    *,
    cascade: bool = False,
    context: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Protected deletion operation.

    Args:
        resource: Resource type
        identifier: Record identifier
        delete_callable: The actual delete function
        cascade: Whether deletion cascades
        context: Optional additional context

    Returns:
        ExecutionResult with deletion result and audit trail

    Raises:
        ExecutionDenied: If TrigGuard denies the deletion
    """
    return _get_adapter().execute_if_permitted(
        surface=ExecutionSurface.DATA_MUTATION,
        action="delete",
        action_callable=delete_callable,
        arguments={
            "resource": resource,
            "identifier": identifier,
            "cascade": cascade,
        },
        context=context or {},
    )


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    # SPEND Surface
    "protected_spend",
    "protected_payment",
    # DATA_EXPORT Surface
    "protected_data_export",
    "protected_api_request",
    # CODE_EXECUTION Surface
    "protected_code_exec",
    "protected_shell_command",
    # DELEGATION Surface
    "protected_delegation",
    "protected_permission_grant",
    # IDENTITY_ASSERTION Surface
    "protected_identity_assertion",
    "protected_signature",
    # DATA_MUTATION Surface
    "protected_data_mutation",
    "protected_delete",
]
