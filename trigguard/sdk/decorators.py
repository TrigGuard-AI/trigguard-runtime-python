"""
TrigGuard SDK Decorators

Simple decorator-based integration for enforcing TrigGuard authorization.

The @requires_grant decorator provides instant authorization enforcement
for any function. AI agent frameworks can add a single decorator to
immediately enforce TrigGuard grant verification.

Usage:
    from trigguard.sdk import requires_grant

    @requires_grant(surface="SPEND", action="transfer_money")
    def transfer_money(amount: float, currency: str) -> bool:
        return bank.transfer(amount, currency)

    # Caller must provide grant
    transfer_money(100, "USD", grant=my_grant, keyset=cached_keys)

The decorator:
1. Extracts grant and keyset from kwargs
2. Verifies the grant using TrigGuardVerifierSDK
3. If invalid: raises GrantVerificationError
4. If valid: executes the function
5. Returns function result

This is the simplest integration path for TrigGuard adoption.
"""

from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union

from trigguard.grants.action_grant import ActionGrant
from trigguard.verification.verifier_sdk import TrigGuardVerifierSDK
from trigguard.executor.contract import ExecutorVerificationContract


class GrantVerificationError(Exception):
    """Raised when grant verification fails."""

    def __init__(
        self,
        reason: str,
        surface: Optional[str] = None,
        action: Optional[str] = None,
        grant_id: Optional[str] = None,
    ):
        self.reason = reason
        self.surface = surface
        self.action = action
        self.grant_id = grant_id
        super().__init__(f"TrigGuard authorization failed: {reason}")


class MissingGrantError(GrantVerificationError):
    """Raised when no grant is provided to a protected function."""

    def __init__(self, surface: str, action: str):
        super().__init__(
            reason="No ActionGrant provided",
            surface=surface,
            action=action,
        )


F = TypeVar("F", bound=Callable[..., Any])


def requires_grant(
    surface: str,
    action: str,
    *,
    strict: bool = True,
    require_keyset: bool = False,
) -> Callable[[F], F]:
    """
    Decorator that enforces TrigGuard grant verification before execution.

    This is the simplest way to integrate TrigGuard into any function.
    The decorated function requires a `grant` kwarg (and optionally `keyset`).

    Args:
        surface: Execution surface (e.g., "SPEND", "CODE_EXEC")
        action: Specific action (e.g., "transfer_money", "run_shell")
        strict: If True, raises on verification failure. If False, returns None.
        require_keyset: If True, requires keyset to be provided

    Usage:
        @requires_grant(surface="SPEND", action="transfer_money")
        def transfer_money(amount: float, currency: str) -> bool:
            return bank.transfer(amount, currency)

        # Call with grant
        result = transfer_money(100, "USD", grant=my_grant, keyset=cached_keys)

    Raises:
        MissingGrantError: If no grant is provided
        GrantVerificationError: If grant verification fails (when strict=True)

    Returns:
        Decorated function that enforces grant verification
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract grant and keyset/sdk from kwargs
            grant: Optional[ActionGrant] = kwargs.pop("grant", None)
            keyset: Optional[Union[dict, TrigGuardVerifierSDK]] = kwargs.pop(
                "keyset", None
            )

            # Validate grant is provided
            if grant is None:
                if strict:
                    raise MissingGrantError(surface=surface, action=action)
                return None

            # Validate keyset if required
            if require_keyset and keyset is None:
                if strict:
                    raise GrantVerificationError(
                        reason="Keyset required but not provided",
                        surface=surface,
                        action=action,
                    )
                return None

            # Create or use verifier SDK
            if isinstance(keyset, TrigGuardVerifierSDK):
                sdk = keyset
            else:
                sdk = TrigGuardVerifierSDK()
                # Load keyset if provided as dict
                if keyset is not None:
                    sdk.load_key_set(keyset)

            # Create verification contract
            contract = ExecutorVerificationContract(sdk)

            # Verify before execute
            decision = contract.verify_before_execute(
                grant,
                surface=surface,
                action=action,
            )

            # Handle verification result
            if not decision.allowed:
                if strict:
                    raise GrantVerificationError(
                        reason=decision.reason,
                        surface=surface,
                        action=action,
                        grant_id=str(grant.grant_id) if grant else None,
                    )
                return None

            # Grant verified - execute the function
            return func(*args, **kwargs)

        # Store metadata for introspection
        wrapper._trigguard_protected = True  # type: ignore
        wrapper._trigguard_surface = surface  # type: ignore
        wrapper._trigguard_action = action  # type: ignore

        return wrapper  # type: ignore

    return decorator


def requires_grant_async(
    surface: str,
    action: str,
    *,
    strict: bool = True,
    require_keyset: bool = False,
) -> Callable[[F], F]:
    """
    Async version of @requires_grant decorator.

    Same semantics as @requires_grant but for async functions.

    Usage:
        @requires_grant_async(surface="SPEND", action="transfer_money")
        async def transfer_money(amount: float) -> bool:
            return await bank.transfer_async(amount)
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract grant and keyset/sdk from kwargs
            grant: Optional[ActionGrant] = kwargs.pop("grant", None)
            keyset: Optional[Union[dict, TrigGuardVerifierSDK]] = kwargs.pop(
                "keyset", None
            )

            # Validate grant is provided
            if grant is None:
                if strict:
                    raise MissingGrantError(surface=surface, action=action)
                return None

            # Validate keyset if required
            if require_keyset and keyset is None:
                if strict:
                    raise GrantVerificationError(
                        reason="Keyset required but not provided",
                        surface=surface,
                        action=action,
                    )
                return None

            # Create or use verifier SDK
            if isinstance(keyset, TrigGuardVerifierSDK):
                sdk = keyset
            else:
                sdk = TrigGuardVerifierSDK()
                # Load keyset if provided as dict
                if keyset is not None:
                    sdk.load_key_set(keyset)

            # Create verification contract
            contract = ExecutorVerificationContract(sdk)

            # Verify before execute
            decision = contract.verify_before_execute(
                grant,
                surface=surface,
                action=action,
            )

            # Handle verification result
            if not decision.allowed:
                if strict:
                    raise GrantVerificationError(
                        reason=decision.reason,
                        surface=surface,
                        action=action,
                        grant_id=str(grant.grant_id) if grant else None,
                    )
                return None

            # Grant verified - execute the function
            return await func(*args, **kwargs)

        # Store metadata for introspection
        wrapper._trigguard_protected = True  # type: ignore
        wrapper._trigguard_surface = surface  # type: ignore
        wrapper._trigguard_action = action  # type: ignore

        return wrapper  # type: ignore

    return decorator


def is_protected(func: Callable[..., Any]) -> bool:
    """Check if a function is protected by @requires_grant."""
    return getattr(func, "_trigguard_protected", False)


def get_protected_surface(func: Callable[..., Any]) -> Optional[str]:
    """Get the surface a protected function requires."""
    return getattr(func, "_trigguard_surface", None)


def get_protected_action(func: Callable[..., Any]) -> Optional[str]:
    """Get the action a protected function requires."""
    return getattr(func, "_trigguard_action", None)
