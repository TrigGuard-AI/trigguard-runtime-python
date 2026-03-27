"""
Action Grant Error Types

Custom exceptions for grant issuance and verification.
"""


class GrantError(Exception):
    """Base exception for all grant-related errors."""

    pass


class GrantIssuanceError(GrantError):
    """Error during grant issuance."""

    pass


class GrantVerificationError(GrantError):
    """Base error for grant verification failures."""

    pass


class GrantExpiredError(GrantVerificationError):
    """Grant has expired."""

    pass


class GrantSignatureError(GrantVerificationError):
    """Grant signature verification failed."""

    pass


class GrantScopeMismatchError(GrantVerificationError):
    """Grant scope does not match requested action."""

    pass


class GrantConstraintViolationError(GrantVerificationError):
    """Execution input violates grant constraints."""

    pass
