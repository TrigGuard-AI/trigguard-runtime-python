"""
Action Grant Data Model

A portable, signed permission token for one specific action.

Action Grants are:
- Narrow: one action, one surface, explicit constraints
- Short-lived: seconds, not hours
- Signed: Ed25519 cryptographic signature
- Verifiable offline: no network required
- Bound to decision artifacts: policy_version, decision_hash, receipt_hash
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4


@dataclass
class GrantConstraints:
    """
    Explicit constraints on what the grant authorizes.

    Examples:
        max_amount: Maximum monetary value
        allowed_currency: Specific currency required
        allowed_command: Exact command that can be run
        allowed_tool_args: Allowed arguments for a tool
        one_time_use: Grant can only be used once
    """

    max_amount: Optional[float] = None
    allowed_currency: Optional[str] = None
    allowed_command: Optional[str] = None
    allowed_tool_args: Optional[dict[str, Any]] = None
    one_time_use: bool = False
    custom: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {}
        if self.max_amount is not None:
            result["max_amount"] = self.max_amount
        if self.allowed_currency is not None:
            result["allowed_currency"] = self.allowed_currency
        if self.allowed_command is not None:
            result["allowed_command"] = self.allowed_command
        if self.allowed_tool_args is not None:
            result["allowed_tool_args"] = self.allowed_tool_args
        if self.one_time_use:
            result["one_time_use"] = True
        if self.custom:
            result["custom"] = self.custom
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GrantConstraints":
        """Create from dictionary."""
        return cls(
            max_amount=data.get("max_amount"),
            allowed_currency=data.get("allowed_currency"),
            allowed_command=data.get("allowed_command"),
            allowed_tool_args=data.get("allowed_tool_args"),
            one_time_use=data.get("one_time_use", False),
            custom=data.get("custom", {}),
        )


@dataclass
class ActionGrant:
    """
    A signed, short-lived permission for one specific action.

    This is the portable authorization artifact that executors
    verify before running actions.

    Fields:
        grant_id: Unique identifier for this grant
        issuer: Identity of the grant issuer (e.g., "trigguard-kernel")
        issued_at: When the grant was issued (UTC)
        expires_at: When the grant expires (UTC)
        subject: Agent/caller identity if known
        surface: Execution surface (e.g., "SPEND", "CODE_EXECUTION")
        action: Specific action authorized (e.g., "transfer_money")
        resource: Target resource if applicable (e.g., account_id)
        constraints: Explicit limits on execution
        policy_version: Policy version at time of decision
        decision_hash: Hash of the authorization decision
        receipt_hash: Hash of the DecisionReceipt
        metadata: Additional context (must be deterministic)
        signature: Ed25519 signature of canonical payload
    """

    # Core identity
    grant_id: UUID
    issuer: str

    # Temporal bounds
    issued_at: datetime
    expires_at: datetime

    # Scope
    subject: Optional[str]
    surface: str
    action: str
    resource: Optional[str]
    constraints: GrantConstraints

    # Decision binding
    policy_version: str
    decision_hash: str
    receipt_hash: str

    # Optional
    kid: Optional[str] = None  # Key ID for signature verification
    metadata: dict[str, Any] = field(default_factory=dict)

    # Signature (not included in signed payload)
    signature: Optional[str] = None

    def to_canonical_dict(self) -> dict[str, Any]:
        """
        Convert to canonical dictionary for signing.

        Rules:
        - Stable key ordering (alphabetical)
        - No nondeterministic fields
        - Signature NOT included (it signs this payload)
        """
        result = {
            "action": self.action,
            "constraints": self.constraints.to_dict(),
            "decision_hash": self.decision_hash,
            "expires_at": self.expires_at.isoformat(),
            "grant_id": str(self.grant_id),
            "issued_at": self.issued_at.isoformat(),
            "issuer": self.issuer,
            "metadata": dict(sorted(self.metadata.items())),
            "policy_version": self.policy_version,
            "receipt_hash": self.receipt_hash,
            "resource": self.resource,
            "subject": self.subject,
            "surface": self.surface,
        }
        if self.kid is not None:
            result["kid"] = self.kid
        return result

    def to_canonical_json(self) -> str:
        """
        Canonical JSON representation for signing.

        Compact, sorted keys, no indentation.
        """
        return json.dumps(
            self.to_canonical_dict(),
            separators=(",", ":"),
            sort_keys=True,
        )

    def to_dict(self) -> dict[str, Any]:
        """Full dictionary representation including signature."""
        result = self.to_canonical_dict()
        if self.signature:
            result["signature"] = self.signature
        return result

    def to_json(self) -> str:
        """Full JSON representation including signature."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionGrant":
        """Create ActionGrant from dictionary."""
        return cls(
            grant_id=UUID(data["grant_id"]),
            issuer=data["issuer"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            subject=data.get("subject"),
            surface=data["surface"],
            action=data["action"],
            resource=data.get("resource"),
            constraints=GrantConstraints.from_dict(data.get("constraints", {})),
            policy_version=data["policy_version"],
            decision_hash=data["decision_hash"],
            receipt_hash=data["receipt_hash"],
            kid=data.get("kid"),
            metadata=data.get("metadata", {}),
            signature=data.get("signature"),
        )

    @property
    def is_expired(self) -> bool:
        """Check if grant has expired."""
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    @property
    def ttl_seconds(self) -> float:
        """Remaining time-to-live in seconds."""
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return max(0, (expires - now).total_seconds())

    @property
    def surface_id(self) -> str:
        """
        Get canonical surface ID.

        Normalizes the surface field to a canonical registry ID.
        If the surface is not registered, returns it with 'unknown.' prefix.

        Returns:
            Canonical surface ID (e.g., "trigguard.spend.transfer")
        """
        # Lazy import to avoid circular dependency
        from trigguard.core.surfaces import normalize_surface

        return normalize_surface(self.surface)

    @property
    def is_registered_surface(self) -> bool:
        """
        Check if this grant's surface is registered.

        Returns:
            True if surface is in the global registry
        """
        from trigguard.core.surfaces import is_registered_surface

        return is_registered_surface(self.surface)

    def __str__(self) -> str:
        return (
            f"ActionGrant(id={self.grant_id}, "
            f"surface={self.surface}, "
            f"action={self.action}, "
            f"ttl={self.ttl_seconds:.1f}s)"
        )
