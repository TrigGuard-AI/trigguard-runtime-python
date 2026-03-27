"""
Policy Bundle

A signed, versioned, immutable policy package for distribution.

PolicyBundles are distributed from a central policy registry to local kernels.
The kernel remains the sole decision authority - bundles only contain policy intelligence.

IMPORTANT:
- Bundles MUST be cryptographically signed
- Bundles MUST be immutable once loaded
- Bundles MUST serialize deterministically
- Unsigned/tampered bundles MUST be rejected
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from enum import Enum


class BundleStatus(str, Enum):
    """Status of a policy bundle."""

    PENDING = "pending"  # Downloaded, not verified
    VERIFIED = "verified"  # Signature verified
    ACTIVE = "active"  # Currently in use
    SUPERSEDED = "superseded"  # Replaced by newer version
    REJECTED = "rejected"  # Failed verification


@dataclass(frozen=True)
class PolicyThreshold:
    """Threshold configuration for a surface tier."""

    tier: int
    deny_threshold: float
    warn_threshold: float


@dataclass(frozen=True)
class PolicyRule:
    """A single policy rule in the bundle."""

    name: str
    description: str
    forbidden_signals: tuple[str, ...]
    required_signals: tuple[str, ...] = field(default_factory=tuple)
    applies_to_tiers: tuple[int, ...] = field(default_factory=lambda: (1, 2, 3))


@dataclass
class PolicyBundle:
    """
    A signed, versioned policy package.

    PolicyBundles contain:
    - Version identifier
    - Signal taxonomy hash (for compatibility checking)
    - Policy rules
    - Thresholds per tier
    - Surface definitions
    - Cryptographic signature

    Once loaded, a bundle is immutable.
    """

    # Version and identity
    version: str
    bundle_id: str

    # Compatibility
    signal_taxonomy_hash: str  # Hash of expected signal taxonomy
    min_kernel_version: str = "1.0.0"

    # Policy content
    policy_rules: list[PolicyRule] = field(default_factory=list)
    thresholds: list[PolicyThreshold] = field(default_factory=list)
    forbidden_signals: list[str] = field(default_factory=list)
    silence_triggers: list[str] = field(default_factory=list)
    critical_signals: list[str] = field(default_factory=list)

    # Surface configurations
    surfaces: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    description: str = ""

    # Cryptographic integrity
    bundle_hash: str = ""  # SHA256 of canonical content
    signature: str = ""  # Cryptographic signature
    signed_by: str = ""  # Signer identity

    # Internal state
    _frozen: bool = field(default=False, repr=False)
    _status: BundleStatus = field(default=BundleStatus.PENDING, repr=False)

    def freeze(self) -> None:
        """
        Freeze the bundle to prevent modification.

        Call this after verification to ensure immutability.
        """
        object.__setattr__(self, "_frozen", True)

    @property
    def is_frozen(self) -> bool:
        """Check if bundle is frozen."""
        return self._frozen

    @property
    def status(self) -> BundleStatus:
        """Get bundle status."""
        return self._status

    def set_status(self, status: BundleStatus) -> None:
        """Set bundle status (only if not frozen)."""
        if self._frozen and status != BundleStatus.SUPERSEDED:
            raise ValueError("Cannot modify frozen bundle status")
        object.__setattr__(self, "_status", status)

    def to_canonical_dict(self) -> dict[str, Any]:
        """
        Convert to canonical dictionary for hashing.

        Excludes signature and hash (those are computed from this).
        Keys are sorted for deterministic serialization.
        """
        return {
            "bundle_id": self.bundle_id,
            "created_at": self.created_at.isoformat(),
            "critical_signals": sorted(self.critical_signals),
            "description": self.description,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "forbidden_signals": sorted(self.forbidden_signals),
            "min_kernel_version": self.min_kernel_version,
            "policy_rules": [
                {
                    "applies_to_tiers": sorted(r.applies_to_tiers),
                    "description": r.description,
                    "forbidden_signals": sorted(r.forbidden_signals),
                    "name": r.name,
                    "required_signals": sorted(r.required_signals),
                }
                for r in sorted(self.policy_rules, key=lambda r: r.name)
            ],
            "signal_taxonomy_hash": self.signal_taxonomy_hash,
            "silence_triggers": sorted(self.silence_triggers),
            "surfaces": dict(sorted(self.surfaces.items())),
            "thresholds": [
                {
                    "deny_threshold": t.deny_threshold,
                    "tier": t.tier,
                    "warn_threshold": t.warn_threshold,
                }
                for t in sorted(self.thresholds, key=lambda t: t.tier)
            ],
            "version": self.version,
        }

    def to_canonical_json(self) -> str:
        """
        Convert to canonical JSON for hashing.

        Produces deterministic, stable JSON.
        """
        return json.dumps(
            self.to_canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def compute_hash(self) -> str:
        """
        Compute SHA256 hash of bundle content.

        This hash is used to verify integrity.
        """
        canonical = self.to_canonical_json()
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_signed_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary including signature.

        Use this for serialization and transmission.
        """
        data = self.to_canonical_dict()
        data["bundle_hash"] = self.bundle_hash
        data["signature"] = self.signature
        data["signed_by"] = self.signed_by
        return data

    def to_json(self) -> str:
        """Serialize bundle to JSON."""
        return json.dumps(self.to_signed_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyBundle":
        """
        Create bundle from dictionary.

        Use this for deserialization.
        """
        # Parse policy rules
        rules = [
            PolicyRule(
                name=r["name"],
                description=r["description"],
                forbidden_signals=tuple(r["forbidden_signals"]),
                required_signals=tuple(r.get("required_signals", [])),
                applies_to_tiers=tuple(r.get("applies_to_tiers", [1, 2, 3])),
            )
            for r in data.get("policy_rules", [])
        ]

        # Parse thresholds
        thresholds = [
            PolicyThreshold(
                tier=t["tier"],
                deny_threshold=t["deny_threshold"],
                warn_threshold=t["warn_threshold"],
            )
            for t in data.get("thresholds", [])
        ]

        # Parse timestamps
        created_at = datetime.fromisoformat(data["created_at"])
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])

        return cls(
            version=data["version"],
            bundle_id=data["bundle_id"],
            signal_taxonomy_hash=data["signal_taxonomy_hash"],
            min_kernel_version=data.get("min_kernel_version", "1.0.0"),
            policy_rules=rules,
            thresholds=thresholds,
            forbidden_signals=data.get("forbidden_signals", []),
            silence_triggers=data.get("silence_triggers", []),
            critical_signals=data.get("critical_signals", []),
            surfaces=data.get("surfaces", {}),
            created_at=created_at,
            expires_at=expires_at,
            description=data.get("description", ""),
            bundle_hash=data.get("bundle_hash", ""),
            signature=data.get("signature", ""),
            signed_by=data.get("signed_by", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "PolicyBundle":
        """Create bundle from JSON string."""
        return cls.from_dict(json.loads(json_str))


def create_unsigned_bundle(
    version: str,
    bundle_id: str,
    signal_taxonomy_hash: str,
    forbidden_signals: list[str],
    silence_triggers: list[str],
    critical_signals: list[str],
    thresholds: list[PolicyThreshold],
    description: str = "",
) -> PolicyBundle:
    """
    Create an unsigned policy bundle.

    The bundle will have its hash computed but no signature.
    Use sign_bundle() to add a signature before distribution.
    """
    bundle = PolicyBundle(
        version=version,
        bundle_id=bundle_id,
        signal_taxonomy_hash=signal_taxonomy_hash,
        forbidden_signals=forbidden_signals,
        silence_triggers=silence_triggers,
        critical_signals=critical_signals,
        thresholds=thresholds,
        description=description,
    )

    # Compute hash
    bundle.bundle_hash = bundle.compute_hash()

    return bundle
