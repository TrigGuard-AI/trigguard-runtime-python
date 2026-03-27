"""
Discovery Contract

Portable contract for surface discovery and capability advertisement.

This module defines the contracts that tools, executors, and agents
use to advertise their capabilities to TrigGuard.

A DiscoveryManifest is what a tool or executor publishes.
TrigGuard can then govern access to those surfaces consistently.

Usage:
    from trigguard.discovery import DiscoveryManifest, SurfaceDiscoveryRecord

    # Create discovery record for a tool
    record = SurfaceDiscoveryRecord(
        surface_id="trigguard.spend.transfer",
        supported_actions=["transfer", "send"],
        grant_required=True,
    )

    # Create manifest
    manifest = DiscoveryManifest(
        issuer="my-payment-tool",
        surfaces=[record],
    )

    # Export for advertisement
    manifest.to_dict()
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class ConstraintSchema:
    """
    Schema for constraints supported by a surface.

    Defines what constraints an executor can verify.
    """

    # Supported constraint types
    supports_max_amount: bool = False
    supports_currency: bool = False
    supports_command_allowlist: bool = False
    supports_resource_binding: bool = False
    supports_one_time_use: bool = False

    # Custom constraint definitions
    custom_constraints: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {}
        if self.supports_max_amount:
            result["max_amount"] = {"type": "number", "description": "Maximum amount"}
        if self.supports_currency:
            result["currency"] = {
                "type": "string",
                "description": "Allowed currency code",
            }
        if self.supports_command_allowlist:
            result["allowed_command"] = {
                "type": "string",
                "description": "Allowed command pattern",
            }
        if self.supports_resource_binding:
            result["resource"] = {"type": "string", "description": "Bound resource ID"}
        if self.supports_one_time_use:
            result["one_time_use"] = {
                "type": "boolean",
                "description": "Grant can only be used once",
            }
        if self.custom_constraints:
            result.update(self.custom_constraints)
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConstraintSchema":
        """Create from dictionary."""
        return cls(
            supports_max_amount="max_amount" in data,
            supports_currency="currency" in data,
            supports_command_allowlist="allowed_command" in data,
            supports_resource_binding="resource" in data,
            supports_one_time_use="one_time_use" in data,
            custom_constraints={
                k: v
                for k, v in data.items()
                if k
                not in [
                    "max_amount",
                    "currency",
                    "allowed_command",
                    "resource",
                    "one_time_use",
                ]
            },
        )


@dataclass
class SurfaceDiscoveryRecord:
    """
    Discovery record for a single execution surface.

    This describes what a tool/executor supports for a given surface.
    Executors publish these; TrigGuard uses them for governance.

    Fields:
        surface_id: Canonical surface identifier
        supported_actions: List of actions this tool can perform
        resource_types: Types of resources supported (e.g., "account", "file")
        constraint_schema: What constraints the executor can verify
        verifier_required: Whether signature verification is required
        grant_required: Whether an Action Grant is required
        metadata: Additional tool-specific metadata
    """

    # Core identity
    surface_id: str
    supported_actions: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)

    # Constraint support
    constraint_schema: Optional[ConstraintSchema] = None

    # Requirements
    verifier_required: bool = True
    grant_required: bool = True

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "surface_id": self.surface_id,
            "supported_actions": self.supported_actions,
            "resource_types": self.resource_types,
            "verifier_required": self.verifier_required,
            "grant_required": self.grant_required,
        }
        if self.constraint_schema:
            result["constraint_schema"] = self.constraint_schema.to_dict()
        if self.metadata:
            result["metadata"] = self.metadata
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SurfaceDiscoveryRecord":
        """Create from dictionary."""
        constraint_data = data.get("constraint_schema")
        constraint_schema = (
            ConstraintSchema.from_dict(constraint_data) if constraint_data else None
        )

        return cls(
            surface_id=data["surface_id"],
            supported_actions=data.get("supported_actions", []),
            resource_types=data.get("resource_types", []),
            constraint_schema=constraint_schema,
            verifier_required=data.get("verifier_required", True),
            grant_required=data.get("grant_required", True),
            metadata=data.get("metadata", {}),
        )


@dataclass
class DiscoveryManifest:
    """
    Portable manifest of surfaces supported by a tool or executor.

    This is the contract a tool publishes for TrigGuard to discover.

    Fields:
        issuer: Identity of the tool/executor publishing this manifest
        version: Manifest version string
        updated_at: When this manifest was last updated
        surfaces: List of surface discovery records
        metadata: Additional manifest metadata
    """

    # Identity
    issuer: str
    version: str = "1.0"
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Surfaces
    surfaces: list[SurfaceDiscoveryRecord] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_surface(self, record: SurfaceDiscoveryRecord) -> None:
        """Add a surface discovery record."""
        # Check for duplicates
        existing_ids = {s.surface_id for s in self.surfaces}
        if record.surface_id in existing_ids:
            # Replace existing
            self.surfaces = [
                s if s.surface_id != record.surface_id else record
                for s in self.surfaces
            ]
        else:
            self.surfaces.append(record)
        self.updated_at = datetime.now(timezone.utc)

    def get_surface(self, surface_id: str) -> Optional[SurfaceDiscoveryRecord]:
        """Get a surface record by ID."""
        for surface in self.surfaces:
            if surface.surface_id == surface_id:
                return surface
        return None

    def supports_surface(self, surface_id: str) -> bool:
        """Check if this manifest supports a surface."""
        return any(s.surface_id == surface_id for s in self.surfaces)

    def supports_action(self, surface_id: str, action: str) -> bool:
        """Check if this manifest supports an action on a surface."""
        record = self.get_surface(surface_id)
        if record is None:
            return False
        # Empty list means all actions supported
        if not record.supported_actions:
            return True
        return action in record.supported_actions

    def list_surface_ids(self) -> list[str]:
        """List all surface IDs in this manifest."""
        return [s.surface_id for s in self.surfaces]

    def list_grant_required_surfaces(self) -> list[str]:
        """List surfaces that require grants."""
        return [s.surface_id for s in self.surfaces if s.grant_required]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "issuer": self.issuer,
            "version": self.version,
            "updated_at": self.updated_at.isoformat(),
            "surface_count": len(self.surfaces),
            "surfaces": [s.to_dict() for s in self.surfaces],
            "metadata": self.metadata,
        }

    def to_canonical_json(self) -> str:
        """Deterministic JSON representation."""
        return json.dumps(
            self.to_dict(),
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DiscoveryManifest":
        """Create from dictionary."""
        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        elif updated_at is None:
            updated_at = datetime.now(timezone.utc)

        return cls(
            issuer=data["issuer"],
            version=data.get("version", "1.0"),
            updated_at=updated_at,
            surfaces=[
                SurfaceDiscoveryRecord.from_dict(s) for s in data.get("surfaces", [])
            ],
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DiscoveryManifest":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


def build_discovery_manifest(
    issuer: str,
    surface_configs: list[dict[str, Any]],
    version: str = "1.0",
) -> DiscoveryManifest:
    """
    Build a discovery manifest from configuration.

    Args:
        issuer: Tool/executor identity
        surface_configs: List of surface configuration dicts
        version: Manifest version

    Returns:
        DiscoveryManifest instance
    """
    surfaces = [SurfaceDiscoveryRecord.from_dict(cfg) for cfg in surface_configs]
    return DiscoveryManifest(
        issuer=issuer,
        version=version,
        surfaces=surfaces,
    )


def merge_manifests(*manifests: DiscoveryManifest) -> DiscoveryManifest:
    """
    Merge multiple discovery manifests.

    Later manifests override earlier ones for the same surface.

    Args:
        manifests: Manifests to merge

    Returns:
        Merged manifest
    """
    if not manifests:
        raise ValueError("At least one manifest required")

    result = DiscoveryManifest(
        issuer="merged",
        surfaces=[],
    )

    for manifest in manifests:
        for surface in manifest.surfaces:
            result.add_surface(surface)

    return result
