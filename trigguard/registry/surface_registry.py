"""
Execution Surface Registry

Canonical registry of execution surfaces with alias resolution
and deterministic export.

The registry is the source of truth for surface identities.
It does NOT contain policy logic - only surface definitions.

Usage:
    from trigguard.registry import get_global_surface_registry

    registry = get_global_surface_registry()
    surface = registry.get("trigguard.spend.transfer")

    # Alias resolution
    surface = registry.resolve("SPEND")  # -> trigguard.spend.transfer

    # Risk tier lookup
    high_risk = registry.list_by_risk(SurfaceRiskTier.IRREVERSIBLE)
"""

import json
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from trigguard.registry.surface_types import (
    ExecutionSurfaceDefinition,
    SurfaceRiskTier,
    CANONICAL_SURFACES,
    get_canonical_surfaces,
)


class SurfaceRegistryError(Exception):
    """Base exception for registry errors."""

    pass


class DuplicateSurfaceError(SurfaceRegistryError):
    """Raised when registering a duplicate surface with different definition."""

    pass


class UnknownSurfaceError(SurfaceRegistryError):
    """Raised when surface is not found and fail_on_unknown is True."""

    pass


class ExecutionSurfaceRegistry:
    """
    Registry of execution surface definitions.

    Provides:
    - Canonical surface registration
    - Alias resolution (SPEND -> trigguard.spend.transfer)
    - Risk tier lookup
    - Deterministic manifest export

    Thread-safe for reads. Write operations should be done during initialization.
    """

    def __init__(
        self,
        preload_canonical: bool = True,
        fail_on_unknown: bool = False,
    ):
        """
        Initialize the registry.

        Args:
            preload_canonical: Load TrigGuard canonical surfaces
            fail_on_unknown: Raise on unknown surface access
        """
        self._surfaces: dict[str, ExecutionSurfaceDefinition] = {}
        self._aliases: dict[str, str] = {}
        self._fail_on_unknown = fail_on_unknown
        self._version = "1.0"
        self._updated_at = datetime.now(timezone.utc)

        if preload_canonical:
            self._load_canonical_surfaces()

    def _load_canonical_surfaces(self) -> None:
        """Load all canonical TrigGuard surfaces."""
        for surface_id, surface in get_canonical_surfaces().items():
            self._surfaces[surface_id] = surface

        # Set up standard aliases
        self._aliases.update(
            {
                # Legacy uppercase names
                "SPEND": "trigguard.spend.transfer",
                "DATA_EXPORT": "trigguard.data.export",
                "EXPORT": "trigguard.data.export",
                "CODE_EXEC": "trigguard.code.exec",
                "CODE_EXECUTION": "trigguard.code.exec",
                "DELEGATION": "trigguard.delegation.grant",
                "IDENTITY_ASSERTION": "trigguard.identity.assert",
                "DATA_MUTATION": "trigguard.data.mutate",
                "TIME_COMMIT": "trigguard.time.commit",
                "EXTERNAL_API": "trigguard.api.external",
                "INTERNAL_API": "trigguard.api.internal",
                "TOOL_INVOCATION": "trigguard.tool.invoke",
                "INFERENCE": "trigguard.ai.inference",
                "RETRIEVAL": "trigguard.retrieval.search",
                "GENERATION": "trigguard.ai.inference",
                # Common short forms
                "spend": "trigguard.spend.transfer",
                "transfer": "trigguard.spend.transfer",
                "payment": "trigguard.spend.transfer",
                "export": "trigguard.data.export",
                "code": "trigguard.code.exec",
                "exec": "trigguard.code.exec",
                "shell": "trigguard.code.exec",
                "delete": "trigguard.data.delete",
                "identity": "trigguard.identity.assert",
                "delegate": "trigguard.delegation.grant",
                "api": "trigguard.api.external",
                "tool": "trigguard.tool.invoke",
                "inference": "trigguard.ai.inference",
                "search": "trigguard.retrieval.search",
            }
        )

    def register(
        self,
        surface: ExecutionSurfaceDefinition,
        allow_override: bool = False,
    ) -> None:
        """
        Register a surface definition.

        Args:
            surface: Surface definition to register
            allow_override: Allow overriding existing definition

        Raises:
            DuplicateSurfaceError: If surface exists with different definition
        """
        existing = self._surfaces.get(surface.surface_id)

        if existing is not None and not allow_override:
            # Check if definitions match
            if existing.to_canonical_json() != surface.to_canonical_json():
                raise DuplicateSurfaceError(
                    f"Surface '{surface.surface_id}' already registered "
                    "with different definition"
                )
            # Same definition, no-op
            return

        self._surfaces[surface.surface_id] = surface
        self._updated_at = datetime.now(timezone.utc)

    def register_alias(self, alias: str, surface_id: str) -> None:
        """
        Register an alias for a surface.

        Args:
            alias: Alias name (e.g., "SPEND")
            surface_id: Target surface ID (e.g., "trigguard.spend.transfer")

        Raises:
            ValueError: If target surface doesn't exist
        """
        if surface_id not in self._surfaces:
            raise ValueError(f"Target surface '{surface_id}' not registered")

        self._aliases[alias] = surface_id
        self._aliases[alias.lower()] = surface_id
        self._aliases[alias.upper()] = surface_id

    def get(self, surface_id: str) -> Optional[ExecutionSurfaceDefinition]:
        """
        Get a surface definition by ID.

        Does NOT resolve aliases. Use resolve() for that.

        Args:
            surface_id: Canonical surface ID

        Returns:
            Surface definition or None
        """
        return self._surfaces.get(surface_id)

    def resolve(self, surface_or_alias: str) -> Optional[ExecutionSurfaceDefinition]:
        """
        Resolve a surface name or alias to its definition.

        Args:
            surface_or_alias: Surface ID or alias

        Returns:
            Surface definition or None

        Raises:
            UnknownSurfaceError: If fail_on_unknown and surface not found
        """
        # Try direct lookup first
        surface = self._surfaces.get(surface_or_alias)
        if surface is not None:
            return surface

        # Try alias resolution
        canonical_id = self._aliases.get(surface_or_alias)
        if canonical_id is not None:
            return self._surfaces.get(canonical_id)

        # Try case-insensitive alias
        canonical_id = self._aliases.get(surface_or_alias.lower())
        if canonical_id is not None:
            return self._surfaces.get(canonical_id)

        if self._fail_on_unknown:
            raise UnknownSurfaceError(f"Unknown surface: {surface_or_alias}")

        return None

    def resolve_alias(self, alias: str) -> Optional[str]:
        """
        Resolve an alias to canonical surface ID.

        Args:
            alias: Alias name

        Returns:
            Canonical surface ID or None
        """
        return self._aliases.get(alias) or self._aliases.get(alias.lower())

    def normalize(self, surface_or_alias: str) -> str:
        """
        Normalize a surface name to canonical ID.

        Args:
            surface_or_alias: Surface ID or alias

        Returns:
            Canonical surface ID

        Raises:
            UnknownSurfaceError: If surface cannot be resolved
        """
        # Already canonical
        if surface_or_alias in self._surfaces:
            return surface_or_alias

        # Try alias
        canonical_id = self.resolve_alias(surface_or_alias)
        if canonical_id is not None:
            return canonical_id

        # Unknown - return as-is with namespace prefix if needed
        if "." not in surface_or_alias:
            return f"unknown.{surface_or_alias.lower()}"

        return surface_or_alias

    def exists(self, surface_id: str) -> bool:
        """Check if surface exists (by ID, not alias)."""
        return surface_id in self._surfaces

    def is_registered(self, surface_or_alias: str) -> bool:
        """Check if surface or alias is registered."""
        return self.resolve(surface_or_alias) is not None

    def list_all(self) -> "list[ExecutionSurfaceDefinition]":
        """List all registered surfaces."""
        return list(self._surfaces.values())

    def list_ids(self) -> "list[str]":
        """List all registered surface IDs."""
        return sorted(self._surfaces.keys())

    def list_by_risk(
        self, risk_tier: SurfaceRiskTier
    ) -> "list[ExecutionSurfaceDefinition]":
        """
        List surfaces by risk tier.

        Args:
            risk_tier: Risk tier to filter by

        Returns:
            List of surfaces with that risk tier
        """
        return [s for s in self._surfaces.values() if s.risk_tier == risk_tier]

    def list_by_namespace(self, namespace: str) -> list[ExecutionSurfaceDefinition]:
        """
        List surfaces by namespace.

        Args:
            namespace: Namespace to filter by (e.g., "trigguard")

        Returns:
            List of surfaces in that namespace
        """
        return [s for s in self._surfaces.values() if s.namespace == namespace]

    def list_by_tags(self, *tags: str) -> list[ExecutionSurfaceDefinition]:
        """
        List surfaces matching any of the given tags.

        Args:
            tags: Tags to search for

        Returns:
            List of matching surfaces
        """
        return [s for s in self._surfaces.values() if s.matches_tags(*tags)]

    def list_irreversible(self) -> list[ExecutionSurfaceDefinition]:
        """List all irreversible surfaces."""
        return self.list_by_risk(SurfaceRiskTier.IRREVERSIBLE)

    def get_risk_tier(self, surface_or_alias: str) -> Optional[SurfaceRiskTier]:
        """
        Get risk tier for a surface.

        Args:
            surface_or_alias: Surface ID or alias

        Returns:
            Risk tier or None if not found
        """
        surface = self.resolve(surface_or_alias)
        return surface.risk_tier if surface else None

    def requires_grant(self, surface_or_alias: str) -> bool:
        """
        Check if surface requires a signed Action Grant.

        Args:
            surface_or_alias: Surface ID or alias

        Returns:
            True if grant required, False otherwise
        """
        surface = self.resolve(surface_or_alias)
        if surface is None:
            # Unknown surfaces require grants by default (fail-safe)
            return True
        return surface.requires_grant

    def export_manifest(self) -> dict[str, Any]:
        """
        Export registry as a manifest dictionary.

        Deterministic output suitable for hashing or comparison.
        """
        return {
            "issuer": "trigguard",
            "version": self._version,
            "updated_at": self._updated_at.isoformat(),
            "surface_count": len(self._surfaces),
            "surfaces": [
                self._surfaces[sid].to_dict() for sid in sorted(self._surfaces.keys())
            ],
            "aliases": dict(sorted(self._aliases.items())),
        }

    def to_canonical_json(self) -> str:
        """Deterministic JSON export."""
        return json.dumps(
            self.export_manifest(),
            separators=(",", ":"),
            sort_keys=True,
        )

    def __len__(self) -> int:
        return len(self._surfaces)

    def __contains__(self, surface_id: str) -> bool:
        return surface_id in self._surfaces


# Global registry singleton
_global_registry: Optional[ExecutionSurfaceRegistry] = None


def get_global_surface_registry() -> ExecutionSurfaceRegistry:
    """
    Get the global surface registry singleton.

    The registry is lazily initialized with canonical TrigGuard surfaces.
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = ExecutionSurfaceRegistry(preload_canonical=True)
    return _global_registry


def reset_global_surface_registry() -> None:
    """Reset the global registry (for testing)."""
    global _global_registry
    _global_registry = None


def normalize_surface(surface: str) -> str:
    """
    Normalize a surface name to canonical ID.

    Convenience function using global registry.
    """
    return get_global_surface_registry().normalize(surface)


def is_registered_surface(surface: str) -> bool:
    """
    Check if a surface is registered.

    Convenience function using global registry.
    """
    return get_global_surface_registry().is_registered(surface)


def get_surface_definition(surface: str) -> Optional[ExecutionSurfaceDefinition]:
    """
    Get surface definition by ID or alias.

    Convenience function using global registry.
    """
    return get_global_surface_registry().resolve(surface)
