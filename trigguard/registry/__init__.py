"""
TrigGuard Execution Surface Registry

Canonical registry of execution surfaces with alias resolution.

Usage:
    from trigguard.registry import (
        get_global_surface_registry,
        ExecutionSurfaceRegistry,
        ExecutionSurfaceDefinition,
        SurfaceRiskTier,
    )

    registry = get_global_surface_registry()

    # Get surface by ID or alias
    surface = registry.resolve("SPEND")  # -> trigguard.spend.transfer

    # Check risk tier
    tier = registry.get_risk_tier("trigguard.code.exec")
"""

from trigguard.registry.surface_types import (
    SurfaceRiskTier,
    ExecutionSurfaceDefinition,
    CANONICAL_SURFACES,
    get_canonical_surfaces,
    get_canonical_surface,
)
from trigguard.registry.surface_registry import (
    ExecutionSurfaceRegistry,
    SurfaceRegistryError,
    DuplicateSurfaceError,
    UnknownSurfaceError,
    get_global_surface_registry,
    reset_global_surface_registry,
    normalize_surface,
    is_registered_surface,
    get_surface_definition,
)

__all__ = [
    # Types
    "SurfaceRiskTier",
    "ExecutionSurfaceDefinition",
    # Registry
    "ExecutionSurfaceRegistry",
    "get_global_surface_registry",
    "reset_global_surface_registry",
    # Errors
    "SurfaceRegistryError",
    "DuplicateSurfaceError",
    "UnknownSurfaceError",
    # Convenience functions
    "normalize_surface",
    "is_registered_surface",
    "get_surface_definition",
    # Canonical surfaces
    "CANONICAL_SURFACES",
    "get_canonical_surfaces",
    "get_canonical_surface",
]
