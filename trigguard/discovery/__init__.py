"""
TrigGuard Discovery Module

Portable contracts for surface discovery and capability advertisement.

Usage:
    from trigguard.discovery import (
        DiscoveryManifest,
        SurfaceDiscoveryRecord,
        ToolSurfaceManifest,
        declares_surface,
    )

    # Declare surface on a function
    @declares_surface("trigguard.spend.transfer")
    def send_payment(amount: float) -> bool:
        ...

    # Build manifest from tool definition
    manifest = ToolSurfaceManifest.from_tool_definition({
        "name": "send_payment",
        "parameters": {"amount": {"type": "number"}},
    })
"""

from trigguard.discovery.discovery_contract import (
    ConstraintSchema,
    SurfaceDiscoveryRecord,
    DiscoveryManifest,
    build_discovery_manifest,
    merge_manifests,
)
from trigguard.discovery.tool_manifest import (
    ToolSurfaceManifest,
    declares_surface,
    get_declared_surface,
    collect_surfaces_from_module,
    infer_surface_from_name,
    infer_constraints_from_parameters,
    SURFACE_KEYWORDS,
)

__all__ = [
    # Discovery contract
    "ConstraintSchema",
    "SurfaceDiscoveryRecord",
    "DiscoveryManifest",
    "build_discovery_manifest",
    "merge_manifests",
    # Tool manifest
    "ToolSurfaceManifest",
    "declares_surface",
    "get_declared_surface",
    "collect_surfaces_from_module",
    "infer_surface_from_name",
    "infer_constraints_from_parameters",
    "SURFACE_KEYWORDS",
]
