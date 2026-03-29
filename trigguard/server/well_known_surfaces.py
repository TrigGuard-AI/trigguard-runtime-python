"""
Well-Known Surface Endpoints

Public endpoints for surface registry and discovery.

Endpoints:
    GET /.well-known/trigguard-surfaces
        Returns canonical surface registry

    GET /.well-known/trigguard-discovery
        Returns discovery manifest for this TrigGuard instance

These endpoints allow external tools and executors to:
- Discover what surfaces TrigGuard recognizes
- Understand surface risk tiers and constraints
- Self-register their capabilities
"""

try:
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

    class APIRouter:
        def __init__(self, **kwargs):
            pass

        def get(self, *args, **kwargs):
            def decorator(f):
                return f

            return decorator

    class JSONResponse:
        def __init__(self, content, headers=None):
            self.content = content
            self.headers = headers or {}


from datetime import datetime, timezone
from typing import Any, Optional

from trigguard.registry.surface_registry import get_global_surface_registry
from trigguard.registry.surface_types import SurfaceRiskTier
from trigguard.discovery.discovery_contract import (
    DiscoveryManifest,
    SurfaceDiscoveryRecord,
    ConstraintSchema,
)
from trigguard.attestation import AttestationRegistry

# Router for well-known surface endpoints
surface_router = APIRouter(tags=["well-known", "surfaces"])

# Current discovery manifest (configured at startup)
_current_manifest: Optional[DiscoveryManifest] = None


def configure_discovery_manifest(manifest: DiscoveryManifest) -> None:
    """
    Configure the discovery manifest for this instance.

    Called during server startup to set capabilities.

    Args:
        manifest: Discovery manifest to serve
    """
    global _current_manifest
    _current_manifest = manifest


def get_current_manifest() -> Optional[DiscoveryManifest]:
    """Get the currently configured discovery manifest."""
    return _current_manifest


def build_default_manifest() -> DiscoveryManifest:
    """
    Build default discovery manifest from registry.

    Creates a manifest advertising all canonical surfaces.
    """
    registry = get_global_surface_registry()
    surfaces = []

    for surface_def in registry.list_all():
        # Build constraint schema based on surface
        constraint_schema = ConstraintSchema()
        if "money" in surface_def.tags or "payment" in surface_def.tags:
            constraint_schema.supports_max_amount = True
            constraint_schema.supports_currency = True
        if "code" in surface_def.tags:
            constraint_schema.supports_command_allowlist = True
        constraint_schema.supports_resource_binding = True

        record = SurfaceDiscoveryRecord(
            surface_id=surface_def.surface_id,
            supported_actions=[],  # All actions
            resource_types=[],  # All resources
            constraint_schema=constraint_schema,
            verifier_required=surface_def.risk_tier >= SurfaceRiskTier.HIGH,
            grant_required=surface_def.requires_grant,
        )
        surfaces.append(record)

    return DiscoveryManifest(
        issuer="trigguard",
        version="1.0",
        surfaces=surfaces,
    )


@surface_router.get("/.well-known/trigguard-surfaces")
async def get_trigguard_surfaces():
    """
    Surface registry endpoint.

    Returns canonical TrigGuard surface definitions.
    External tools use this to understand:
    - What surfaces are recognized
    - Risk tiers for each surface
    - Default constraints
    - Tags for classification

    Response:
        {
            "issuer": "trigguard",
            "version": "1.0",
            "updated_at": "2026-03-27T12:00:00Z",
            "surface_count": 18,
            "surfaces": [
                {
                    "surface_id": "trigguard.spend.transfer",
                    "display_name": "Spend Transfer",
                    "risk_tier": "irreversible",
                    "reversible": false,
                    "tags": ["money", "payment", "irreversible"]
                }
            ]
        }
    """
    registry = get_global_surface_registry()
    attestation_registry = AttestationRegistry.get_global()

    # Build response
    surfaces = []
    for surface_def in sorted(registry.list_all(), key=lambda s: s.surface_id):
        # Get attestation hash if available
        attestation = attestation_registry.get(surface_def.surface_id)
        code_hash = attestation.code_hash if attestation else None

        surfaces.append(
            {
                "surface_id": surface_def.surface_id,
                "namespace": surface_def.namespace,
                "display_name": surface_def.display_name,
                "description": surface_def.description,
                "risk_tier": surface_def.risk_tier.value,
                "reversible": surface_def.reversible,
                "tags": surface_def.tags,
                "requires_grant": surface_def.requires_grant,
                "version": surface_def.version,
                "code_hash": code_hash,
            }
        )

    response = {
        "issuer": "trigguard",
        "version": "1.0",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "surface_count": len(surfaces),
        "surfaces": surfaces,
    }

    return JSONResponse(
        content=response,
        headers={
            "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
        },
    )


@surface_router.get("/.well-known/trigguard-discovery")
async def get_trigguard_discovery():
    """
    Discovery manifest endpoint.

    Returns this TrigGuard instance's capability manifest.
    External executors use this to understand:
    - What surfaces this instance can govern
    - What actions are supported
    - What constraints can be verified
    - Grant/verifier requirements

    Response:
        {
            "issuer": "trigguard",
            "version": "1.0",
            "updated_at": "2026-03-27T12:00:00Z",
            "surface_count": 18,
            "surfaces": [
                {
                    "surface_id": "trigguard.spend.transfer",
                    "supported_actions": [],
                    "resource_types": [],
                    "verifier_required": true,
                    "grant_required": true,
                    "constraint_schema": {
                        "max_amount": {"type": "number"},
                        "currency": {"type": "string"}
                    }
                }
            ]
        }
    """
    global _current_manifest

    if _current_manifest is None:
        _current_manifest = build_default_manifest()

    return JSONResponse(
        content=_current_manifest.to_dict(),
        headers={
            "Cache-Control": "public, max-age=3600",
        },
    )


@surface_router.get("/.well-known/trigguard-surfaces/{surface_id:path}")
async def get_surface_by_id(surface_id: str):
    """
    Get a specific surface by ID.

    Args:
        surface_id: Canonical surface ID or alias

    Returns:
        Surface definition or 404
    """
    registry = get_global_surface_registry()
    surface_def = registry.resolve(surface_id)

    if surface_def is None:
        return JSONResponse(
            content={"error": f"Surface not found: {surface_id}"},
            headers={"Cache-Control": "no-cache"},
        )

    return JSONResponse(
        content={
            "surface_id": surface_def.surface_id,
            "namespace": surface_def.namespace,
            "display_name": surface_def.display_name,
            "description": surface_def.description,
            "risk_tier": surface_def.risk_tier.value,
            "reversible": surface_def.reversible,
            "tags": surface_def.tags,
            "requires_grant": surface_def.requires_grant,
            "default_constraints": surface_def.default_constraints,
            "examples": surface_def.examples,
            "version": surface_def.version,
            "deprecated": surface_def.deprecated,
            "successor": surface_def.successor,
        },
        headers={
            "Cache-Control": "public, max-age=3600",
        },
    )


@surface_router.get("/.well-known/trigguard-surfaces-by-risk/{risk_tier}")
async def get_surfaces_by_risk(risk_tier: str):
    """
    Get surfaces by risk tier.

    Args:
        risk_tier: Risk tier (low, medium, high, irreversible)

    Returns:
        List of surfaces with that risk tier
    """
    registry = get_global_surface_registry()

    try:
        tier = SurfaceRiskTier(risk_tier.lower())
    except ValueError:
        return JSONResponse(
            content={
                "error": f"Invalid risk tier: {risk_tier}",
                "valid_tiers": ["low", "medium", "high", "irreversible"],
            },
            headers={"Cache-Control": "no-cache"},
        )

    surfaces = registry.list_by_risk(tier)

    return JSONResponse(
        content={
            "risk_tier": risk_tier,
            "surface_count": len(surfaces),
            "surfaces": [
                {
                    "surface_id": s.surface_id,
                    "display_name": s.display_name,
                    "requires_grant": s.requires_grant,
                }
                for s in sorted(surfaces, key=lambda x: x.surface_id)
            ],
        },
        headers={
            "Cache-Control": "public, max-age=3600",
        },
    )


@surface_router.get("/.well-known/trigguard-aliases")
async def get_surface_aliases():
    """
    Get surface alias mappings.

    Returns mapping of aliases to canonical surface IDs.
    Useful for tooling that needs to normalize surface names.
    """
    registry = get_global_surface_registry()

    # Build alias map (deduplicated)
    aliases = {}
    for surface_def in registry.list_all():
        aliases[surface_def.surface_id] = surface_def.surface_id

    # Add registry aliases
    manifest = registry.export_manifest()
    alias_map = manifest.get("aliases", {})

    # Group by canonical ID
    grouped: dict[str, list[str]] = {}
    for alias, canonical in alias_map.items():
        if canonical not in grouped:
            grouped[canonical] = []
        if alias != canonical:
            grouped[canonical].append(alias)

    return JSONResponse(
        content={
            "issuer": "trigguard",
            "alias_count": len(alias_map),
            "aliases": alias_map,
            "grouped": {k: sorted(v) for k, v in sorted(grouped.items())},
        },
        headers={
            "Cache-Control": "public, max-age=3600",
        },
    )
