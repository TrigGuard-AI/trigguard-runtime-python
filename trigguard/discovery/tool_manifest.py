"""
Tool Surface Manifest

Utilities for tools and agents to declare their execution surfaces.

This module allows integrations to self-describe what surfaces they
operate on and what grant/verification requirements they expect.

Usage:
    from trigguard.discovery import ToolSurfaceManifest

    # From a tool definition
    manifest = ToolSurfaceManifest.from_tool_definition({
        "name": "send_payment",
        "description": "Send a payment to a recipient",
        "parameters": {"amount": {"type": "number"}, "currency": {"type": "string"}},
    })

    # From a callable
    @manifest.declares_surface("trigguard.spend.transfer")
    def send_payment(amount: float, currency: str):
        ...
"""

import inspect
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union

from trigguard.discovery.discovery_contract import (
    SurfaceDiscoveryRecord,
    DiscoveryManifest,
    ConstraintSchema,
)
from trigguard.registry.surface_registry import (
    get_global_surface_registry,
    get_surface_definition,
)
from trigguard.registry.surface_types import SurfaceRiskTier

F = TypeVar("F", bound=Callable[..., Any])


# Surface inference heuristics
SURFACE_KEYWORDS: dict[str, str] = {
    # Money/payment
    "pay": "trigguard.spend.transfer",
    "payment": "trigguard.spend.transfer",
    "transfer": "trigguard.spend.transfer",
    "send_money": "trigguard.spend.transfer",
    "wire": "trigguard.spend.transfer",
    "charge": "trigguard.spend.transfer",
    # Data
    "export": "trigguard.data.export",
    "download": "trigguard.data.export",
    "dump": "trigguard.data.export",
    "delete": "trigguard.data.delete",
    "remove": "trigguard.data.delete",
    "update": "trigguard.data.mutate",
    "modify": "trigguard.data.mutate",
    # Code
    "exec": "trigguard.code.exec",
    "execute": "trigguard.code.exec",
    "run": "trigguard.code.exec",
    "shell": "trigguard.code.exec",
    "eval": "trigguard.code.exec",
    "deploy": "trigguard.code.deploy",
    # API
    "api": "trigguard.api.external",
    "request": "trigguard.api.external",
    "webhook": "trigguard.api.external",
    # Tool
    "tool": "trigguard.tool.invoke",
    "invoke": "trigguard.tool.invoke",
    "call": "trigguard.tool.invoke",
    # AI
    "generate": "trigguard.ai.inference",
    "complete": "trigguard.ai.inference",
    "infer": "trigguard.ai.inference",
    # Search
    "search": "trigguard.retrieval.search",
    "retrieve": "trigguard.retrieval.search",
    "query": "trigguard.retrieval.search",
}


def infer_surface_from_name(name: str) -> Optional[str]:
    """
    Infer surface ID from function/tool name.

    Uses keyword matching heuristics.

    Args:
        name: Function or tool name

    Returns:
        Inferred surface ID or None
    """
    name_lower = name.lower()

    # Try exact match
    if name_lower in SURFACE_KEYWORDS:
        return SURFACE_KEYWORDS[name_lower]

    # Try word matching
    for keyword, surface_id in SURFACE_KEYWORDS.items():
        if keyword in name_lower:
            return surface_id

    return None


def infer_constraints_from_parameters(
    parameters: dict[str, Any],
) -> ConstraintSchema:
    """
    Infer constraint schema from parameter definitions.

    Args:
        parameters: Parameter schema (OpenAPI-style or type dicts)

    Returns:
        Inferred constraint schema
    """
    schema = ConstraintSchema()

    for param_name, param_def in parameters.items():
        param_lower = param_name.lower()

        # Amount detection
        if param_lower in ("amount", "value", "sum", "total", "price"):
            schema.supports_max_amount = True

        # Currency detection
        if param_lower in ("currency", "currency_code", "curr"):
            schema.supports_currency = True

        # Command detection
        if param_lower in ("command", "cmd", "shell", "script"):
            schema.supports_command_allowlist = True

        # Resource detection
        if param_lower in (
            "resource",
            "resource_id",
            "id",
            "account",
            "account_id",
            "file",
            "path",
        ):
            schema.supports_resource_binding = True

    return schema


@dataclass
class ToolSurfaceManifest:
    """
    Manifest builder for tool surface declarations.

    Provides utilities to:
    - Infer surfaces from tool definitions
    - Build discovery records from callables
    - Decorate functions with surface metadata
    """

    issuer: str
    records: dict[str, SurfaceDiscoveryRecord] = field(default_factory=dict)
    _updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_record(self, record: SurfaceDiscoveryRecord) -> None:
        """Add a surface discovery record."""
        self.records[record.surface_id] = record
        self._updated_at = datetime.now(timezone.utc)

    def declare_surface(
        self,
        surface_id: str,
        actions: Optional[list[str]] = None,
        resource_types: Optional[list[str]] = None,
        grant_required: Optional[bool] = None,
        verifier_required: bool = True,
        constraint_schema: Optional[ConstraintSchema] = None,
    ) -> SurfaceDiscoveryRecord:
        """
        Declare support for a surface.

        Args:
            surface_id: Canonical surface ID
            actions: Supported actions (None = all)
            resource_types: Supported resource types
            grant_required: Whether grant is required (None = infer from registry)
            verifier_required: Whether signature verification required
            constraint_schema: Constraint schema

        Returns:
            Created discovery record
        """
        # Infer grant_required from registry if not specified
        if grant_required is None:
            surface_def = get_surface_definition(surface_id)
            grant_required = surface_def.requires_grant if surface_def else True

        record = SurfaceDiscoveryRecord(
            surface_id=surface_id,
            supported_actions=actions or [],
            resource_types=resource_types or [],
            constraint_schema=constraint_schema,
            verifier_required=verifier_required,
            grant_required=grant_required,
        )

        self.add_record(record)
        return record

    def to_discovery_manifest(self) -> DiscoveryManifest:
        """Convert to discovery manifest."""
        return DiscoveryManifest(
            issuer=self.issuer,
            surfaces=list(self.records.values()),
            updated_at=self._updated_at,
        )

    @classmethod
    def from_tool_definition(
        cls,
        tool_def: dict[str, Any],
        issuer: Optional[str] = None,
        surface_id: Optional[str] = None,
    ) -> "ToolSurfaceManifest":
        """
        Create manifest from a tool definition.

        Supports OpenAI/Anthropic/MCP tool schemas.

        Args:
            tool_def: Tool definition dictionary
            issuer: Issuer name (defaults to tool name)
            surface_id: Override surface ID (otherwise inferred)

        Returns:
            ToolSurfaceManifest instance
        """
        name = tool_def.get("name", "unknown_tool")
        description = tool_def.get("description", "")
        parameters = tool_def.get("parameters", {})

        # Handle nested properties (OpenAPI style)
        if "properties" in parameters:
            parameters = parameters["properties"]

        issuer = issuer or name

        # Infer surface if not provided
        if surface_id is None:
            surface_id = infer_surface_from_name(name)
            if surface_id is None:
                surface_id = "trigguard.tool.invoke"

        # Infer constraints
        constraint_schema = infer_constraints_from_parameters(parameters)

        manifest = cls(issuer=issuer)
        manifest.declare_surface(
            surface_id=surface_id,
            actions=[name],
            constraint_schema=constraint_schema,
        )

        return manifest

    @classmethod
    def from_callable(
        cls,
        func: Callable[..., Any],
        issuer: Optional[str] = None,
        surface_id: Optional[str] = None,
    ) -> "ToolSurfaceManifest":
        """
        Create manifest from a callable.

        Inspects function signature to infer surface and constraints.

        Args:
            func: Function to analyze
            issuer: Issuer name (defaults to module.function)
            surface_id: Override surface ID

        Returns:
            ToolSurfaceManifest instance
        """
        name = func.__name__
        module = getattr(func, "__module__", "unknown")
        issuer = issuer or f"{module}.{name}"

        # Get signature
        sig = inspect.signature(func)
        parameters = {}

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            param_type = "any"
            if param.annotation != inspect.Parameter.empty:
                param_type = getattr(
                    param.annotation, "__name__", str(param.annotation)
                )
            parameters[param_name] = {"type": param_type}

        # Infer surface
        if surface_id is None:
            surface_id = infer_surface_from_name(name)
            if surface_id is None:
                # Check docstring for hints
                doc = func.__doc__ or ""
                for keyword, sid in SURFACE_KEYWORDS.items():
                    if keyword in doc.lower():
                        surface_id = sid
                        break

            if surface_id is None:
                surface_id = "trigguard.tool.invoke"

        # Infer constraints
        constraint_schema = infer_constraints_from_parameters(parameters)

        manifest = cls(issuer=issuer)
        manifest.declare_surface(
            surface_id=surface_id,
            actions=[name],
            constraint_schema=constraint_schema,
        )

        return manifest


def declares_surface(
    surface_id: str,
    actions: Optional[list[str]] = None,
    grant_required: Optional[bool] = None,
) -> Callable[[F], F]:
    """
    Decorator to declare surface metadata on a function.

    The metadata is stored on the function for later discovery.

    Usage:
        @declares_surface("trigguard.spend.transfer")
        def send_payment(amount: float) -> bool:
            ...

    Args:
        surface_id: Canonical surface ID
        actions: Supported actions
        grant_required: Whether grant required

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        # Store metadata
        func._trigguard_surface_id = surface_id  # type: ignore
        func._trigguard_actions = actions or [func.__name__]  # type: ignore
        func._trigguard_grant_required = grant_required  # type: ignore

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        # Copy metadata to wrapper
        wrapper._trigguard_surface_id = surface_id  # type: ignore
        wrapper._trigguard_actions = actions or [func.__name__]  # type: ignore
        wrapper._trigguard_grant_required = grant_required  # type: ignore

        return wrapper  # type: ignore

    return decorator


def get_declared_surface(func: Callable[..., Any]) -> Optional[str]:
    """
    Get declared surface ID from a function.

    Args:
        func: Function to inspect

    Returns:
        Surface ID or None if not declared
    """
    return getattr(func, "_trigguard_surface_id", None)


def collect_surfaces_from_module(module: Any) -> DiscoveryManifest:
    """
    Collect surface declarations from a module.

    Scans module for functions decorated with @declares_surface.

    Args:
        module: Python module to scan

    Returns:
        DiscoveryManifest with collected surfaces
    """
    manifest = ToolSurfaceManifest(issuer=module.__name__)

    for name in dir(module):
        obj = getattr(module, name)
        if callable(obj):
            surface_id = get_declared_surface(obj)
            if surface_id:
                actions = getattr(obj, "_trigguard_actions", [name])
                grant_required = getattr(obj, "_trigguard_grant_required", None)
                manifest.declare_surface(
                    surface_id=surface_id,
                    actions=actions,
                    grant_required=grant_required,
                )

    return manifest.to_discovery_manifest()
