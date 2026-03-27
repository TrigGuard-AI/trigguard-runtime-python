"""
Execution Surface Types

Canonical type definitions for execution surfaces in TrigGuard.

Surface identities are namespaced, versioned, and portable:
- trigguard.spend.transfer
- trigguard.code.exec
- openai.tool.call
- langchain.tool.invoke

Risk tiers classify surfaces by reversibility and impact:
- LOW: Read-only, retrieval
- MEDIUM: Internal mutations
- HIGH: External effects
- IRREVERSIBLE: Cannot be undone (financial, identity, delegation)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class SurfaceRiskTier(Enum):
    """
    Risk classification for execution surfaces.

    Determines default policy behavior and verification requirements.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    IRREVERSIBLE = "irreversible"

    def __lt__(self, other: "SurfaceRiskTier") -> bool:
        order = [
            SurfaceRiskTier.LOW,
            SurfaceRiskTier.MEDIUM,
            SurfaceRiskTier.HIGH,
            SurfaceRiskTier.IRREVERSIBLE,
        ]
        return order.index(self) < order.index(other)

    @property
    def requires_grant(self) -> bool:
        """Check if this tier requires a signed Action Grant."""
        return self in (SurfaceRiskTier.HIGH, SurfaceRiskTier.IRREVERSIBLE)

    @property
    def fail_closed(self) -> bool:
        """Check if this tier should fail closed on errors."""
        return self == SurfaceRiskTier.IRREVERSIBLE


@dataclass
class ExecutionSurfaceDefinition:
    """
    Canonical definition of an execution surface.

    This is the registry entry that defines what a surface IS,
    independent of policy decisions about whether it's ALLOWED.

    Fields:
        surface_id: Canonical namespaced identifier (e.g., "trigguard.spend.transfer")
        namespace: Top-level namespace (e.g., "trigguard", "openai")
        display_name: Human-readable name
        description: Full description of what this surface does
        risk_tier: Risk classification
        reversible: Whether actions on this surface can be undone
        default_constraints: Default constraint schema for grants
        examples: Example actions/invocations
        tags: Searchable tags
        version: Definition version for evolution
        deprecated: Whether this surface is deprecated
        successor: If deprecated, what surface replaces it
        created_at: When this definition was created
    """

    # Core identity
    surface_id: str
    namespace: str
    display_name: str
    description: str

    # Risk classification
    risk_tier: SurfaceRiskTier
    reversible: bool

    # Constraints and examples
    default_constraints: dict[str, Any] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # Version tracking
    version: str = "1.0"
    deprecated: bool = False
    successor: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate surface_id format."""
        if not self.surface_id:
            raise ValueError("surface_id cannot be empty")

        parts = self.surface_id.split(".")
        if len(parts) < 2:
            raise ValueError(
                f"surface_id must be namespaced (got: {self.surface_id}). "
                "Expected format: namespace.category.action"
            )

        expected_namespace = parts[0]
        if self.namespace != expected_namespace:
            raise ValueError(
                f"namespace '{self.namespace}' does not match "
                f"surface_id prefix '{expected_namespace}'"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "surface_id": self.surface_id,
            "namespace": self.namespace,
            "display_name": self.display_name,
            "description": self.description,
            "risk_tier": self.risk_tier.value,
            "reversible": self.reversible,
            "default_constraints": self.default_constraints,
            "examples": self.examples,
            "tags": self.tags,
            "version": self.version,
            "deprecated": self.deprecated,
            "successor": self.successor,
            "created_at": self.created_at.isoformat(),
        }

    def to_canonical_json(self) -> str:
        """Deterministic JSON representation."""
        return json.dumps(
            self.to_dict(),
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionSurfaceDefinition":
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif created_at is None:
            created_at = datetime.now(timezone.utc)

        return cls(
            surface_id=data["surface_id"],
            namespace=data["namespace"],
            display_name=data["display_name"],
            description=data["description"],
            risk_tier=SurfaceRiskTier(data["risk_tier"]),
            reversible=data["reversible"],
            default_constraints=data.get("default_constraints", {}),
            examples=data.get("examples", []),
            tags=data.get("tags", []),
            version=data.get("version", "1.0"),
            deprecated=data.get("deprecated", False),
            successor=data.get("successor"),
            created_at=created_at,
        )

    def matches_tags(self, *search_tags: str) -> bool:
        """Check if surface matches any of the given tags."""
        lowercase_tags = [t.lower() for t in self.tags]
        return any(tag.lower() in lowercase_tags for tag in search_tags)

    @property
    def requires_grant(self) -> bool:
        """Check if this surface requires a signed Action Grant."""
        return self.risk_tier.requires_grant

    @property
    def fail_closed(self) -> bool:
        """Check if this surface should fail closed on errors."""
        return self.risk_tier.fail_closed


# Canonical TrigGuard surface definitions
CANONICAL_SURFACES: dict[str, ExecutionSurfaceDefinition] = {}


def _define_canonical_surface(
    surface_id: str,
    display_name: str,
    description: str,
    risk_tier: SurfaceRiskTier,
    reversible: bool,
    tags: list[str],
    **kwargs: Any,
) -> ExecutionSurfaceDefinition:
    """Helper to define and register a canonical surface."""
    namespace = surface_id.split(".")[0]
    surface = ExecutionSurfaceDefinition(
        surface_id=surface_id,
        namespace=namespace,
        display_name=display_name,
        description=description,
        risk_tier=risk_tier,
        reversible=reversible,
        tags=tags,
        **kwargs,
    )
    CANONICAL_SURFACES[surface_id] = surface
    return surface


# ============================================================
# TRIGGUARD CANONICAL SURFACES
# ============================================================

# Financial
SURFACE_SPEND_TRANSFER = _define_canonical_surface(
    surface_id="trigguard.spend.transfer",
    display_name="Spend Transfer",
    description="Transfer of monetary value between accounts or to external parties",
    risk_tier=SurfaceRiskTier.IRREVERSIBLE,
    reversible=False,
    tags=["money", "payment", "financial", "irreversible"],
    default_constraints={"max_amount": None, "allowed_currency": None},
    examples=["bank transfer", "payment", "wire transfer", "crypto send"],
)

SURFACE_SPEND_AUTHORIZE = _define_canonical_surface(
    surface_id="trigguard.spend.authorize",
    display_name="Spend Authorization",
    description="Authorization of future spending without immediate transfer",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=True,
    tags=["money", "authorization", "financial"],
    examples=["credit card authorization", "pre-auth hold"],
)

# Data
SURFACE_DATA_EXPORT = _define_canonical_surface(
    surface_id="trigguard.data.export",
    display_name="Data Export",
    description="Export of data to external systems or files",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=False,
    tags=["data", "export", "privacy", "exfiltration"],
    examples=["file download", "API export", "data dump"],
)

SURFACE_DATA_DELETE = _define_canonical_surface(
    surface_id="trigguard.data.delete",
    display_name="Data Deletion",
    description="Permanent deletion of data",
    risk_tier=SurfaceRiskTier.IRREVERSIBLE,
    reversible=False,
    tags=["data", "delete", "destructive", "irreversible"],
    examples=["record deletion", "file removal", "account purge"],
)

SURFACE_DATA_MUTATE = _define_canonical_surface(
    surface_id="trigguard.data.mutate",
    display_name="Data Mutation",
    description="Modification of existing data",
    risk_tier=SurfaceRiskTier.MEDIUM,
    reversible=True,
    tags=["data", "mutation", "update"],
    examples=["record update", "field modification"],
)

# Code
SURFACE_CODE_EXEC = _define_canonical_surface(
    surface_id="trigguard.code.exec",
    display_name="Code Execution",
    description="Execution of arbitrary code or scripts",
    risk_tier=SurfaceRiskTier.IRREVERSIBLE,
    reversible=False,
    tags=["code", "execution", "script", "dangerous"],
    default_constraints={"allowed_command": None},
    examples=["shell command", "script execution", "REPL eval"],
)

SURFACE_CODE_DEPLOY = _define_canonical_surface(
    surface_id="trigguard.code.deploy",
    display_name="Code Deployment",
    description="Deployment of code to production or staging environments",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=True,
    tags=["code", "deployment", "infrastructure"],
    examples=["production deploy", "release", "CI/CD trigger"],
)

# Identity
SURFACE_IDENTITY_ASSERT = _define_canonical_surface(
    surface_id="trigguard.identity.assert",
    display_name="Identity Assertion",
    description="Acting as or asserting a specific identity",
    risk_tier=SurfaceRiskTier.IRREVERSIBLE,
    reversible=False,
    tags=["identity", "impersonation", "authentication"],
    examples=["sign as user", "act as admin", "identity claim"],
)

SURFACE_IDENTITY_GRANT = _define_canonical_surface(
    surface_id="trigguard.identity.grant",
    display_name="Identity Grant",
    description="Granting identity or access to another party",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=True,
    tags=["identity", "access", "permissions"],
    examples=["invite user", "grant role", "share access"],
)

# Delegation
SURFACE_DELEGATION_GRANT = _define_canonical_surface(
    surface_id="trigguard.delegation.grant",
    display_name="Delegation Grant",
    description="Delegation of authority to another agent or system",
    risk_tier=SurfaceRiskTier.IRREVERSIBLE,
    reversible=False,
    tags=["delegation", "authority", "trust"],
    examples=["agent delegation", "permission transfer", "proxy authorization"],
)

SURFACE_DELEGATION_REVOKE = _define_canonical_surface(
    surface_id="trigguard.delegation.revoke",
    display_name="Delegation Revocation",
    description="Revocation of previously delegated authority",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=False,
    tags=["delegation", "revocation", "authority"],
    examples=["revoke agent", "remove delegation"],
)

# Time-sensitive
SURFACE_TIME_COMMIT = _define_canonical_surface(
    surface_id="trigguard.time.commit",
    display_name="Time Commitment",
    description="Time-sensitive commitment that cannot be easily changed",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=False,
    tags=["time", "commitment", "deadline", "schedule"],
    examples=["meeting booking", "deadline commitment", "contract signature"],
)

# External APIs
SURFACE_API_EXTERNAL = _define_canonical_surface(
    surface_id="trigguard.api.external",
    display_name="External API Call",
    description="Call to external third-party API",
    risk_tier=SurfaceRiskTier.MEDIUM,
    reversible=True,
    tags=["api", "external", "third-party"],
    examples=["REST API call", "webhook trigger", "service invocation"],
)

SURFACE_API_INTERNAL = _define_canonical_surface(
    surface_id="trigguard.api.internal",
    display_name="Internal API Call",
    description="Call to internal system API",
    risk_tier=SurfaceRiskTier.LOW,
    reversible=True,
    tags=["api", "internal", "system"],
    examples=["internal service call", "microservice invocation"],
)

# Tool Invocation
SURFACE_TOOL_INVOKE = _define_canonical_surface(
    surface_id="trigguard.tool.invoke",
    display_name="Tool Invocation",
    description="Invocation of a registered tool or function",
    risk_tier=SurfaceRiskTier.MEDIUM,
    reversible=True,
    tags=["tool", "function", "invocation"],
    examples=["tool call", "function invocation", "MCP tool"],
)

# AI/LLM
SURFACE_AI_INFERENCE = _define_canonical_surface(
    surface_id="trigguard.ai.inference",
    display_name="AI Inference",
    description="AI model inference or generation",
    risk_tier=SurfaceRiskTier.LOW,
    reversible=True,
    tags=["ai", "inference", "llm", "generation"],
    examples=["LLM completion", "embedding generation", "classification"],
)

SURFACE_AI_FINETUNE = _define_canonical_surface(
    surface_id="trigguard.ai.finetune",
    display_name="AI Finetuning",
    description="Finetuning or training of AI models",
    risk_tier=SurfaceRiskTier.HIGH,
    reversible=False,
    tags=["ai", "training", "finetuning", "ml"],
    examples=["model finetuning", "training job", "RLHF"],
)

# Retrieval
SURFACE_RETRIEVAL_SEARCH = _define_canonical_surface(
    surface_id="trigguard.retrieval.search",
    display_name="Retrieval Search",
    description="Search and retrieval from knowledge bases",
    risk_tier=SurfaceRiskTier.LOW,
    reversible=True,
    tags=["retrieval", "search", "rag", "knowledge"],
    examples=["vector search", "semantic search", "knowledge retrieval"],
)


def get_canonical_surfaces() -> dict[str, ExecutionSurfaceDefinition]:
    """Get all canonical TrigGuard surfaces."""
    return CANONICAL_SURFACES.copy()


def get_canonical_surface(surface_id: str) -> Optional[ExecutionSurfaceDefinition]:
    """Get a canonical surface by ID."""
    return CANONICAL_SURFACES.get(surface_id)
