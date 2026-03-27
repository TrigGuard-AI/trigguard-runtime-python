"""
TrigGuard Execution Surface Registry

Canonical definitions for execution surfaces and their properties.

Irreversible surfaces (Tier 1) require strict authorization:
- SPEND: Financial transactions
- DATA_EXPORT: Data leaving the system
- CODE_EXEC: Running arbitrary code
- DELEGATION: Authority transfer
- IDENTITY_ASSERTION: Acting as a specific identity

These surfaces trigger fail-closed behavior if evaluation fails.
"""

from enum import Enum
from typing import Set

from trigguard.protocol.decision_contracts import ExecutionSurface

# Canonical surface aliases for SDK convenience
SPEND = ExecutionSurface.SPEND
DATA_EXPORT = ExecutionSurface.EXPORT
CODE_EXEC = ExecutionSurface.CODE_EXECUTION
DELEGATION = ExecutionSurface.DELEGATION
IDENTITY_ASSERTION = ExecutionSurface.IDENTITY_ASSERTION
TIME_COMMIT = ExecutionSurface.DATA_MUTATION  # Time-sensitive commits

# Surface categories
IRREVERSIBLE_SURFACES: Set[ExecutionSurface] = {
    ExecutionSurface.SPEND,
    ExecutionSurface.EXPORT,
    ExecutionSurface.CODE_EXECUTION,
    ExecutionSurface.DELEGATION,
    ExecutionSurface.IDENTITY_ASSERTION,
    ExecutionSurface.DATA_MUTATION,
}

TIER1_SURFACES = IRREVERSIBLE_SURFACES

TIER2_SURFACES: Set[ExecutionSurface] = {
    ExecutionSurface.EXTERNAL_API,
    ExecutionSurface.INTERNAL_API,
    ExecutionSurface.TOOL_INVOCATION,
}

TIER3_SURFACES: Set[ExecutionSurface] = {
    ExecutionSurface.INFERENCE,
    ExecutionSurface.RETRIEVAL,
    ExecutionSurface.GENERATION,
}


def is_irreversible(surface: ExecutionSurface) -> bool:
    """
    Check if a surface involves irreversible actions.

    Irreversible surfaces require stricter policy evaluation
    and trigger fail-closed behavior on errors.

    Args:
        surface: The execution surface to check

    Returns:
        True if the surface is irreversible
    """
    return surface in IRREVERSIBLE_SURFACES


def get_risk_tier(surface: ExecutionSurface) -> int:
    """
    Get the risk tier for a surface.

    Tier 1: Irreversible (highest risk)
    Tier 2: Medium risk
    Tier 3: Low risk

    Args:
        surface: The execution surface

    Returns:
        Risk tier (1, 2, or 3)
    """
    if surface in TIER1_SURFACES:
        return 1
    if surface in TIER2_SURFACES:
        return 2
    return 3


def requires_strict_evaluation(surface: ExecutionSurface) -> bool:
    """
    Check if surface requires strict policy evaluation.

    Strict evaluation means:
    - Any CRITICAL signal triggers DENY
    - Missing required signals trigger DENY
    - Fail-closed on any error

    Args:
        surface: The execution surface

    Returns:
        True if strict evaluation is required
    """
    return get_risk_tier(surface) == 1


def parse_surface(surface_str: str) -> ExecutionSurface:
    """
    Parse a surface string to ExecutionSurface enum.

    Supports both canonical names and aliases.

    Args:
        surface_str: Surface name (e.g., "SPEND", "CODE_EXEC")

    Returns:
        ExecutionSurface enum value

    Raises:
        ValueError: If surface is not recognized
    """
    # Alias mapping
    aliases = {
        "code_exec": ExecutionSurface.CODE_EXECUTION,
        "data_export": ExecutionSurface.EXPORT,
        "time_commit": ExecutionSurface.DATA_MUTATION,
    }

    normalized = surface_str.lower().strip()

    # Check aliases first
    if normalized in aliases:
        return aliases[normalized]

    # Try direct enum lookup
    try:
        return ExecutionSurface(normalized)
    except ValueError:
        pass

    # Try uppercase enum name
    try:
        return ExecutionSurface[surface_str.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown surface: {surface_str}")


__all__ = [
    # Surface constants
    "SPEND",
    "DATA_EXPORT",
    "CODE_EXEC",
    "DELEGATION",
    "IDENTITY_ASSERTION",
    "TIME_COMMIT",
    # Surface sets
    "IRREVERSIBLE_SURFACES",
    "TIER1_SURFACES",
    "TIER2_SURFACES",
    "TIER3_SURFACES",
    # Functions
    "is_irreversible",
    "get_risk_tier",
    "requires_strict_evaluation",
    "parse_surface",
]
