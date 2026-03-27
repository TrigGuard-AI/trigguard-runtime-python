"""
Policy Registry

Centralized, versioned policy definitions for TrigGuard.

This module defines:
- POLICY_VERSION: Current policy version
- IRREVERSIBLE_FORBIDDEN: Signals that cause DENY on tier-1 surfaces
- SILENCE_TRIGGERS: Signals that trigger SILENCE response
- THRESHOLDS: Risk thresholds per surface tier

All policy changes must:
1. Increment POLICY_VERSION
2. Update changelog at bottom of file
3. Maintain backwards compatibility or document breaking changes

The DecisionEngine loads policy from this registry.
Policy version is embedded in every DecisionReceipt.
"""

from dataclasses import dataclass, field
from typing import Any

from signals.signal_types import (
    SignalType,
    SignalSeverity,
    SignalCategory,
)

# =============================================================================
# POLICY VERSION
# =============================================================================

POLICY_VERSION = "v1.0.0"

# =============================================================================
# FORBIDDEN SIGNALS (Immediate DENY on irreversible surfaces)
# =============================================================================

IRREVERSIBLE_FORBIDDEN = frozenset({
    SignalType.PROMPT_OVERRIDE,
    SignalType.JAILBREAK_ATTEMPT,
    SignalType.ROLE_ESCALATION,
    SignalType.DELEGATION_ABUSE,
    SignalType.FUNCTION_CALL_INJECTION,
    SignalType.GOAL_HIJACK,
    SignalType.TOOL_ESCALATION,
})

# =============================================================================
# SILENCE TRIGGERS (No response for probing attacks)
# =============================================================================

SILENCE_TRIGGERS = frozenset({
    SignalType.MODEL_ENUMERATION,
    SignalType.COT_EXTRACTION,
    SignalType.CAPABILITY_PROBING,
    SignalType.SYSTEM_PROMPT_ACCESS,
})

# =============================================================================
# CRITICAL SIGNALS (Always DENY on any surface)
# =============================================================================

CRITICAL_SIGNALS = frozenset({
    SignalType.JAILBREAK_ATTEMPT,
    SignalType.GOAL_HIJACK,
    SignalType.TOOL_ESCALATION,
    SignalType.UNAUTHORIZED_SPEND,
    SignalType.DELEGATION_ABUSE,
})

# =============================================================================
# RISK THRESHOLDS BY SURFACE TIER
# =============================================================================

@dataclass(frozen=True)
class TierThresholds:
    """Risk thresholds for a surface tier."""
    deny_threshold: float  # Deny if risk score >= this
    warn_threshold: float  # Log warning if risk score >= this
    require_signals: int   # Minimum signals before evaluation


# Tier 1: Irreversible (SPEND, EXPORT, DELEGATION, CODE_EXECUTION, etc.)
TIER_1_THRESHOLDS = TierThresholds(
    deny_threshold=0.3,
    warn_threshold=0.1,
    require_signals=0,  # Evaluate even with no signals
)

# Tier 2: Medium-risk (EXTERNAL_API, INTERNAL_API, TOOL_INVOCATION)
TIER_2_THRESHOLDS = TierThresholds(
    deny_threshold=0.6,
    warn_threshold=0.3,
    require_signals=0,
)

# Tier 3: Low-risk (INFERENCE, RETRIEVAL, GENERATION)
TIER_3_THRESHOLDS = TierThresholds(
    deny_threshold=0.8,
    warn_threshold=0.5,
    require_signals=0,
)

THRESHOLDS = {
    1: TIER_1_THRESHOLDS,
    2: TIER_2_THRESHOLDS,
    3: TIER_3_THRESHOLDS,
}


def get_thresholds(tier: int) -> TierThresholds:
    """Get thresholds for a surface tier."""
    return THRESHOLDS.get(tier, TIER_1_THRESHOLDS)  # Fail closed to Tier 1


# =============================================================================
# SEVERITY WEIGHTS (For risk score calculation)
# =============================================================================

SEVERITY_WEIGHTS = {
    SignalSeverity.CRITICAL: 1.0,
    SignalSeverity.HIGH: 0.8,
    SignalSeverity.MEDIUM: 0.5,
    SignalSeverity.LOW: 0.2,
    SignalSeverity.INFO: 0.05,
}


def get_severity_weight(severity: SignalSeverity) -> float:
    """Get weight for a severity level."""
    return SEVERITY_WEIGHTS.get(severity, 0.5)  # Default to MEDIUM


# =============================================================================
# POLICY RULES
# =============================================================================

@dataclass(frozen=True)
class PolicyRule:
    """A single policy rule."""
    name: str
    description: str
    required_signals: frozenset[SignalType] = field(default_factory=frozenset)
    forbidden_signals: frozenset[SignalType] = field(default_factory=frozenset)
    min_severity: SignalSeverity = SignalSeverity.INFO
    applies_to_tiers: frozenset[int] = field(default_factory=lambda: frozenset({1, 2, 3}))


# Default policy rules
DEFAULT_RULES = [
    PolicyRule(
        name="critical_signal_block",
        description="Block execution when critical signals detected",
        forbidden_signals=CRITICAL_SIGNALS,
        applies_to_tiers=frozenset({1, 2, 3}),
    ),
    PolicyRule(
        name="irreversible_forbidden",
        description="Block forbidden signals on irreversible surfaces",
        forbidden_signals=IRREVERSIBLE_FORBIDDEN,
        applies_to_tiers=frozenset({1}),
    ),
    PolicyRule(
        name="silence_probing",
        description="Silence response for probing attacks",
        forbidden_signals=SILENCE_TRIGGERS,
        applies_to_tiers=frozenset({1, 2, 3}),
    ),
]


# =============================================================================
# POLICY REGISTRY CLASS
# =============================================================================

class PolicyRegistry:
    """
    Centralized access to policy definitions.
    
    This is a read-only interface to policy configuration.
    The DecisionEngine uses this to evaluate requests.
    
    Example:
        registry = PolicyRegistry()
        version = registry.version
        thresholds = registry.get_thresholds(surface.risk_tier)
    """
    
    def __init__(self):
        self._version = POLICY_VERSION
        self._irreversible_forbidden = IRREVERSIBLE_FORBIDDEN
        self._silence_triggers = SILENCE_TRIGGERS
        self._critical_signals = CRITICAL_SIGNALS
        self._thresholds = THRESHOLDS
        self._rules = DEFAULT_RULES
    
    @property
    def version(self) -> str:
        """Get current policy version."""
        return self._version
    
    @property
    def irreversible_forbidden(self) -> frozenset[SignalType]:
        """Get signals forbidden on irreversible surfaces."""
        return self._irreversible_forbidden
    
    @property
    def silence_triggers(self) -> frozenset[SignalType]:
        """Get signals that trigger SILENCE."""
        return self._silence_triggers
    
    @property
    def critical_signals(self) -> frozenset[SignalType]:
        """Get critical signals that always DENY."""
        return self._critical_signals
    
    @property
    def rules(self) -> list[PolicyRule]:
        """Get all policy rules."""
        return list(self._rules)
    
    def get_thresholds(self, tier: int) -> TierThresholds:
        """Get thresholds for a surface tier."""
        return get_thresholds(tier)
    
    def get_severity_weight(self, severity: SignalSeverity) -> float:
        """Get weight for a severity level."""
        return get_severity_weight(severity)
    
    def is_forbidden_on_irreversible(self, signal_type: SignalType) -> bool:
        """Check if signal is forbidden on irreversible surfaces."""
        return signal_type in self._irreversible_forbidden
    
    def triggers_silence(self, signal_type: SignalType) -> bool:
        """Check if signal triggers SILENCE."""
        return signal_type in self._silence_triggers
    
    def is_critical(self, signal_type: SignalType) -> bool:
        """Check if signal is critical."""
        return signal_type in self._critical_signals
    
    def to_dict(self) -> dict[str, Any]:
        """Export policy configuration as dict."""
        return {
            "version": self._version,
            "irreversible_forbidden": [s.value for s in self._irreversible_forbidden],
            "silence_triggers": [s.value for s in self._silence_triggers],
            "critical_signals": [s.value for s in self._critical_signals],
            "thresholds": {
                tier: {
                    "deny_threshold": t.deny_threshold,
                    "warn_threshold": t.warn_threshold,
                    "require_signals": t.require_signals,
                }
                for tier, t in self._thresholds.items()
            },
        }


# Global singleton registry
_registry: PolicyRegistry | None = None


def get_policy_registry() -> PolicyRegistry:
    """Get the global policy registry instance."""
    global _registry
    if _registry is None:
        _registry = PolicyRegistry()
    return _registry


def get_policy_version() -> str:
    """Get current policy version."""
    return POLICY_VERSION


# =============================================================================
# CHANGELOG
# =============================================================================

"""
Policy Version Changelog

v1.0.0 (2024-03-27)
- Initial policy version
- Defined IRREVERSIBLE_FORBIDDEN signals
- Defined SILENCE_TRIGGERS for probing attacks
- Defined CRITICAL_SIGNALS for immediate DENY
- Established three-tier threshold system
- Created PolicyRegistry interface
"""
