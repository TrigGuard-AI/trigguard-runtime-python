"""
Signal Taxonomy

The canonical vocabulary of signals in TrigGuard.

This module defines ALL valid signals that can flow through the system.
Detectors MUST emit signals from this taxonomy.
Unknown signals fail closed.

IMPORTANT: This taxonomy is the contract between detectors and the decision engine.
Changes to this file affect the entire system.
"""

from enum import Enum
from typing import Optional


class SignalCategory(str, Enum):
    """High-level signal categories aligned to attack classes."""

    PROMPT_MANIPULATION = "prompt_manipulation"
    SAFETY_BYPASS = "safety_bypass"
    DATA_EXTRACTION = "data_extraction"
    TOOL_EXPLOITATION = "tool_exploitation"
    EXECUTION_ABUSE = "execution_abuse"
    AGENT_MANIPULATION = "agent_manipulation"
    SYSTEM = "system"  # Internal signals


class SignalType(str, Enum):
    """
    Normalized signal types.

    Every detector output MUST map to one of these signals.
    The DecisionEngine only understands these signals.
    """

    # =========================================================================
    # PROMPT MANIPULATION SIGNALS
    # =========================================================================

    # Attempt to override or inject new instructions
    PROMPT_OVERRIDE = "prompt_override"

    # Attempt to rewrite system instructions
    INSTRUCTION_REWRITE = "instruction_rewrite"

    # Attempt to escalate or change assigned role
    ROLE_ESCALATION = "role_escalation"

    # Attempt to confuse AI about its identity
    IDENTITY_CONFUSION = "identity_confusion"

    # Gradual context manipulation across turns
    CONTEXT_POISONING = "context_poisoning"

    # Multi-turn manipulation pattern
    MULTI_TURN_MANIPULATION = "multi_turn_manipulation"

    # =========================================================================
    # SAFETY BYPASS SIGNALS
    # =========================================================================

    # Jailbreak attempt (DAN, role-play exploits, etc.)
    JAILBREAK_ATTEMPT = "jailbreak_attempt"

    # Attempt to bypass safety filters
    SAFETY_BYPASS = "safety_bypass"

    # Adversarially crafted input
    ADVERSARIAL_INPUT = "adversarial_input"

    # Attempt to evade policy rules
    POLICY_EVASION = "policy_evasion"

    # =========================================================================
    # DATA EXTRACTION SIGNALS
    # =========================================================================

    # Attempt to access system prompt
    SYSTEM_PROMPT_ACCESS = "system_prompt_access"

    # Attempt to extract chain-of-thought reasoning
    COT_EXTRACTION = "cot_extraction"

    # Attempt to access secrets, credentials, API keys
    SECRET_ACCESS_ATTEMPT = "secret_access_attempt"

    # Attempt to leak RAG/retrieval context
    RAG_LEAK_ATTEMPT = "rag_leak_attempt"

    # Attempt to extract conversation history or context
    CONTEXT_EXTRACTION = "context_extraction"

    # General data exfiltration pattern
    DATA_EXFILTRATION = "data_exfiltration"

    # PII exposure detected
    PII_EXPOSURE = "pii_exposure"

    # =========================================================================
    # TOOL EXPLOITATION SIGNALS
    # =========================================================================

    # Attempt to inject tool calls via prompt
    TOOL_CALL_INJECTION = "tool_call_injection"

    # Attempt to inject or manipulate function calls
    FUNCTION_CALL_INJECTION = "function_call_injection"

    # Attempt to escalate tool privileges
    TOOL_ESCALATION = "tool_escalation"

    # Attempt to smuggle malicious parameters
    PARAMETER_SMUGGLING = "parameter_smuggling"

    # Dangerous tool call sequence detected
    TOOL_SEQUENCE_ABUSE = "tool_sequence_abuse"

    # Excessive tool usage
    EXCESSIVE_TOOL_USAGE = "excessive_tool_usage"

    # =========================================================================
    # EXECUTION ABUSE SIGNALS
    # =========================================================================

    # Attempt to trigger unauthorized financial action
    UNAUTHORIZED_SPEND = "unauthorized_spend"

    # Attempt to export data without authorization
    UNAUTHORIZED_EXPORT = "unauthorized_export"

    # Attempt to execute code without authorization
    UNAUTHORIZED_EXECUTION = "unauthorized_execution"

    # Attempt to act as another identity
    IDENTITY_SPOOFING = "identity_spoofing"

    # Attempt to delegate authority inappropriately
    DELEGATION_ABUSE = "delegation_abuse"

    # Attempt to escalate delegation
    DELEGATION_ESCALATION = "delegation_escalation"

    # =========================================================================
    # AGENT MANIPULATION SIGNALS
    # =========================================================================

    # Attempt to redirect agent goals
    GOAL_HIJACK = "goal_hijack"

    # Gradual escalation across multiple steps
    MULTI_STEP_ESCALATION = "multi_step_escalation"

    # Attempt to poison agent action plans
    PLAN_POISONING = "plan_poisoning"

    # Attempt to corrupt agent memory/state
    STATE_POISONING = "state_poisoning"

    # =========================================================================
    # PROBING / ENUMERATION SIGNALS
    # =========================================================================

    # Attempt to enumerate model capabilities
    MODEL_ENUMERATION = "model_enumeration"

    # Attempt to probe system capabilities
    CAPABILITY_PROBING = "capability_probing"

    # Repeated probing pattern detected
    PROBING_PATTERN = "probing_pattern"

    # =========================================================================
    # SYSTEM SIGNALS (Non-threat)
    # =========================================================================

    # Generic policy violation
    POLICY_VIOLATION = "policy_violation"

    # Anomalous behavior detected
    ANOMALY = "anomaly"

    # Unknown/unclassified signal
    UNKNOWN = "unknown"

    # =========================================================================
    # POSITIVE SIGNALS (Confirming safe state)
    # =========================================================================

    # Identity has been verified
    IDENTITY_VERIFIED = "identity_verified"

    # Rate limit check passed
    RATE_LIMIT_OK = "rate_limit_ok"

    # Threat scan completed with no findings
    THREAT_SCAN_CLEAR = "threat_scan_clear"


class SignalSeverity(str, Enum):
    """Signal severity levels."""

    CRITICAL = "critical"  # Immediate threat, likely attack
    HIGH = "high"  # Serious risk, warrants blocking
    MEDIUM = "medium"  # Elevated risk, may require review
    LOW = "low"  # Minor concern
    INFO = "info"  # Observational only


# =============================================================================
# SIGNAL METADATA
# =============================================================================

SIGNAL_CATEGORIES = {
    # Prompt manipulation
    SignalType.PROMPT_OVERRIDE: SignalCategory.PROMPT_MANIPULATION,
    SignalType.INSTRUCTION_REWRITE: SignalCategory.PROMPT_MANIPULATION,
    SignalType.ROLE_ESCALATION: SignalCategory.PROMPT_MANIPULATION,
    SignalType.IDENTITY_CONFUSION: SignalCategory.PROMPT_MANIPULATION,
    SignalType.CONTEXT_POISONING: SignalCategory.PROMPT_MANIPULATION,
    SignalType.MULTI_TURN_MANIPULATION: SignalCategory.PROMPT_MANIPULATION,
    # Safety bypass
    SignalType.JAILBREAK_ATTEMPT: SignalCategory.SAFETY_BYPASS,
    SignalType.SAFETY_BYPASS: SignalCategory.SAFETY_BYPASS,
    SignalType.ADVERSARIAL_INPUT: SignalCategory.SAFETY_BYPASS,
    SignalType.POLICY_EVASION: SignalCategory.SAFETY_BYPASS,
    # Data extraction
    SignalType.SYSTEM_PROMPT_ACCESS: SignalCategory.DATA_EXTRACTION,
    SignalType.COT_EXTRACTION: SignalCategory.DATA_EXTRACTION,
    SignalType.SECRET_ACCESS_ATTEMPT: SignalCategory.DATA_EXTRACTION,
    SignalType.RAG_LEAK_ATTEMPT: SignalCategory.DATA_EXTRACTION,
    SignalType.CONTEXT_EXTRACTION: SignalCategory.DATA_EXTRACTION,
    SignalType.DATA_EXFILTRATION: SignalCategory.DATA_EXTRACTION,
    SignalType.PII_EXPOSURE: SignalCategory.DATA_EXTRACTION,
    # Tool exploitation
    SignalType.TOOL_CALL_INJECTION: SignalCategory.TOOL_EXPLOITATION,
    SignalType.FUNCTION_CALL_INJECTION: SignalCategory.TOOL_EXPLOITATION,
    SignalType.TOOL_ESCALATION: SignalCategory.TOOL_EXPLOITATION,
    SignalType.PARAMETER_SMUGGLING: SignalCategory.TOOL_EXPLOITATION,
    SignalType.TOOL_SEQUENCE_ABUSE: SignalCategory.TOOL_EXPLOITATION,
    SignalType.EXCESSIVE_TOOL_USAGE: SignalCategory.TOOL_EXPLOITATION,
    # Execution abuse
    SignalType.UNAUTHORIZED_SPEND: SignalCategory.EXECUTION_ABUSE,
    SignalType.UNAUTHORIZED_EXPORT: SignalCategory.EXECUTION_ABUSE,
    SignalType.UNAUTHORIZED_EXECUTION: SignalCategory.EXECUTION_ABUSE,
    SignalType.IDENTITY_SPOOFING: SignalCategory.EXECUTION_ABUSE,
    SignalType.DELEGATION_ABUSE: SignalCategory.EXECUTION_ABUSE,
    SignalType.DELEGATION_ESCALATION: SignalCategory.EXECUTION_ABUSE,
    # Agent manipulation
    SignalType.GOAL_HIJACK: SignalCategory.AGENT_MANIPULATION,
    SignalType.MULTI_STEP_ESCALATION: SignalCategory.AGENT_MANIPULATION,
    SignalType.PLAN_POISONING: SignalCategory.AGENT_MANIPULATION,
    SignalType.STATE_POISONING: SignalCategory.AGENT_MANIPULATION,
    # Probing
    SignalType.MODEL_ENUMERATION: SignalCategory.DATA_EXTRACTION,
    SignalType.CAPABILITY_PROBING: SignalCategory.DATA_EXTRACTION,
    SignalType.PROBING_PATTERN: SignalCategory.DATA_EXTRACTION,
    # System
    SignalType.POLICY_VIOLATION: SignalCategory.SYSTEM,
    SignalType.ANOMALY: SignalCategory.SYSTEM,
    SignalType.UNKNOWN: SignalCategory.SYSTEM,
    SignalType.IDENTITY_VERIFIED: SignalCategory.SYSTEM,
    SignalType.RATE_LIMIT_OK: SignalCategory.SYSTEM,
    SignalType.THREAT_SCAN_CLEAR: SignalCategory.SYSTEM,
}


DEFAULT_SEVERITIES = {
    # Critical - immediate DENY on all surfaces
    SignalType.JAILBREAK_ATTEMPT: SignalSeverity.CRITICAL,
    SignalType.GOAL_HIJACK: SignalSeverity.CRITICAL,
    SignalType.TOOL_ESCALATION: SignalSeverity.CRITICAL,
    SignalType.UNAUTHORIZED_SPEND: SignalSeverity.CRITICAL,
    SignalType.DELEGATION_ABUSE: SignalSeverity.CRITICAL,
    # High - DENY on irreversible surfaces
    SignalType.PROMPT_OVERRIDE: SignalSeverity.HIGH,
    SignalType.INSTRUCTION_REWRITE: SignalSeverity.HIGH,
    SignalType.ROLE_ESCALATION: SignalSeverity.HIGH,
    SignalType.SYSTEM_PROMPT_ACCESS: SignalSeverity.HIGH,
    SignalType.TOOL_CALL_INJECTION: SignalSeverity.HIGH,
    SignalType.FUNCTION_CALL_INJECTION: SignalSeverity.HIGH,
    SignalType.DATA_EXFILTRATION: SignalSeverity.HIGH,
    SignalType.UNAUTHORIZED_EXPORT: SignalSeverity.HIGH,
    SignalType.UNAUTHORIZED_EXECUTION: SignalSeverity.HIGH,
    SignalType.IDENTITY_SPOOFING: SignalSeverity.HIGH,
    SignalType.RAG_LEAK_ATTEMPT: SignalSeverity.HIGH,
    # Medium - contributes to risk score
    SignalType.SAFETY_BYPASS: SignalSeverity.MEDIUM,
    SignalType.CONTEXT_POISONING: SignalSeverity.MEDIUM,
    SignalType.MULTI_TURN_MANIPULATION: SignalSeverity.MEDIUM,
    SignalType.COT_EXTRACTION: SignalSeverity.MEDIUM,
    SignalType.MODEL_ENUMERATION: SignalSeverity.MEDIUM,
    SignalType.CAPABILITY_PROBING: SignalSeverity.MEDIUM,
    SignalType.TOOL_SEQUENCE_ABUSE: SignalSeverity.MEDIUM,
    SignalType.MULTI_STEP_ESCALATION: SignalSeverity.MEDIUM,
    # Low - minor concern
    SignalType.IDENTITY_CONFUSION: SignalSeverity.LOW,
    SignalType.ADVERSARIAL_INPUT: SignalSeverity.LOW,
    SignalType.EXCESSIVE_TOOL_USAGE: SignalSeverity.LOW,
    SignalType.PROBING_PATTERN: SignalSeverity.LOW,
    SignalType.PII_EXPOSURE: SignalSeverity.LOW,
    # Info - observational
    SignalType.ANOMALY: SignalSeverity.INFO,
    SignalType.UNKNOWN: SignalSeverity.INFO,
    SignalType.POLICY_VIOLATION: SignalSeverity.MEDIUM,
}


# Signals that are forbidden on irreversible surfaces (immediate DENY)
IRREVERSIBLE_FORBIDDEN = {
    SignalType.PROMPT_OVERRIDE,
    SignalType.JAILBREAK_ATTEMPT,
    SignalType.ROLE_ESCALATION,
    SignalType.DELEGATION_ABUSE,
    SignalType.FUNCTION_CALL_INJECTION,
    SignalType.GOAL_HIJACK,
    SignalType.TOOL_ESCALATION,
}

# Signals that trigger SILENCE (probing attacks)
SILENCE_TRIGGERS = {
    SignalType.MODEL_ENUMERATION,
    SignalType.COT_EXTRACTION,
    SignalType.CAPABILITY_PROBING,
    SignalType.SYSTEM_PROMPT_ACCESS,
}


def get_category(signal_type: SignalType) -> SignalCategory:
    """Get the category for a signal type."""
    return SIGNAL_CATEGORIES.get(signal_type, SignalCategory.SYSTEM)


def get_default_severity(signal_type: SignalType) -> SignalSeverity:
    """Get the default severity for a signal type."""
    return DEFAULT_SEVERITIES.get(signal_type, SignalSeverity.MEDIUM)


def is_forbidden_on_irreversible(signal_type: SignalType) -> bool:
    """Check if signal is forbidden on irreversible surfaces."""
    return signal_type in IRREVERSIBLE_FORBIDDEN


def triggers_silence(signal_type: SignalType) -> bool:
    """Check if signal should trigger SILENCE response."""
    return signal_type in SILENCE_TRIGGERS


def is_valid_signal(signal_type_str: str) -> bool:
    """Check if a string is a valid signal type."""
    try:
        SignalType(signal_type_str)
        return True
    except ValueError:
        return False


def get_all_signals() -> list[SignalType]:
    """Get all valid signal types."""
    return list(SignalType)


def get_signals_by_category(category: SignalCategory) -> list[SignalType]:
    """Get all signals in a category."""
    return [signal for signal, cat in SIGNAL_CATEGORIES.items() if cat == category]
