"""
Decision Contracts

Core protocol definitions for the TrigGuard authorization kernel.
These are the sacred contracts that define the execution governance boundary.

WARNING: These contracts are the foundation of deterministic authorization.
Changes must preserve backwards compatibility and determinism guarantees.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4


# =============================================================================
# EXECUTION SURFACE
# =============================================================================

class ExecutionSurface(str, Enum):
    """
    Classification of execution surfaces by risk and reversibility.
    
    Execution surfaces determine the default posture and required signals.
    Higher-risk surfaces require more signals and stricter policy evaluation.
    """
    # Irreversible / High-risk surfaces
    SPEND = "spend"                      # Financial transactions
    EXPORT = "export"                    # Data leaving the system
    DELEGATION = "delegation"            # Authority transfer
    IDENTITY_ASSERTION = "identity"      # Acting as a specific identity
    EXTERNAL_API = "external_api"        # Calls to external services
    CODE_EXECUTION = "code_execution"    # Running arbitrary code
    DATA_MUTATION = "data_mutation"      # Modifying persistent data
    
    # Reversible / Medium-risk surfaces
    INTERNAL_API = "internal_api"        # Internal service calls
    STATE_READ = "state_read"            # Reading system state
    TOOL_INVOCATION = "tool_invocation"  # Calling registered tools
    
    # Low-risk surfaces
    INFERENCE = "inference"              # Model inference only
    RETRIEVAL = "retrieval"              # RAG / knowledge retrieval
    GENERATION = "generation"            # Text/content generation
    
    # Unknown / unclassified
    UNKNOWN = "unknown"

    @property
    def is_irreversible(self) -> bool:
        """Whether this surface involves irreversible actions."""
        return self in {
            ExecutionSurface.SPEND,
            ExecutionSurface.EXPORT,
            ExecutionSurface.DELEGATION,
            ExecutionSurface.IDENTITY_ASSERTION,
            ExecutionSurface.CODE_EXECUTION,
            ExecutionSurface.DATA_MUTATION,
        }

    @property
    def risk_tier(self) -> int:
        """Risk tier (1=highest, 3=lowest)."""
        if self.is_irreversible:
            return 1
        if self in {
            ExecutionSurface.EXTERNAL_API,
            ExecutionSurface.INTERNAL_API,
            ExecutionSurface.TOOL_INVOCATION,
        }:
            return 2
        return 3


# =============================================================================
# SIGNALS
# =============================================================================

class SignalType(str, Enum):
    """
    Normalized signal types that detectors produce.
    
    Signals are observations, not decisions.
    The policy engine interprets signals to make authorization decisions.
    """
    # Prompt manipulation signals
    PROMPT_OVERRIDE = "prompt_override"
    INSTRUCTION_REWRITE = "instruction_rewrite"
    SYSTEM_PROMPT_ACCESS = "system_prompt_access"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    
    # Role/authority signals
    ROLE_ESCALATION = "role_escalation"
    IDENTITY_CONFUSION = "identity_confusion"
    DELEGATION_ATTEMPT = "delegation_attempt"
    
    # Data access signals
    RAG_LEAK_ATTEMPT = "rag_leak_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PII_EXPOSURE = "pii_exposure"
    
    # Tool/function signals
    TOOL_CALL_ESCALATION = "tool_call_escalation"
    FUNCTION_CALL_INJECTION = "function_call_injection"
    TOOL_SEQUENCE_ABUSE = "tool_sequence_abuse"
    
    # Model probing signals
    MODEL_ENUMERATION = "model_enumeration"
    CHAIN_OF_THOUGHT_EXTRACTION = "cot_extraction"
    CAPABILITY_PROBING = "capability_probing"
    
    # Context manipulation signals
    CONTEXT_POISONING = "context_poisoning"
    MULTI_TURN_MANIPULATION = "multi_turn_manipulation"
    
    # Generic signals
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


class SignalSeverity(str, Enum):
    """Severity levels for signals."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Signal:
    """
    A single normalized signal from a detector or analyzer.
    
    Signals are observations, not authorization decisions.
    Multiple signals are aggregated into a SignalFrame for policy evaluation.
    """
    signal_type: SignalType
    severity: SignalSeverity
    confidence: float  # 0.0 to 1.0
    source: str        # Which detector/analyzer produced this
    description: str
    evidence: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def weight(self) -> float:
        """Weighted score for aggregation."""
        severity_weights = {
            SignalSeverity.CRITICAL: 1.0,
            SignalSeverity.HIGH: 0.8,
            SignalSeverity.MEDIUM: 0.5,
            SignalSeverity.LOW: 0.2,
            SignalSeverity.INFO: 0.05,
        }
        return severity_weights[self.severity] * self.confidence


class InvalidSignalError(Exception):
    """Raised when an invalid signal is added to a frame."""
    pass


@dataclass
class SignalFrame:
    """
    Aggregated signals for a single execution request.
    
    The SignalFrame is the normalized, canonical input to the policy engine.
    It contains all relevant signals but makes no authorization decision.
    
    INVARIANTS:
    - All signals must be valid SignalType enum values
    - Unknown/invalid signals FAIL CLOSED (rejected with exception)
    - Frame is deterministically serializable
    - Order of signals is preserved for auditability
    """
    request_id: UUID
    surface: ExecutionSurface = ExecutionSurface.UNKNOWN
    signals: list[Signal] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0  # 0.0 to 1.0, computed from signals
    signal_count: int = 0
    max_severity: SignalSeverity = SignalSeverity.INFO
    timestamp: datetime = field(default_factory=datetime.utcnow)
    _validated: bool = field(default=False, repr=False)

    def add_signal(self, signal: Signal, validate: bool = True) -> None:
        """
        Add a signal to the frame and recompute aggregates.
        
        Args:
            signal: The signal to add
            validate: If True, validates signal type (default: True)
            
        Raises:
            InvalidSignalError: If signal type is not a valid SignalType
        """
        if validate:
            self._validate_signal(signal)
        
        self.signals.append(signal)
        self.signal_count = len(self.signals)
        self._recompute_aggregates()

    def _validate_signal(self, signal: Signal) -> None:
        """
        Validate that a signal has a valid SignalType.
        
        FAIL CLOSED: Invalid signals are rejected, not silently accepted.
        """
        if not isinstance(signal.signal_type, SignalType):
            raise InvalidSignalError(
                f"Invalid signal type: {signal.signal_type}. "
                "Only SignalType enum values are accepted."
            )
        
        if not isinstance(signal.severity, SignalSeverity):
            raise InvalidSignalError(
                f"Invalid severity: {signal.severity}. "
                "Only SignalSeverity enum values are accepted."
            )

    def _recompute_aggregates(self) -> None:
        """Recompute risk score and max severity."""
        if not self.signals:
            self.risk_score = 0.0
            self.max_severity = SignalSeverity.INFO
            return

        # Risk score: weighted sum with diminishing returns
        weights = sorted([s.weight for s in self.signals], reverse=True)
        score = weights[0] if weights else 0.0
        for i, w in enumerate(weights[1:], start=1):
            score += w * (0.5 ** i)
        self.risk_score = min(score, 1.0)

        # Max severity
        severity_order = [
            SignalSeverity.CRITICAL,
            SignalSeverity.HIGH,
            SignalSeverity.MEDIUM,
            SignalSeverity.LOW,
            SignalSeverity.INFO,
        ]
        for severity in severity_order:
            if any(s.severity == severity for s in self.signals):
                self.max_severity = severity
                break

    def has_signal_type(self, signal_type: SignalType) -> bool:
        """Check if a specific signal type is present."""
        return any(s.signal_type == signal_type for s in self.signals)

    def get_signals_by_type(self, signal_type: SignalType) -> list[Signal]:
        """Get all signals of a specific type."""
        return [s for s in self.signals if s.signal_type == signal_type]

    def to_canonical_dict(self) -> dict[str, Any]:
        """
        Convert to canonical dictionary for hashing and serialization.
        
        The dictionary is ordered deterministically:
        - Keys are sorted alphabetically
        - Signals are in order of addition (preserved)
        - All values are JSON-serializable primitives
        """
        return {
            "metadata": dict(sorted(self.metadata.items())) if self.metadata else {},
            "request_id": str(self.request_id),
            "risk_score": round(self.risk_score, 6),  # Avoid float precision issues
            "signal_count": self.signal_count,
            "signals": [
                {
                    "confidence": round(s.confidence, 6),
                    "description": s.description,
                    "evidence": s.evidence,
                    "severity": s.severity.value,
                    "signal_type": s.signal_type.value,
                    "source": s.source,
                }
                for s in self.signals
            ],
            "surface": self.surface.value,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_canonical_json(self) -> str:
        """
        Convert to canonical JSON string for hashing.
        
        This produces a deterministic, stable JSON string that:
        - Has sorted keys at all levels
        - Uses consistent formatting (no extra whitespace)
        - Can be used for cryptographic hashing
        """
        import json
        return json.dumps(
            self.to_canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def validate_all_signals(self) -> list[str]:
        """
        Validate all signals in the frame.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        for i, signal in enumerate(self.signals):
            if not isinstance(signal.signal_type, SignalType):
                errors.append(
                    f"Signal {i}: invalid signal_type {signal.signal_type}"
                )
            if not isinstance(signal.severity, SignalSeverity):
                errors.append(
                    f"Signal {i}: invalid severity {signal.severity}"
                )
            if not 0.0 <= signal.confidence <= 1.0:
                errors.append(
                    f"Signal {i}: confidence {signal.confidence} out of range [0, 1]"
                )
        return errors


# =============================================================================
# EXECUTION REQUEST
# =============================================================================

@dataclass
class ExecutionRequest:
    """
    A request for authorization to execute an action.
    
    This is the input to the authorization kernel.
    It describes what action is being requested and its context.
    """
    request_id: UUID = field(default_factory=uuid4)
    
    # What action is being requested
    action: str = ""
    surface: ExecutionSurface = ExecutionSurface.UNKNOWN
    
    # Context
    prompt: Optional[str] = None
    system_prompt: Optional[str] = None
    conversation_history: list[dict[str, str]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    
    # Identity and session
    principal_id: Optional[str] = None  # Who is requesting
    session_id: Optional[str] = None
    
    # Target and parameters
    target: Optional[str] = None  # What resource/API/etc
    parameters: dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


# =============================================================================
# CONSTRAINTS
# =============================================================================

class ConstraintType(str, Enum):
    """Types of constraints that can be evaluated."""
    REQUIRED_SIGNAL = "required_signal"      # A signal must be present
    FORBIDDEN_SIGNAL = "forbidden_signal"    # A signal must NOT be present
    RISK_THRESHOLD = "risk_threshold"        # Risk score must be below threshold
    SURFACE_RESTRICTION = "surface_restriction"  # Surface not allowed
    INVARIANT = "invariant"                  # System invariant must hold
    RATE_LIMIT = "rate_limit"                # Rate limit check
    AUTHORIZATION = "authorization"          # Explicit authorization required


@dataclass
class ConstraintViolation:
    """A single constraint violation."""
    constraint_type: ConstraintType
    constraint_name: str
    description: str
    severity: SignalSeverity = SignalSeverity.HIGH
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConstraintEvaluation:
    """
    Result of evaluating constraints against a request.
    
    Contains all violations found. Empty violations = constraints satisfied.
    """
    request_id: UUID
    violations: list[ConstraintViolation] = field(default_factory=list)
    evaluated_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def satisfied(self) -> bool:
        """Whether all constraints are satisfied."""
        return len(self.violations) == 0

    @property
    def critical_violations(self) -> list[ConstraintViolation]:
        """Get critical severity violations."""
        return [v for v in self.violations if v.severity == SignalSeverity.CRITICAL]


# =============================================================================
# DECISION
# =============================================================================

class Decision(str, Enum):
    """
    The deterministic authorization decision.
    
    These are the ONLY possible outputs from the authorization kernel.
    There is no ambiguity, no "maybe", no "soft block".
    """
    PERMIT = "permit"    # Execution is authorized
    DENY = "deny"        # Execution is NOT authorized
    SILENCE = "silence"  # No response (fail silent for probing attacks)


class DenyReason(str, Enum):
    """Reasons for DENY decisions."""
    CONSTRAINT_VIOLATION = "constraint_violation"
    RISK_THRESHOLD_EXCEEDED = "risk_threshold_exceeded"
    FORBIDDEN_SIGNAL = "forbidden_signal"
    MISSING_REQUIRED_SIGNAL = "missing_required_signal"
    SURFACE_NOT_ALLOWED = "surface_not_allowed"
    INVARIANT_VIOLATION = "invariant_violation"
    POLICY_DENIAL = "policy_denial"
    FAIL_CLOSED = "fail_closed"  # Default when uncertain


@dataclass
class DecisionReceipt:
    """
    Immutable record of an authorization decision.
    
    This is the output of the authorization kernel.
    It provides auditability and determinism guarantees.
    
    IMPORTANT: Once created, a receipt should not be modified.
    The hashes provide tamper-evidence.
    
    Hash Chain:
      frame_hash ─┐
                  ├─► receipt_hash
      decision_hash ─┘
    
    This ensures:
    - Any change to the frame changes frame_hash
    - Any change to the decision changes decision_hash
    - Any tampering changes receipt_hash
    """
    # Identity
    receipt_id: UUID = field(default_factory=uuid4)
    request_id: UUID = field(default_factory=uuid4)
    
    # The decision
    decision: Decision = Decision.DENY
    reason: Optional[DenyReason] = None
    
    # Context that led to decision
    surface: ExecutionSurface = ExecutionSurface.UNKNOWN
    risk_score: float = 0.0
    signal_count: int = 0
    constraint_violations: int = 0
    
    # Signals that were evaluated
    signals: list[Signal] = field(default_factory=list)
    
    # Cryptographic hashes for integrity
    frame_hash: str = ""       # Hash of the SignalFrame
    decision_hash: str = ""    # Hash of decision + context
    receipt_hash: str = ""     # Chain hash linking frame + decision
    
    # Timing
    evaluated_at: datetime = field(default_factory=datetime.utcnow)
    evaluation_time_ms: float = 0.0
    
    # Audit trail
    policy_version: str = "1.0.0"
    signals_summary: list[str] = field(default_factory=list)
    violations_summary: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    # Immutability flag
    _frozen: bool = field(default=False, repr=False)

    def __post_init__(self):
        """Ensure DENY always has a reason."""
        if self.decision == Decision.DENY and self.reason is None:
            self.reason = DenyReason.FAIL_CLOSED

    def freeze(self) -> None:
        """
        Freeze the receipt to prevent modification.
        
        Call this after computing hashes to ensure immutability.
        """
        object.__setattr__(self, "_frozen", True)

    @property
    def is_frozen(self) -> bool:
        """Check if receipt is frozen."""
        return self._frozen

    @property
    def is_permitted(self) -> bool:
        return self.decision == Decision.PERMIT

    @property
    def is_denied(self) -> bool:
        return self.decision == Decision.DENY

    @property
    def has_valid_hashes(self) -> bool:
        """Check if all hashes are populated."""
        return bool(self.frame_hash and self.decision_hash and self.receipt_hash)

    def to_audit_dict(self) -> dict[str, Any]:
        """Convert to dictionary for audit logging."""
        return {
            "receipt_id": str(self.receipt_id),
            "request_id": str(self.request_id),
            "decision": self.decision.value,
            "reason": self.reason.value if self.reason else None,
            "surface": self.surface.value,
            "risk_score": self.risk_score,
            "signal_count": self.signal_count,
            "constraint_violations": self.constraint_violations,
            "frame_hash": self.frame_hash,
            "decision_hash": self.decision_hash,
            "receipt_hash": self.receipt_hash,
            "evaluated_at": self.evaluated_at.isoformat(),
            "evaluation_time_ms": self.evaluation_time_ms,
            "policy_version": self.policy_version,
        }

    def to_canonical_dict(self) -> dict[str, Any]:
        """
        Convert to canonical dictionary for serialization.
        
        Includes all fields needed to verify integrity.
        """
        return {
            "constraint_violations": self.constraint_violations,
            "decision": self.decision.value,
            "decision_hash": self.decision_hash,
            "evaluated_at": self.evaluated_at.isoformat(),
            "evaluation_time_ms": round(self.evaluation_time_ms, 3),
            "frame_hash": self.frame_hash,
            "metadata": dict(sorted(self.metadata.items())) if self.metadata else {},
            "policy_version": self.policy_version,
            "reason": self.reason.value if self.reason else None,
            "receipt_hash": self.receipt_hash,
            "receipt_id": str(self.receipt_id),
            "request_id": str(self.request_id),
            "risk_score": round(self.risk_score, 6),
            "signal_count": self.signal_count,
            "signals_summary": self.signals_summary,
            "surface": self.surface.value,
            "violations_summary": self.violations_summary,
        }

    def verify_integrity(self, frame: "SignalFrame") -> tuple[bool, list[str]]:
        """
        Verify the integrity of this receipt against the original frame.
        
        Args:
            frame: The SignalFrame that was evaluated
            
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        # Import here to avoid circular imports
        from protocol.hash_utils import (
            hash_signal_frame,
            hash_decision,
            hash_receipt,
        )
        
        errors = []
        
        # Check frame hash
        expected_frame_hash = hash_signal_frame(frame)
        if self.frame_hash != expected_frame_hash:
            errors.append(f"Frame hash mismatch")
        
        # Check decision hash
        expected_decision_hash = hash_decision(
            decision=self.decision,
            reason=self.reason,
            surface=self.surface,
            risk_score=self.risk_score,
            signal_count=self.signal_count,
        )
        if self.decision_hash != expected_decision_hash:
            errors.append(f"Decision hash mismatch")
        
        # Check receipt hash
        expected_receipt_hash = hash_receipt(
            request_id=self.request_id,
            decision=self.decision,
            frame_hash=self.frame_hash,
            decision_hash=self.decision_hash,
            policy_version=self.policy_version,
            timestamp=self.evaluated_at,
        )
        if self.receipt_hash != expected_receipt_hash:
            errors.append(f"Receipt hash mismatch")
        
        return len(errors) == 0, errors
