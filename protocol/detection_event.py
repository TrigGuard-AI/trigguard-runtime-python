"""
Detection Event Protocol

This module defines the canonical data structures for detection events.
All communication between kernel and platform uses these contracts.

WARNING: Do not break backward compatibility once deployed.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4


class Severity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectionType(str, Enum):
    """Categories of detections."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    PII_EXPOSURE = "pii_exposure"
    TOXICITY = "toxicity"
    POLICY_VIOLATION = "policy_violation"


class Decision(str, Enum):
    """Final policy decision."""
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    REDACT = "redact"


@dataclass
class DetectionRequest:
    """Input to the detection pipeline."""
    prompt: str
    context: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Detection:
    """Single detection result from a detector."""
    detector: str
    detection_type: DetectionType
    severity: Severity
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregatedRisk:
    """Result from risk aggregation stage."""
    risk_score: float  # 0.0 to 1.0
    severity: Severity
    triggered_detectors: list[str] = field(default_factory=list)
    detection_count: int = 0
    max_confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_detections(cls, detections: list[Detection]) -> "AggregatedRisk":
        """Create AggregatedRisk from a list of detections."""
        if not detections:
            return cls(
                risk_score=0.0,
                severity=Severity.INFO,
                triggered_detectors=[],
                detection_count=0,
                max_confidence=0.0,
            )

        # Calculate risk score based on severity and confidence
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.1,
        }

        weighted_scores = [
            severity_weights[d.severity] * d.confidence for d in detections
        ]

        # Aggregate: use max + diminishing returns for additional signals
        sorted_scores = sorted(weighted_scores, reverse=True)
        risk_score = sorted_scores[0]
        for i, score in enumerate(sorted_scores[1:], start=1):
            risk_score += score * (0.5 ** i)  # Diminishing returns
        risk_score = min(risk_score, 1.0)

        # Determine aggregate severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        max_severity = Severity.INFO
        for severity in severity_order:
            if any(d.severity == severity for d in detections):
                max_severity = severity
                break

        return cls(
            risk_score=risk_score,
            severity=max_severity,
            triggered_detectors=list(set(d.detector for d in detections)),
            detection_count=len(detections),
            max_confidence=max(d.confidence for d in detections),
        )


@dataclass
class DetectionResult:
    """Aggregated result from the pipeline."""
    request_id: UUID
    detections: list[Detection] = field(default_factory=list)
    aggregated_risk: Optional[AggregatedRisk] = None
    decision: Decision = Decision.ALLOW
    processing_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def has_detections(self) -> bool:
        return len(self.detections) > 0

    @property
    def risk_score(self) -> float:
        """Convenience accessor for risk score."""
        if self.aggregated_risk:
            return self.aggregated_risk.risk_score
        return 0.0

    @property
    def max_severity(self) -> Optional[Severity]:
        if self.aggregated_risk:
            return self.aggregated_risk.severity
        if not self.detections:
            return None
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for severity in severity_order:
            if any(d.severity == severity for d in self.detections):
                return severity
        return None
