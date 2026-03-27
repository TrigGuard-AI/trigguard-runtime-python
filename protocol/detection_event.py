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
class DetectionResult:
    """Aggregated result from the pipeline."""
    request_id: UUID
    detections: list[Detection] = field(default_factory=list)
    decision: Decision = Decision.ALLOW
    processing_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def has_detections(self) -> bool:
        return len(self.detections) > 0

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.detections:
            return None
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for severity in severity_order:
            if any(d.severity == severity for d in self.detections):
                return severity
        return None
