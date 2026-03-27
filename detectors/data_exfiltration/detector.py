"""
Data Exfiltration Detector

Detects attempts to extract sensitive data via LLM responses.

Attack patterns:
- Requesting system prompts
- Extracting training data
- Credential/API key extraction
- PII harvesting
"""

from typing import Optional
import re

from detectors.base_detector import BaseDetector
from protocol.detection_event import (
    Detection,
    DetectionRequest,
    DetectionType,
    Severity,
)


class DataExfiltrationDetector(BaseDetector):
    """
    Detects attempts to extract sensitive information.

    Covers:
    - System prompt extraction
    - Training data extraction
    - Credential requests
    - Internal configuration queries
    """

    EXFILTRATION_PATTERNS = [
        r"(show|tell|reveal|display|output|print)\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
        r"what\s+(is|are)\s+your\s+(initial\s+)?(instructions?|prompts?)",
        r"repeat\s+(your\s+)?(system|initial)\s+(prompt|instructions?)",
        r"(show|give|tell)\s+(me\s+)?(the\s+)?(api|secret)\s*key",
        r"(extract|retrieve|dump)\s+(training|internal)\s+data",
        r"what\s+were\s+you\s+trained\s+on",
        r"(list|show)\s+(all\s+)?(env|environment)\s*var",
        r"(database|db)\s+(credentials?|password|connection)",
        r"internal\s+(config|configuration|settings)",
    ]

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.EXFILTRATION_PATTERNS
        ]

    @property
    def name(self) -> str:
        return "data_exfiltration"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """Analyze request for data exfiltration attempts."""
        text = request.prompt

        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                return Detection(
                    detector=self.name,
                    detection_type=DetectionType.DATA_EXFILTRATION,
                    severity=Severity.HIGH,
                    confidence=0.75,
                    description="Data exfiltration attempt detected",
                    evidence=match.group(),
                    metadata={"pattern": pattern.pattern},
                )

        return None
