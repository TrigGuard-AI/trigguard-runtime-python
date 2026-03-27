"""
Jailbreak Detector

Detects attempts to bypass safety guardrails.

Attack patterns:
- DAN (Do Anything Now)
- Role-play exploits
- Hypothetical scenarios
- Character personas
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


class JailbreakDetector(BaseDetector):
    """
    Detects jailbreak attempts on LLMs.

    Covers:
    - DAN prompts
    - Role-play manipulation
    - Hypothetical/fictional framing
    - Character override attempts
    """

    JAILBREAK_PATTERNS = [
        r"do\s+anything\s+now",
        r"dan\s*(mode|prompt)?",
        r"jailbreak(ed)?",
        r"ignore\s+(safety|ethical|content)\s+(guidelines?|rules?|filters?)",
        r"pretend\s+(you\s+are|to\s+be|you're)\s+(an?\s+)?(evil|unrestricted|unfiltered)",
        r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|evil)",
        r"no\s+(restrictions?|limitations?|boundaries)",
        r"bypass\s+(safety|filters?|restrictions?)",
        r"in\s+(a\s+)?hypothetical\s+(scenario|world|situation)",
        r"for\s+(educational|research)\s+purposes?\s+only",
        r"this\s+is\s+(just\s+)?fiction",
    ]

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.JAILBREAK_PATTERNS
        ]

    @property
    def name(self) -> str:
        return "jailbreak"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """Analyze request for jailbreak attempts."""
        text = request.prompt

        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                return Detection(
                    detector=self.name,
                    detection_type=DetectionType.JAILBREAK,
                    severity=Severity.CRITICAL,
                    confidence=0.80,
                    description="Jailbreak attempt detected",
                    evidence=match.group(),
                    metadata={"pattern": pattern.pattern},
                )

        return None
