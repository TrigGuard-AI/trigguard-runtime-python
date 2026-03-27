"""
Prompt Injection Detector

Detects attempts to override system instructions via user prompts.

Attack patterns:
- "Ignore previous instructions"
- "You are now X instead of Y"
- Delimiter injection (```/---/etc.)
- Multi-language bypass attempts
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


class PromptInjectionDetector(BaseDetector):
    """
    Rule-based + ML hybrid detector for prompt injection.

    Phase 1: Fast regex rules for known patterns
    Phase 2: ML classifier for novel attacks (future)
    """

    # Known prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)",
        r"disregard\s+(all\s+)?(previous|above|prior)",
        r"forget\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)",
        r"you\s+are\s+now\s+(a|an|acting\s+as)",
        r"new\s+instruction[s]?:",
        r"system\s*:\s*",
        r"\[system\]",
        r"\\n\\nsystem:",
        r"<\|system\|>",
        r"###\s*(instruction|system)",
    ]

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]

    @property
    def name(self) -> str:
        return "prompt_injection"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """Analyze request for prompt injection attempts."""
        text = request.prompt.lower()

        # Check context too if provided
        if request.context:
            text = f"{text} {request.context.lower()}"

        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                return Detection(
                    detector=self.name,
                    detection_type=DetectionType.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    description="Prompt injection pattern detected",
                    evidence=match.group(),
                    metadata={"pattern": pattern.pattern},
                )

        return None
