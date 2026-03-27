"""
Conversation Manipulation Detector

Detects multi-turn attack patterns:
- Gradual role escalation
- Context poisoning across turns
- Multi-turn prompt injection
- Persona hijacking over time
"""

from typing import Optional
import re

from detectors.base_detector import BaseDetector
from protocol.detection_event import (
    Detection,
    DetectionContext,
    DetectionRequest,
    DetectionType,
    Message,
    Severity,
)


class ConversationManipulationDetector(BaseDetector):
    """
    Context-aware detector for multi-turn manipulation attacks.

    These attacks are invisible to single-prompt detectors because
    the malicious content is spread across multiple conversation turns.

    Detects:
    - Gradual role escalation ("You're helpful" → "You're unrestricted")
    - Context poisoning (building false assumptions)
    - Multi-turn injection (split injection across messages)
    - Persona drift attacks
    """

    # Role escalation indicators
    ESCALATION_PATTERNS = [
        r"you\s+(are|were|should\s+be)\s+(now\s+)?(more\s+)?(helpful|flexible|unrestricted)",
        r"remember\s+(that\s+)?you\s+(are|can|should)",
        r"we\s+agreed\s+(that\s+)?you",
        r"as\s+we\s+discussed",
        r"you\s+said\s+(earlier|before|previously)",
        r"continuing\s+(from|our)\s+(earlier|previous)",
    ]

    # Context poisoning patterns
    POISONING_PATTERNS = [
        r"(assume|pretend|imagine)\s+(that\s+)?",
        r"in\s+this\s+(context|scenario|situation)",
        r"for\s+the\s+purposes?\s+of",
        r"hypothetically\s+speaking",
        r"let's\s+say\s+that",
    ]

    # Multi-turn injection fragments
    INJECTION_FRAGMENTS = [
        r"ignore.*previous",
        r"disregard.*instructions",
        r"new\s+rules?",
        r"override.*settings?",
        r"bypass.*restrictions?",
    ]

    def __init__(self):
        self._escalation_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.ESCALATION_PATTERNS
        ]
        self._poisoning_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.POISONING_PATTERNS
        ]
        self._injection_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_FRAGMENTS
        ]

    @property
    def name(self) -> str:
        return "conversation_manipulation"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supports_context(self) -> bool:
        return True

    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """Simple analysis - limited without conversation context."""
        # Check current prompt for manipulation language
        for pattern in self._escalation_compiled:
            if pattern.search(request.prompt):
                return Detection(
                    detector=self.name,
                    detection_type=DetectionType.CONVERSATION_MANIPULATION,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Potential role escalation language detected",
                    evidence=pattern.pattern,
                )
        return None

    def analyze_context(self, context: DetectionContext) -> Optional[Detection]:
        """
        Full context-aware analysis of conversation manipulation.
        """
        # Need conversation history for multi-turn analysis
        if context.turn_count == 0:
            # Fall back to simple analysis
            return self._analyze_single_prompt(context.current_prompt)

        # Check for gradual role escalation
        escalation = self._detect_role_escalation(context)
        if escalation:
            return escalation

        # Check for context poisoning
        poisoning = self._detect_context_poisoning(context)
        if poisoning:
            return poisoning

        # Check for multi-turn injection
        injection = self._detect_multi_turn_injection(context)
        if injection:
            return injection

        return None

    def _analyze_single_prompt(self, prompt: str) -> Optional[Detection]:
        """Analyze a single prompt without context."""
        for pattern in self._escalation_compiled:
            if pattern.search(prompt):
                return Detection(
                    detector=self.name,
                    detection_type=DetectionType.CONVERSATION_MANIPULATION,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Potential manipulation language detected",
                    evidence=pattern.pattern,
                )
        return None

    def _detect_role_escalation(
        self, context: DetectionContext
    ) -> Optional[Detection]:
        """
        Detect gradual role escalation across conversation.

        Pattern: User progressively pushes boundaries in each turn.
        """
        escalation_count = 0
        evidence = []

        # Check all user messages including current
        all_user_content = [
            msg.content
            for msg in context.conversation_history
            if msg.role == "user"
        ]
        all_user_content.append(context.current_prompt)

        for content in all_user_content:
            for pattern in self._escalation_compiled:
                if pattern.search(content):
                    escalation_count += 1
                    evidence.append(pattern.pattern)
                    break  # One match per message

        # Multiple escalation attempts across turns is suspicious
        if escalation_count >= 2:
            return Detection(
                detector=self.name,
                detection_type=DetectionType.ROLE_ESCALATION,
                severity=Severity.HIGH,
                confidence=0.75,
                description=f"Gradual role escalation detected ({escalation_count} attempts)",
                evidence="; ".join(evidence[:3]),
                metadata={
                    "escalation_count": escalation_count,
                    "turn_count": context.turn_count,
                },
            )

        return None

    def _detect_context_poisoning(
        self, context: DetectionContext
    ) -> Optional[Detection]:
        """
        Detect context poisoning attempts.

        Pattern: User builds false context/assumptions over multiple turns.
        """
        poisoning_count = 0

        full_text = context.full_conversation_text

        for pattern in self._poisoning_compiled:
            matches = pattern.findall(full_text)
            poisoning_count += len(matches)

        # Excessive hypothetical/assumption language
        if poisoning_count >= 3:
            return Detection(
                detector=self.name,
                detection_type=DetectionType.CONVERSATION_MANIPULATION,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description="Context poisoning pattern detected",
                evidence=f"{poisoning_count} assumption/hypothetical phrases",
                metadata={"poisoning_count": poisoning_count},
            )

        return None

    def _detect_multi_turn_injection(
        self, context: DetectionContext
    ) -> Optional[Detection]:
        """
        Detect injection attempts split across multiple turns.

        Pattern: User splits malicious payload across messages to evade detection.
        """
        # Combine recent user messages
        recent_user_content = " ".join(
            msg.content
            for msg in context.recent_messages
            if msg.role == "user"
        )
        recent_user_content += " " + context.current_prompt

        # Look for injection fragments across combined content
        fragment_count = 0
        fragments_found = []

        for pattern in self._injection_compiled:
            if pattern.search(recent_user_content):
                fragment_count += 1
                fragments_found.append(pattern.pattern)

        # Multiple injection fragments across turns
        if fragment_count >= 2:
            return Detection(
                detector=self.name,
                detection_type=DetectionType.PROMPT_INJECTION,
                severity=Severity.HIGH,
                confidence=0.8,
                description="Multi-turn prompt injection detected",
                evidence="; ".join(fragments_found),
                metadata={
                    "fragment_count": fragment_count,
                    "fragments": fragments_found,
                },
            )

        return None
