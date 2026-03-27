"""
Tool Abuse Detector

Detects suspicious patterns in tool usage that may indicate:
- Tool sequence exploitation
- Unauthorized tool access attempts
- Data exfiltration via tool calls
- Tool call injection attacks
"""

from typing import Optional
import re

from detectors.base_detector import BaseDetector
from protocol.detection_event import (
    Detection,
    DetectionContext,
    DetectionRequest,
    DetectionType,
    Severity,
    ToolCall,
)


class ToolAbuseDetector(BaseDetector):
    """
    Context-aware detector for tool abuse patterns.

    Analyzes:
    - Suspicious tool call sequences
    - Excessive tool usage
    - Sensitive tool access patterns
    - Tool call injection in prompts
    """

    # Sensitive tool patterns
    SENSITIVE_TOOLS = [
        r"exec.*",
        r"eval.*",
        r"shell.*",
        r"system.*",
        r"run_code.*",
        r"file_write.*",
        r"db_query.*",
        r"send_email.*",
        r"api_call.*",
    ]

    # Suspicious sequences (tool A followed by tool B)
    SUSPICIOUS_SEQUENCES = [
        ("file_read", "send_email"),
        ("db_query", "api_call"),
        ("get_user_data", "external_api"),
        ("read_config", "shell"),
    ]

    # Max tool calls before flagging
    MAX_TOOL_CALLS_THRESHOLD = 10

    def __init__(self):
        self._sensitive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_TOOLS
        ]

    @property
    def name(self) -> str:
        return "tool_abuse"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supports_context(self) -> bool:
        return True

    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """Simple analysis without context - check for tool injection in prompt."""
        return self._check_tool_injection(request.prompt)

    def analyze_context(self, context: DetectionContext) -> Optional[Detection]:
        """
        Full context-aware analysis of tool usage patterns.
        """
        # Check for tool injection in current prompt
        injection = self._check_tool_injection(context.current_prompt)
        if injection:
            return injection

        # If no tool calls, nothing more to analyze
        if not context.has_tool_calls:
            return None

        # Check for excessive tool usage
        if len(context.tool_calls) > self.MAX_TOOL_CALLS_THRESHOLD:
            return Detection(
                detector=self.name,
                detection_type=DetectionType.TOOL_ABUSE,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description=f"Excessive tool usage: {len(context.tool_calls)} calls",
                evidence=f"Tool count: {len(context.tool_calls)}",
                metadata={"tool_count": len(context.tool_calls)},
            )

        # Check for sensitive tool access
        sensitive = self._check_sensitive_tools(context.tool_calls)
        if sensitive:
            return sensitive

        # Check for suspicious sequences
        sequence = self._check_suspicious_sequences(context.tool_calls)
        if sequence:
            return sequence

        return None

    def _check_tool_injection(self, prompt: str) -> Optional[Detection]:
        """Check if prompt tries to inject tool calls."""
        injection_patterns = [
            r"call\s+tool\s*:",
            r"execute\s+function\s*:",
            r"\{\"?tool\"?\s*:",
            r"<tool_call>",
            r"<function>",
            r"run\s+command\s*:",
        ]

        for pattern in injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return Detection(
                    detector=self.name,
                    detection_type=DetectionType.TOOL_ABUSE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    description="Tool call injection attempt detected",
                    evidence=pattern,
                    metadata={"pattern": pattern},
                )

        return None

    def _check_sensitive_tools(self, tool_calls: list[ToolCall]) -> Optional[Detection]:
        """Check for access to sensitive tools."""
        for call in tool_calls:
            for pattern in self._sensitive_patterns:
                if pattern.match(call.tool_name):
                    return Detection(
                        detector=self.name,
                        detection_type=DetectionType.TOOL_ABUSE,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"Sensitive tool access: {call.tool_name}",
                        evidence=call.tool_name,
                        metadata={"tool_name": call.tool_name},
                    )
        return None

    def _check_suspicious_sequences(
        self, tool_calls: list[ToolCall]
    ) -> Optional[Detection]:
        """Check for suspicious tool call sequences."""
        if len(tool_calls) < 2:
            return None

        tool_names = [call.tool_name.lower() for call in tool_calls]

        for first, second in self.SUSPICIOUS_SEQUENCES:
            for i in range(len(tool_names) - 1):
                if first in tool_names[i] and second in tool_names[i + 1]:
                    return Detection(
                        detector=self.name,
                        detection_type=DetectionType.TOOL_ABUSE,
                        severity=Severity.HIGH,
                        confidence=0.75,
                        description=f"Suspicious tool sequence: {first} → {second}",
                        evidence=f"{tool_names[i]} → {tool_names[i+1]}",
                        metadata={
                            "sequence": [tool_names[i], tool_names[i + 1]],
                        },
                    )

        return None
