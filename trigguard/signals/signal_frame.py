"""
Signal Frame Builder

Converts detector outputs into normalized SignalFrames for policy evaluation.
This is the bridge between detection (observation) and authorization (decision).

Detectors produce observations.
SignalFrameBuilder normalizes them into policy-evaluable signals.
"""

from typing import Any, Optional
from uuid import UUID

from trigguard.protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionRequest,
)

# Mapping from detection types to signal types
DETECTION_TO_SIGNAL_MAP = {
    "prompt_injection": SignalType.PROMPT_OVERRIDE,
    "jailbreak": SignalType.JAILBREAK_ATTEMPT,
    "data_exfiltration": SignalType.DATA_EXFILTRATION,
    "pii_exposure": SignalType.PII_EXPOSURE,
    "toxicity": SignalType.POLICY_VIOLATION,
    "policy_violation": SignalType.POLICY_VIOLATION,
    "tool_abuse": SignalType.TOOL_CALL_ESCALATION,
    "conversation_manipulation": SignalType.MULTI_TURN_MANIPULATION,
    "role_escalation": SignalType.ROLE_ESCALATION,
}

# Mapping from detection severity to signal severity
SEVERITY_MAP = {
    "critical": SignalSeverity.CRITICAL,
    "high": SignalSeverity.HIGH,
    "medium": SignalSeverity.MEDIUM,
    "low": SignalSeverity.LOW,
    "info": SignalSeverity.INFO,
}


class SignalFrameBuilder:
    """
    Builds SignalFrames from detector outputs.

    This layer ensures:
    - Detectors remain signal producers only
    - All signals are normalized to standard types
    - SignalFrame is the only input to policy evaluation
    """

    def __init__(self):
        pass

    def build(
        self,
        request_id: UUID,
        detections: list[Any],
    ) -> SignalFrame:
        """
        Build a SignalFrame from detector outputs.

        Args:
            request_id: The execution request ID.
            detections: List of Detection objects from detectors.

        Returns:
            SignalFrame ready for policy evaluation.
        """
        frame = SignalFrame(request_id=request_id)

        for detection in detections:
            signal = self._detection_to_signal(detection)
            if signal:
                frame.add_signal(signal)

        return frame

    def _detection_to_signal(self, detection: Any) -> Optional[Signal]:
        """Convert a Detection to a normalized Signal."""
        try:
            # Get detection type string
            detection_type = self._get_detection_type(detection)

            # Map to signal type
            signal_type = DETECTION_TO_SIGNAL_MAP.get(
                detection_type, SignalType.UNKNOWN
            )

            # Get severity
            severity_str = self._get_severity(detection)
            severity = SEVERITY_MAP.get(severity_str, SignalSeverity.MEDIUM)

            # Get confidence
            confidence = getattr(detection, "confidence", 0.5)
            if isinstance(confidence, (int, float)):
                confidence = float(confidence)
            else:
                confidence = 0.5

            # Get source detector name
            source = getattr(detection, "detector", "unknown")

            # Get description
            description = getattr(detection, "description", "No description")

            # Get evidence
            evidence = getattr(detection, "evidence", None)

            return Signal(
                signal_type=signal_type,
                severity=severity,
                confidence=confidence,
                source=source,
                description=description,
                evidence=evidence,
                metadata=getattr(detection, "metadata", {}),
            )

        except Exception as e:
            # If we can't convert, create an anomaly signal
            return Signal(
                signal_type=SignalType.ANOMALY,
                severity=SignalSeverity.LOW,
                confidence=0.3,
                source="signal_frame_builder",
                description=f"Failed to convert detection: {e}",
            )

    def _get_detection_type(self, detection: Any) -> str:
        """Extract detection type as string."""
        detection_type = getattr(detection, "detection_type", None)
        if detection_type is None:
            return "unknown"

        # Handle enum
        if hasattr(detection_type, "value"):
            return detection_type.value

        return str(detection_type)

    def _get_severity(self, detection: Any) -> str:
        """Extract severity as string."""
        severity = getattr(detection, "severity", None)
        if severity is None:
            return "medium"

        # Handle enum
        if hasattr(severity, "value"):
            return severity.value

        return str(severity)

    def add_explicit_signal(
        self,
        frame: SignalFrame,
        signal_type: SignalType,
        severity: SignalSeverity,
        confidence: float,
        source: str,
        description: str,
        evidence: Optional[str] = None,
    ) -> SignalFrame:
        """
        Add an explicit signal to a frame.

        Use this for signals that don't come from detectors
        (e.g., rate limit checks, authentication status).
        """
        signal = Signal(
            signal_type=signal_type,
            severity=severity,
            confidence=confidence,
            source=source,
            description=description,
            evidence=evidence,
        )
        frame.add_signal(signal)
        return frame

    @staticmethod
    def create_empty_frame(request_id: UUID) -> SignalFrame:
        """Create an empty SignalFrame for a request."""
        return SignalFrame(request_id=request_id)


class SignalAggregator:
    """
    Aggregates signals from multiple sources into a unified SignalFrame.

    This handles:
    - Merging signals from multiple detectors
    - Deduplicating similar signals
    - Computing aggregate risk score
    """

    def __init__(self, builder: Optional[SignalFrameBuilder] = None):
        self.builder = builder or SignalFrameBuilder()

    def aggregate(
        self,
        request_id: UUID,
        detector_results: list[Any],
        explicit_signals: Optional[list[Signal]] = None,
    ) -> SignalFrame:
        """
        Aggregate all signals into a single SignalFrame.

        Args:
            request_id: The execution request ID.
            detector_results: Detection objects from all detectors.
            explicit_signals: Additional explicit signals to include.

        Returns:
            Unified SignalFrame for policy evaluation.
        """
        # Build frame from detector results
        frame = self.builder.build(request_id, detector_results)

        # Add explicit signals
        if explicit_signals:
            for signal in explicit_signals:
                frame.add_signal(signal)

        return frame

    def merge_frames(self, frames: list[SignalFrame]) -> SignalFrame:
        """Merge multiple SignalFrames into one."""
        if not frames:
            raise ValueError("Cannot merge empty list of frames")

        merged = SignalFrame(request_id=frames[0].request_id)

        seen_signals: set[tuple] = set()

        for frame in frames:
            for signal in frame.signals:
                # Deduplicate by (type, source, evidence)
                key = (signal.signal_type, signal.source, signal.evidence)
                if key not in seen_signals:
                    merged.add_signal(signal)
                    seen_signals.add(key)

        return merged
