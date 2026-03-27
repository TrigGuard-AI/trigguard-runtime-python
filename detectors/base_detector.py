"""
Base Detector Interface

All detectors must inherit from this base class.
This ensures consistent interface across all detection modules.
"""

from abc import ABC, abstractmethod
from typing import Optional, Union

from protocol.detection_event import Detection, DetectionContext, DetectionRequest


class BaseDetector(ABC):
    """
    Abstract base class for all detectors.

    Each detector is responsible for:
    - Analyzing a request/context for a specific threat type
    - Returning a Detection if a threat is found
    - Returning None if no threat is detected

    Detectors can implement either:
    - analyze(request: DetectionRequest) - simple single-prompt analysis
    - analyze_context(context: DetectionContext) - conversation-aware analysis

    The pipeline will call the appropriate method based on detector capabilities.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this detector."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version of this detector."""
        pass

    @property
    def supports_context(self) -> bool:
        """
        Whether this detector supports DetectionContext.
        Override to return True for conversation-aware detectors.
        """
        return False

    @abstractmethod
    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """
        Analyze the request for threats (simple interface).

        Args:
            request: The detection request to analyze.

        Returns:
            Detection if a threat is found, None otherwise.
        """
        pass

    def analyze_context(self, context: DetectionContext) -> Optional[Detection]:
        """
        Analyze the context for threats (conversation-aware interface).

        Override this method for multi-turn detection capabilities.
        Default implementation falls back to simple analyze().

        Args:
            context: The detection context with conversation history.

        Returns:
            Detection if a threat is found, None otherwise.
        """
        # Default: create a simple request and use analyze()
        request = DetectionRequest(
            prompt=context.current_prompt,
            context=context.system_prompt,
            user_id=context.user_id,
            session_id=context.session_id,
            metadata=context.metadata,
            request_id=context.request_id,
        )
        return self.analyze(request)

    def is_enabled(self) -> bool:
        """Check if this detector is enabled. Override for dynamic control."""
        return True

    def warmup(self) -> None:
        """
        Optional warmup routine.
        Override to load models, rules, or other resources.
        """
        pass

    def shutdown(self) -> None:
        """
        Optional cleanup routine.
        Override to release resources.
        """
        pass
