"""
Base Detector Interface

All detectors must inherit from this base class.
This ensures consistent interface across all detection modules.
"""

from abc import ABC, abstractmethod
from typing import Optional

from protocol.detection_event import Detection, DetectionRequest


class BaseDetector(ABC):
    """
    Abstract base class for all detectors.

    Each detector is responsible for:
    - Analyzing a request for a specific threat type
    - Returning a Detection if a threat is found
    - Returning None if no threat is detected
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

    @abstractmethod
    def analyze(self, request: DetectionRequest) -> Optional[Detection]:
        """
        Analyze the request for threats.

        Args:
            request: The detection request to analyze.

        Returns:
            Detection if a threat is found, None otherwise.
        """
        pass

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
