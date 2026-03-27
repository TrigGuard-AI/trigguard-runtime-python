"""
Detection Pipeline

Orchestrates the execution of detectors in sequence.
Supports future extensions for parallel and async execution.
"""

from dataclasses import dataclass, field
from typing import Optional
import time

from protocol.detection_event import Detection, DetectionRequest, DetectionResult
from detectors.base_detector import BaseDetector


@dataclass
class PipelineConfig:
    """Pipeline configuration."""
    fail_fast: bool = False  # Stop on first detection
    parallel: bool = False   # Run detectors in parallel (future)
    timeout_ms: float = 5000 # Max execution time


class Pipeline:
    """
    Detection pipeline that runs multiple detectors.

    The pipeline:
    1. Receives a request
    2. Runs each detector in sequence
    3. Collects all detections
    4. Returns aggregated results
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self._detectors: list[BaseDetector] = []

    def register(self, detector: BaseDetector) -> None:
        """Register a detector to the pipeline."""
        self._detectors.append(detector)

    def register_many(self, detectors: list[BaseDetector]) -> None:
        """Register multiple detectors."""
        for detector in detectors:
            self.register(detector)

    def run(self, request: DetectionRequest) -> list[Detection]:
        """
        Execute all detectors on the request.

        Args:
            request: The detection request to process.

        Returns:
            List of detections found by all detectors.
        """
        detections: list[Detection] = []

        for detector in self._detectors:
            if not detector.is_enabled():
                continue

            try:
                result = detector.analyze(request)
                if result is not None:
                    detections.append(result)

                    if self.config.fail_fast:
                        break

            except Exception as e:
                # Log error but continue pipeline
                # In production, use proper logging
                print(f"Detector {detector.name} failed: {e}")

        return detections

    @property
    def detectors(self) -> list[BaseDetector]:
        """List of registered detectors."""
        return self._detectors.copy()
