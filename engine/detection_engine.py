"""
Detection Engine

Central orchestrator that coordinates:
- Pipeline execution
- Policy evaluation
- Result aggregation
"""

import time
from typing import Optional

from protocol.detection_event import (
    Detection,
    DetectionRequest,
    DetectionResult,
    Decision,
)
from pipeline.pipeline import Pipeline, PipelineConfig
from policy.policy_engine import PolicyEngine


class DetectionEngine:
    """
    Main entry point for the detection system.

    The engine:
    1. Receives analysis requests
    2. Delegates to the pipeline
    3. Evaluates policy against results
    4. Returns final decision
    """

    def __init__(
        self,
        pipeline: Optional[Pipeline] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.pipeline = pipeline or Pipeline()
        self.policy_engine = policy_engine or PolicyEngine()

    def analyze(self, request: DetectionRequest) -> DetectionResult:
        """
        Analyze a request through the full detection pipeline.

        Args:
            request: The detection request to analyze.

        Returns:
            DetectionResult with all findings and final decision.
        """
        start_time = time.perf_counter()

        # Run detection pipeline
        detections = self.pipeline.run(request)

        # Evaluate policy
        decision = self.policy_engine.evaluate(detections)

        # Calculate processing time
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return DetectionResult(
            request_id=request.request_id,
            detections=detections,
            decision=decision,
            processing_time_ms=elapsed_ms,
        )

    def register_detector(self, detector) -> None:
        """Register a detector with the pipeline."""
        self.pipeline.register(detector)

    def warmup(self) -> None:
        """Warmup all detectors."""
        for detector in self.pipeline.detectors:
            detector.warmup()

    def shutdown(self) -> None:
        """Shutdown all detectors."""
        for detector in self.pipeline.detectors:
            detector.shutdown()
