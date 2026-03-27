"""
Detection Engine

Central orchestrator that coordinates:
- Pipeline execution (parallel detectors)
- Risk aggregation
- Policy evaluation
- Result assembly
"""

import asyncio
import time
from typing import Optional

from trigguard.protocol.detection_event import (
    AggregatedRisk,
    Detection,
    DetectionRequest,
    DetectionResult,
    Decision,
)
from pipeline.pipeline import Pipeline, PipelineConfig
from trigguard.aggregation.risk_aggregator import RiskAggregator
from trigguard.policy.policy_engine import PolicyEngine


class DetectionEngine:
    """
    Main entry point for the detection system.

    Detection flow:
    1. Request → Pipeline (parallel detectors)
    2. Detections → RiskAggregator
    3. AggregatedRisk → PolicyEngine
    4. Decision → DetectionResult
    """

    def __init__(
        self,
        pipeline: Optional[Pipeline] = None,
        aggregator: Optional[RiskAggregator] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.pipeline = pipeline or Pipeline()
        self.aggregator = aggregator or RiskAggregator()
        self.policy_engine = policy_engine or PolicyEngine()

    def analyze(self, request: DetectionRequest) -> DetectionResult:
        """
        Analyze a request through the full detection pipeline.

        Flow:
        1. Run parallel detectors
        2. Aggregate risk signals
        3. Evaluate policy
        4. Return decision

        Args:
            request: The detection request to analyze.

        Returns:
            DetectionResult with all findings, risk score, and decision.
        """
        start_time = time.perf_counter()

        # Stage 1: Run detection pipeline (parallel)
        detections = self.pipeline.run(request)

        # Stage 2: Aggregate risk
        aggregated_risk = self.aggregator.aggregate(detections)

        # Stage 3: Evaluate policy
        decision = self.policy_engine.evaluate(detections, aggregated_risk)

        # Calculate processing time
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return DetectionResult(
            request_id=request.request_id,
            detections=detections,
            aggregated_risk=aggregated_risk,
            decision=decision,
            processing_time_ms=elapsed_ms,
        )

    async def analyze_async(self, request: DetectionRequest) -> DetectionResult:
        """
        Async version of analyze for high-throughput scenarios.

        Args:
            request: The detection request to analyze.

        Returns:
            DetectionResult with all findings, risk score, and decision.
        """
        start_time = time.perf_counter()

        # Stage 1: Run detection pipeline (parallel async)
        detections = await self.pipeline.run_async(request)

        # Stage 2: Aggregate risk
        aggregated_risk = self.aggregator.aggregate(detections)

        # Stage 3: Evaluate policy
        decision = self.policy_engine.evaluate(detections, aggregated_risk)

        # Calculate processing time
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return DetectionResult(
            request_id=request.request_id,
            detections=detections,
            aggregated_risk=aggregated_risk,
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
        """Shutdown all detectors and pipeline."""
        for detector in self.pipeline.detectors:
            detector.shutdown()
        self.pipeline.shutdown()
