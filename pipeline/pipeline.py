"""
Detection Pipeline

Orchestrates the execution of detectors.
Supports both sequential and parallel (async) execution.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional
import time

from protocol.detection_event import Detection, DetectionRequest, DetectionResult
from detectors.base_detector import BaseDetector


@dataclass
class PipelineConfig:
    """Pipeline configuration."""
    fail_fast: bool = False      # Stop on first detection (sequential only)
    parallel: bool = True        # Run detectors in parallel
    timeout_ms: float = 5000     # Max execution time per detector
    max_workers: int = 10        # Max parallel workers


class Pipeline:
    """
    Detection pipeline that runs multiple detectors.

    The pipeline:
    1. Receives a request
    2. Runs detectors (parallel or sequential)
    3. Collects all detections
    4. Returns list of detection signals

    Supports:
    - Async parallel execution (default)
    - Sync sequential execution (fallback)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self._detectors: list[BaseDetector] = []
        self._executor: Optional[ThreadPoolExecutor] = None

    def register(self, detector: BaseDetector) -> None:
        """Register a detector to the pipeline."""
        self._detectors.append(detector)

    def register_many(self, detectors: list[BaseDetector]) -> None:
        """Register multiple detectors."""
        for detector in detectors:
            self.register(detector)

    async def run_async(self, request: DetectionRequest) -> list[Detection]:
        """
        Execute all detectors in parallel using asyncio.

        Args:
            request: The detection request to process.

        Returns:
            List of detections found by all detectors.
        """
        if not self._detectors:
            return []

        enabled_detectors = [d for d in self._detectors if d.is_enabled()]

        if not enabled_detectors:
            return []

        # Run detectors in parallel
        tasks = [
            self._run_detector_async(detector, request)
            for detector in enabled_detectors
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful detections
        detections: list[Detection] = []
        for result in results:
            if isinstance(result, Exception):
                # Log error but continue
                print(f"Detector failed: {result}")
            elif result is not None:
                detections.append(result)

        return detections

    async def _run_detector_async(
        self, detector: BaseDetector, request: DetectionRequest
    ) -> Optional[Detection]:
        """Run a single detector with timeout."""
        loop = asyncio.get_event_loop()

        try:
            # Run sync detector in thread pool to not block
            result = await asyncio.wait_for(
                loop.run_in_executor(None, detector.analyze, request),
                timeout=self.config.timeout_ms / 1000,
            )
            return result
        except asyncio.TimeoutError:
            print(f"Detector {detector.name} timed out")
            return None
        except Exception as e:
            print(f"Detector {detector.name} failed: {e}")
            return None

    def run(self, request: DetectionRequest) -> list[Detection]:
        """
        Execute all detectors on the request.

        Uses parallel execution if config.parallel is True,
        otherwise falls back to sequential execution.

        Args:
            request: The detection request to process.

        Returns:
            List of detections found by all detectors.
        """
        if self.config.parallel:
            # Run async pipeline in sync context
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Already in async context, run sync fallback
                    return self._run_sequential(request)
                return loop.run_until_complete(self.run_async(request))
            except RuntimeError:
                # No event loop, create one
                return asyncio.run(self.run_async(request))
        else:
            return self._run_sequential(request)

    def _run_sequential(self, request: DetectionRequest) -> list[Detection]:
        """Sequential execution fallback."""
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
                print(f"Detector {detector.name} failed: {e}")

        return detections

    @property
    def detectors(self) -> list[BaseDetector]:
        """List of registered detectors."""
        return self._detectors.copy()

    def shutdown(self) -> None:
        """Cleanup resources."""
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None
