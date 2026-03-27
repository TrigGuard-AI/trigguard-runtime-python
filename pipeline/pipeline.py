"""
Detection Pipeline

Orchestrates the execution of detectors.
Supports both sequential and parallel (async) execution.

Flow:
1. Request → ContextBuilder → DetectionContext
2. DetectionContext → Parallel Detectors
3. Detections collected and returned
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional, Union
import time

from trigguard.protocol.detection_event import (
    Detection,
    DetectionContext,
    DetectionRequest,
    DetectionResult,
)
from detectors.base_detector import BaseDetector
from trigguard.context.context_builder import ContextBuilder


@dataclass
class PipelineConfig:
    """Pipeline configuration."""

    fail_fast: bool = False  # Stop on first detection (sequential only)
    parallel: bool = True  # Run detectors in parallel
    timeout_ms: float = 5000  # Max execution time per detector
    max_workers: int = 10  # Max parallel workers
    use_context: bool = True  # Build DetectionContext before running detectors


class Pipeline:
    """
    Detection pipeline that runs multiple detectors.

    The pipeline:
    1. Receives a request
    2. Builds DetectionContext (if use_context=True)
    3. Runs detectors (parallel or sequential)
    4. Collects all detections
    5. Returns list of detection signals

    Supports:
    - Async parallel execution (default)
    - Sync sequential execution (fallback)
    - Context-aware detection (multi-turn conversations)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self._detectors: list[BaseDetector] = []
        self._context_builder = ContextBuilder()
        self._executor: Optional[ThreadPoolExecutor] = None

    def register(self, detector: BaseDetector) -> None:
        """Register a detector to the pipeline."""
        self._detectors.append(detector)

    def register_many(self, detectors: list[BaseDetector]) -> None:
        """Register multiple detectors."""
        for detector in detectors:
            self.register(detector)

    async def run_async(
        self, request: DetectionRequest, context: Optional[DetectionContext] = None
    ) -> list[Detection]:
        """
        Execute all detectors in parallel using asyncio.

        Args:
            request: The detection request to process.
            context: Pre-built context (optional, built from request if not provided).

        Returns:
            List of detections found by all detectors.
        """
        if not self._detectors:
            return []

        # Build context if not provided and config enables it
        if context is None and self.config.use_context:
            context = self._context_builder.build(request)

        enabled_detectors = [d for d in self._detectors if d.is_enabled()]

        if not enabled_detectors:
            return []

        # Run detectors in parallel
        tasks = [
            self._run_detector_async(detector, request, context)
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
        self,
        detector: BaseDetector,
        request: DetectionRequest,
        context: Optional[DetectionContext] = None,
    ) -> Optional[Detection]:
        """Run a single detector with timeout."""
        loop = asyncio.get_event_loop()

        try:
            # Choose the right method based on detector capabilities
            if context is not None and detector.supports_context:
                analyze_fn = lambda: detector.analyze_context(context)
            elif context is not None:
                # Detector doesn't support context, use analyze_context default fallback
                analyze_fn = lambda: detector.analyze_context(context)
            else:
                analyze_fn = lambda: detector.analyze(request)

            # Run sync detector in thread pool to not block
            result = await asyncio.wait_for(
                loop.run_in_executor(None, analyze_fn),
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
        # Build context first if enabled
        context = None
        if self.config.use_context:
            context = self._context_builder.build(request)

        if self.config.parallel:
            # Run async pipeline in sync context
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Already in async context, run sync fallback
                    return self._run_sequential(request, context)
                return loop.run_until_complete(self.run_async(request, context))
            except RuntimeError:
                # No event loop, create one
                return asyncio.run(self.run_async(request, context))
        else:
            return self._run_sequential(request, context)

    def _run_sequential(
        self, request: DetectionRequest, context: Optional[DetectionContext] = None
    ) -> list[Detection]:
        """Sequential execution fallback."""
        detections: list[Detection] = []

        for detector in self._detectors:
            if not detector.is_enabled():
                continue

            try:
                # Choose the right method based on detector capabilities
                if context is not None and detector.supports_context:
                    result = detector.analyze_context(context)
                elif context is not None:
                    result = detector.analyze_context(context)
                else:
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
