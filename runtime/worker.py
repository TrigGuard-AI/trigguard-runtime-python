"""
Worker Runtime

Executes detection jobs from queues or API calls.
Entry point for the detection system.
"""

from typing import Any, Optional

from trigguard.engine.detection_engine import DetectionEngine
from trigguard.protocol.detection_event import DetectionRequest, DetectionResult


class Worker:
    """
    Runtime worker that processes detection requests.

    In production, this would:
    - Consume from Kafka/Redis/SQS
    - Handle batching
    - Manage concurrency
    - Report metrics
    """

    def __init__(self, engine: Optional[DetectionEngine] = None):
        self.engine = engine or DetectionEngine()
        self._running = False

    def process(self, request: DetectionRequest) -> DetectionResult:
        """
        Process a single detection request.

        Args:
            request: The detection request to process.

        Returns:
            DetectionResult with findings and decision.
        """
        return self.engine.analyze(request)

    def process_raw(self, prompt: str, **kwargs) -> DetectionResult:
        """
        Process a raw prompt string.

        Convenience method for simple use cases.
        """
        request = DetectionRequest(prompt=prompt, **kwargs)
        return self.process(request)

    def start(self) -> None:
        """
        Start the worker loop.

        In production, this would:
        - Connect to message queue
        - Start consuming messages
        - Run until shutdown
        """
        self._running = True
        self.engine.warmup()
        # Main loop would go here

    def stop(self) -> None:
        """Stop the worker gracefully."""
        self._running = False
        self.engine.shutdown()

    @property
    def is_running(self) -> bool:
        return self._running
