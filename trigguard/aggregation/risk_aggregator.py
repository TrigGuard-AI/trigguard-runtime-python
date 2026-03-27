"""
Risk Aggregator

Aggregates detection results into a unified risk assessment.
This stage sits between parallel detectors and policy evaluation.
"""

from typing import Optional

from trigguard.protocol.detection_event import (
    AggregatedRisk,
    Detection,
    Severity,
)


class RiskAggregator:
    """
    Aggregates multiple detection signals into a unified risk score.

    The aggregation strategy:
    1. Weight each detection by severity and confidence
    2. Apply diminishing returns for multiple signals
    3. Cap at 1.0 maximum risk score
    4. Determine overall severity level

    This pattern handles:
    - Single high-confidence detection → HIGH risk
    - Multiple medium signals → aggregated HIGH risk
    - No detections → LOW risk
    """

    # Severity weights for risk calculation
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.2,
        Severity.INFO: 0.1,
    }

    # Risk score thresholds for severity mapping
    RISK_THRESHOLDS = {
        0.8: Severity.CRITICAL,
        0.6: Severity.HIGH,
        0.4: Severity.MEDIUM,
        0.2: Severity.LOW,
    }

    def __init__(self, diminishing_factor: float = 0.5):
        """
        Initialize the aggregator.

        Args:
            diminishing_factor: Factor for diminishing returns on multiple signals.
                               Lower = faster diminishing. Default 0.5.
        """
        self.diminishing_factor = diminishing_factor

    def aggregate(self, detections: list[Detection]) -> AggregatedRisk:
        """
        Aggregate detection results into a unified risk assessment.

        Args:
            detections: List of detections from all detectors.

        Returns:
            AggregatedRisk with computed risk score and metadata.
        """
        if not detections:
            return AggregatedRisk(
                risk_score=0.0,
                severity=Severity.INFO,
                triggered_detectors=[],
                detection_count=0,
                max_confidence=0.0,
            )

        # Calculate weighted scores
        weighted_scores = [
            self.SEVERITY_WEIGHTS[d.severity] * d.confidence for d in detections
        ]

        # Aggregate with diminishing returns
        risk_score = self._compute_risk_score(weighted_scores)

        # Determine severity from detections (max severity wins)
        severity = self._determine_severity(detections)

        # Override severity based on aggregated risk score if higher
        score_severity = self._severity_from_score(risk_score)
        if self._severity_rank(score_severity) < self._severity_rank(severity):
            severity = score_severity

        return AggregatedRisk(
            risk_score=risk_score,
            severity=severity,
            triggered_detectors=list(set(d.detector for d in detections)),
            detection_count=len(detections),
            max_confidence=max(d.confidence for d in detections),
            metadata={
                "individual_scores": weighted_scores,
                "aggregation_method": "diminishing_returns",
            },
        )

    def _compute_risk_score(self, weighted_scores: list[float]) -> float:
        """Compute risk score with diminishing returns."""
        if not weighted_scores:
            return 0.0

        sorted_scores = sorted(weighted_scores, reverse=True)
        risk_score = sorted_scores[0]

        for i, score in enumerate(sorted_scores[1:], start=1):
            risk_score += score * (self.diminishing_factor**i)

        return min(risk_score, 1.0)

    def _determine_severity(self, detections: list[Detection]) -> Severity:
        """Determine max severity from detections."""
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        for severity in severity_order:
            if any(d.severity == severity for d in detections):
                return severity

        return Severity.INFO

    def _severity_from_score(self, score: float) -> Severity:
        """Map risk score to severity level."""
        for threshold, severity in sorted(self.RISK_THRESHOLDS.items(), reverse=True):
            if score >= threshold:
                return severity
        return Severity.INFO

    def _severity_rank(self, severity: Severity) -> int:
        """Get numeric rank for severity comparison (lower = more severe)."""
        ranks = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return ranks.get(severity, 4)
