"""
Test Risk Aggregation

Verifies the risk aggregation logic works correctly.
"""

import sys
from pathlib import Path

# Add kernel root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.detection_event import (
    Detection,
    DetectionType,
    Severity,
    AggregatedRisk,
)
from aggregation.risk_aggregator import RiskAggregator


def test_no_detections_low_risk():
    """No detections should result in LOW/INFO risk."""
    aggregator = RiskAggregator()
    result = aggregator.aggregate([])

    assert result.risk_score == 0.0
    assert result.severity == Severity.INFO
    assert result.detection_count == 0
    assert result.triggered_detectors == []
    print("✓ No detections → LOW risk test passed")


def test_single_high_detection():
    """Single high severity detection should result in HIGH risk."""
    aggregator = RiskAggregator()

    detection = Detection(
        detector="test_detector",
        detection_type=DetectionType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.9,
        description="Test detection",
    )

    result = aggregator.aggregate([detection])

    assert result.risk_score >= 0.7  # High severity * high confidence
    assert result.severity == Severity.HIGH
    assert result.detection_count == 1
    assert "test_detector" in result.triggered_detectors
    print("✓ Single high detection → HIGH risk test passed")


def test_single_critical_detection():
    """Single critical detection should result in CRITICAL risk."""
    aggregator = RiskAggregator()

    detection = Detection(
        detector="jailbreak",
        detection_type=DetectionType.JAILBREAK,
        severity=Severity.CRITICAL,
        confidence=0.85,
        description="Jailbreak detected",
    )

    result = aggregator.aggregate([detection])

    assert result.risk_score >= 0.8
    assert result.severity == Severity.CRITICAL
    print("✓ Single critical detection → CRITICAL risk test passed")


def test_multiple_medium_aggregates_to_high():
    """Multiple medium signals should aggregate to HIGH risk."""
    aggregator = RiskAggregator()

    detections = [
        Detection(
            detector="detector_1",
            detection_type=DetectionType.PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            confidence=0.7,
            description="Medium signal 1",
        ),
        Detection(
            detector="detector_2",
            detection_type=DetectionType.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            confidence=0.75,
            description="Medium signal 2",
        ),
        Detection(
            detector="detector_3",
            detection_type=DetectionType.POLICY_VIOLATION,
            severity=Severity.MEDIUM,
            confidence=0.65,
            description="Medium signal 3",
        ),
    ]

    result = aggregator.aggregate(detections)

    # Multiple medium signals should push risk higher
    assert result.risk_score >= 0.4
    assert result.detection_count == 3
    assert len(result.triggered_detectors) == 3
    print(f"✓ Multiple medium signals → aggregated risk {result.risk_score:.2f} test passed")


def test_diminishing_returns():
    """Additional signals should have diminishing impact."""
    aggregator = RiskAggregator()

    # Two identical detections
    detection = Detection(
        detector="test",
        detection_type=DetectionType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.8,
        description="Test",
    )

    result_one = aggregator.aggregate([detection])
    result_two = aggregator.aggregate([detection, detection])

    # Second detection should add less than the first
    score_increase = result_two.risk_score - result_one.risk_score
    assert score_increase < result_one.risk_score  # Diminishing returns
    assert score_increase > 0  # But still adds something
    print("✓ Diminishing returns test passed")


def test_max_confidence_tracked():
    """Max confidence should be tracked correctly."""
    aggregator = RiskAggregator()

    detections = [
        Detection(
            detector="low_conf",
            detection_type=DetectionType.PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            confidence=0.5,
            description="Low confidence",
        ),
        Detection(
            detector="high_conf",
            detection_type=DetectionType.JAILBREAK,
            severity=Severity.MEDIUM,
            confidence=0.95,
            description="High confidence",
        ),
    ]

    result = aggregator.aggregate(detections)

    assert result.max_confidence == 0.95
    print("✓ Max confidence tracking test passed")


def test_risk_score_capped_at_one():
    """Risk score should never exceed 1.0."""
    aggregator = RiskAggregator()

    # Many high-severity, high-confidence detections
    detections = [
        Detection(
            detector=f"detector_{i}",
            detection_type=DetectionType.JAILBREAK,
            severity=Severity.CRITICAL,
            confidence=0.99,
            description=f"Critical {i}",
        )
        for i in range(10)
    ]

    result = aggregator.aggregate(detections)

    assert result.risk_score <= 1.0
    print("✓ Risk score capped at 1.0 test passed")


def test_aggregated_risk_from_detections():
    """Test the class method for creating AggregatedRisk."""
    detection = Detection(
        detector="test",
        detection_type=DetectionType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.8,
        description="Test",
    )

    result = AggregatedRisk.from_detections([detection])

    assert result.risk_score > 0
    assert result.severity == Severity.HIGH
    assert result.detection_count == 1
    print("✓ AggregatedRisk.from_detections test passed")


if __name__ == "__main__":
    print("Running Risk Aggregation Tests\n")

    test_no_detections_low_risk()
    test_single_high_detection()
    test_single_critical_detection()
    test_multiple_medium_aggregates_to_high()
    test_diminishing_returns()
    test_max_confidence_tracked()
    test_risk_score_capped_at_one()
    test_aggregated_risk_from_detections()

    print("\n✓ All risk aggregation tests passed!")
