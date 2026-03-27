"""
SignalFrame Tests

Tests for canonical SignalFrame structure.
Verifies:
- Invalid signals rejected
- Deterministic serialization
- Signals preserved in order
"""

import json
import pytest
from datetime import datetime
from uuid import uuid4

from trigguard.protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionSurface,
    InvalidSignalError,
)


class TestSignalFrameValidation:
    """Tests for signal validation in SignalFrame."""

    def test_add_valid_signal_succeeds(self):
        """Valid signals are accepted."""
        frame = SignalFrame(request_id=uuid4())
        signal = Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="test_detector",
            description="Test jailbreak attempt",
        )

        frame.add_signal(signal)

        assert len(frame.signals) == 1
        assert frame.signal_count == 1
        assert frame.signals[0].signal_type == SignalType.JAILBREAK_ATTEMPT

    def test_add_invalid_signal_type_raises(self):
        """Invalid signal types are rejected."""
        frame = SignalFrame(request_id=uuid4())

        # Create a signal with invalid type
        signal = Signal(
            signal_type=SignalType.UNKNOWN,  # Valid type, but let's test invalid
            severity=SignalSeverity.HIGH,
            confidence=0.9,
            source="test",
            description="test",
        )
        # Manually corrupt the signal type
        signal.signal_type = "not_a_real_signal_type"  # type: ignore

        with pytest.raises(InvalidSignalError):
            frame.add_signal(signal)

    def test_add_invalid_severity_raises(self):
        """Invalid severity values are rejected."""
        frame = SignalFrame(request_id=uuid4())

        signal = Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.HIGH,
            confidence=0.9,
            source="test",
            description="test",
        )
        # Manually corrupt the severity
        signal.severity = "invalid_severity"  # type: ignore

        with pytest.raises(InvalidSignalError):
            frame.add_signal(signal)

    def test_validation_can_be_skipped(self):
        """Validation can be explicitly skipped."""
        frame = SignalFrame(request_id=uuid4())

        signal = Signal(
            signal_type=SignalType.UNKNOWN,
            severity=SignalSeverity.INFO,
            confidence=0.5,
            source="test",
            description="test",
        )

        # Should not raise even if we corrupt and skip validation
        frame.add_signal(signal, validate=False)
        assert len(frame.signals) == 1


class TestSignalFrameSerialization:
    """Tests for deterministic SignalFrame serialization."""

    def test_to_canonical_json_is_deterministic(self):
        """Same frame produces same JSON across multiple calls."""
        request_id = uuid4()
        timestamp = datetime(2024, 1, 15, 12, 0, 0)

        frame1 = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.SPEND,
            timestamp=timestamp,
        )
        frame1.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.95,
                source="detector_a",
                description="Test signal",
            )
        )

        # Create identical frame
        frame2 = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.SPEND,
            timestamp=timestamp,
        )
        frame2.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.95,
                source="detector_a",
                description="Test signal",
            )
        )

        # JSON should be identical
        json1 = frame1.to_canonical_json()
        json2 = frame2.to_canonical_json()

        assert json1 == json2, "Canonical JSON should be deterministic"

    def test_canonical_json_keys_are_sorted(self):
        """JSON output has alphabetically sorted keys."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.INFERENCE,
        )

        json_str = frame.to_canonical_json()
        parsed = json.loads(json_str)

        # Top-level keys should be sorted
        keys = list(parsed.keys())
        assert keys == sorted(keys), "Top-level keys should be sorted"

    def test_canonical_dict_has_required_fields(self):
        """Canonical dict contains all required fields."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
            metadata={"key": "value"},
        )

        canonical = frame.to_canonical_dict()

        assert "request_id" in canonical
        assert "surface" in canonical
        assert "signals" in canonical
        assert "metadata" in canonical
        assert "timestamp" in canonical
        assert "risk_score" in canonical
        assert "signal_count" in canonical

    def test_signals_serialized_in_order(self):
        """Signals are serialized in the order they were added."""
        frame = SignalFrame(request_id=uuid4())

        # Add signals in specific order
        signals_to_add = [
            SignalType.PROMPT_OVERRIDE,
            SignalType.JAILBREAK_ATTEMPT,
            SignalType.DATA_EXFILTRATION,
        ]

        for i, signal_type in enumerate(signals_to_add):
            frame.add_signal(
                Signal(
                    signal_type=signal_type,
                    severity=SignalSeverity.HIGH,
                    confidence=0.9,
                    source=f"detector_{i}",
                    description=f"Signal {i}",
                )
            )

        canonical = frame.to_canonical_dict()

        # Verify order matches
        for i, expected_type in enumerate(signals_to_add):
            assert canonical["signals"][i]["signal_type"] == expected_type.value

    def test_canonical_json_is_parseable(self):
        """Canonical JSON can be parsed back to dict."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CODE_EXECUTION,
            metadata={"context": "test"},
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.UNAUTHORIZED_EXECUTION,
                severity=SignalSeverity.CRITICAL,
                confidence=0.99,
                source="code_detector",
                description="Unauthorized code execution attempt",
            )
        )

        json_str = frame.to_canonical_json()
        parsed = json.loads(json_str)

        assert parsed["surface"] == "code_execution"
        assert len(parsed["signals"]) == 1
        assert parsed["signals"][0]["signal_type"] == "unauthorized_execution"

    def test_metadata_is_sorted(self):
        """Metadata keys are sorted in canonical output."""
        frame = SignalFrame(
            request_id=uuid4(),
            metadata={"z_key": 1, "a_key": 2, "m_key": 3},
        )

        canonical = frame.to_canonical_dict()
        metadata_keys = list(canonical["metadata"].keys())

        assert metadata_keys == sorted(metadata_keys)


class TestSignalFrameAggregation:
    """Tests for signal aggregation in frame."""

    def test_risk_score_computed_on_add(self):
        """Risk score is recomputed when signals are added."""
        frame = SignalFrame(request_id=uuid4())
        assert frame.risk_score == 0.0

        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=1.0,
                source="test",
                description="test",
            )
        )

        assert frame.risk_score > 0.0

    def test_max_severity_tracked(self):
        """Max severity is correctly tracked."""
        frame = SignalFrame(request_id=uuid4())
        assert frame.max_severity == SignalSeverity.INFO

        # Add LOW signal
        frame.add_signal(
            Signal(
                signal_type=SignalType.ANOMALY,
                severity=SignalSeverity.LOW,
                confidence=0.5,
                source="test",
                description="test",
            )
        )
        assert frame.max_severity == SignalSeverity.LOW

        # Add CRITICAL signal
        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.9,
                source="test",
                description="test",
            )
        )
        assert frame.max_severity == SignalSeverity.CRITICAL

    def test_signal_count_accurate(self):
        """Signal count is accurate."""
        frame = SignalFrame(request_id=uuid4())

        for i in range(5):
            frame.add_signal(
                Signal(
                    signal_type=SignalType.ANOMALY,
                    severity=SignalSeverity.LOW,
                    confidence=0.3,
                    source="test",
                    description=f"Signal {i}",
                )
            )

        assert frame.signal_count == 5
        assert len(frame.signals) == 5

    def test_has_signal_type(self):
        """has_signal_type correctly identifies present signals."""
        frame = SignalFrame(request_id=uuid4())

        assert frame.has_signal_type(SignalType.JAILBREAK_ATTEMPT) is False

        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.9,
                source="test",
                description="test",
            )
        )

        assert frame.has_signal_type(SignalType.JAILBREAK_ATTEMPT) is True
        assert frame.has_signal_type(SignalType.PROMPT_OVERRIDE) is False

    def test_get_signals_by_type(self):
        """get_signals_by_type returns correct signals."""
        frame = SignalFrame(request_id=uuid4())

        # Add multiple signals of same type
        frame.add_signal(
            Signal(
                signal_type=SignalType.PROMPT_OVERRIDE,
                severity=SignalSeverity.HIGH,
                confidence=0.8,
                source="detector_1",
                description="First override",
            )
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.9,
                source="detector_2",
                description="Jailbreak",
            )
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.PROMPT_OVERRIDE,
                severity=SignalSeverity.MEDIUM,
                confidence=0.6,
                source="detector_3",
                description="Second override",
            )
        )

        overrides = frame.get_signals_by_type(SignalType.PROMPT_OVERRIDE)
        assert len(overrides) == 2

        jailbreaks = frame.get_signals_by_type(SignalType.JAILBREAK_ATTEMPT)
        assert len(jailbreaks) == 1


class TestSignalFrameValidateAll:
    """Tests for validate_all_signals method."""

    def test_validate_all_passes_for_valid_frame(self):
        """validate_all_signals returns empty list for valid frame."""
        frame = SignalFrame(request_id=uuid4())
        frame.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.95,
                source="test",
                description="test",
            )
        )

        errors = frame.validate_all_signals()
        assert errors == []

    def test_validate_all_catches_invalid_confidence(self):
        """validate_all_signals catches out-of-range confidence."""
        frame = SignalFrame(request_id=uuid4())
        signal = Signal(
            signal_type=SignalType.ANOMALY,
            severity=SignalSeverity.LOW,
            confidence=1.5,  # Out of range
            source="test",
            description="test",
        )
        # Bypass validation for this test
        frame.signals.append(signal)
        frame.signal_count = 1

        errors = frame.validate_all_signals()
        assert len(errors) == 1
        assert "confidence" in errors[0].lower()


class TestSignalFrameSurface:
    """Tests for surface field in SignalFrame."""

    def test_frame_has_surface_field(self):
        """SignalFrame has surface field."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
        )

        assert frame.surface == ExecutionSurface.SPEND

    def test_surface_included_in_canonical(self):
        """Surface is included in canonical representation."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CODE_EXECUTION,
        )

        canonical = frame.to_canonical_dict()
        assert canonical["surface"] == "code_execution"

    def test_default_surface_is_unknown(self):
        """Default surface is UNKNOWN."""
        frame = SignalFrame(request_id=uuid4())
        assert frame.surface == ExecutionSurface.UNKNOWN
