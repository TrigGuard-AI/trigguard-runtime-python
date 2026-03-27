"""
Determinism Tests

Tests that verify TrigGuard's determinism guarantees:
- Same frame → same decision → same hashes
- Hash stability across runs
- Tamper detection

These tests are critical for audit and compliance.
"""

import pytest
from datetime import datetime
from uuid import uuid4, UUID

from protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionSurface,
    Decision,
    DenyReason,
)
from protocol.hash_utils import (
    hash_signal_frame,
    hash_decision,
    hash_receipt,
    compute_all_hashes,
    _canonical_json,
    _sha256_hash,
)


class TestCanonicalJson:
    """Tests for canonical JSON serialization."""

    def test_canonical_json_sorts_keys(self):
        """Keys are sorted alphabetically."""
        data = {"zebra": 1, "apple": 2, "mango": 3}
        result = _canonical_json(data)
        
        assert result == '{"apple":2,"mango":3,"zebra":1}'

    def test_canonical_json_no_whitespace(self):
        """No whitespace in output."""
        data = {"a": 1, "b": 2}
        result = _canonical_json(data)
        
        assert " " not in result
        assert "\n" not in result
        assert "\t" not in result

    def test_canonical_json_handles_nested(self):
        """Nested dicts also have sorted keys."""
        data = {
            "outer": {"z": 1, "a": 2},
            "another": 3,
        }
        result = _canonical_json(data)
        
        # Both levels should be sorted
        assert '"another":3' in result
        assert '"a":2,"z":1' in result

    def test_canonical_json_deterministic(self):
        """Same dict produces same JSON every time."""
        data = {"key": "value", "number": 42}
        
        results = [_canonical_json(data) for _ in range(100)]
        
        assert len(set(results)) == 1, "All results should be identical"


class TestHashSignalFrame:
    """Tests for signal frame hashing."""

    def test_same_frame_same_hash(self):
        """Identical frames produce identical hashes."""
        request_id = UUID("12345678-1234-5678-1234-567812345678")
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        
        frame1 = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.SPEND,
            timestamp=timestamp,
        )
        frame1.add_signal(Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="detector",
            description="test",
        ))
        
        frame2 = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.SPEND,
            timestamp=timestamp,
        )
        frame2.add_signal(Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="detector",
            description="test",
        ))
        
        hash1 = hash_signal_frame(frame1)
        hash2 = hash_signal_frame(frame2)
        
        assert hash1 == hash2

    def test_different_signals_different_hash(self):
        """Frames with different signals produce different hashes."""
        request_id = uuid4()
        
        frame1 = SignalFrame(request_id=request_id)
        frame1.add_signal(Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="detector",
            description="test",
        ))
        
        frame2 = SignalFrame(request_id=request_id)
        frame2.add_signal(Signal(
            signal_type=SignalType.PROMPT_OVERRIDE,
            severity=SignalSeverity.HIGH,
            confidence=0.8,
            source="detector",
            description="test",
        ))
        
        hash1 = hash_signal_frame(frame1)
        hash2 = hash_signal_frame(frame2)
        
        assert hash1 != hash2

    def test_hash_is_sha256(self):
        """Frame hash is a valid SHA-256 hex digest."""
        frame = SignalFrame(request_id=uuid4())
        
        hash_val = hash_signal_frame(frame)
        
        # SHA-256 produces 64 hex characters
        assert len(hash_val) == 64
        assert all(c in "0123456789abcdef" for c in hash_val)

    def test_signal_order_affects_hash(self):
        """Different signal order produces different hash."""
        request_id = uuid4()
        
        signal_a = Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="a",
            description="a",
        )
        signal_b = Signal(
            signal_type=SignalType.PROMPT_OVERRIDE,
            severity=SignalSeverity.HIGH,
            confidence=0.8,
            source="b",
            description="b",
        )
        
        frame1 = SignalFrame(request_id=request_id)
        frame1.add_signal(signal_a)
        frame1.add_signal(signal_b)
        
        frame2 = SignalFrame(request_id=request_id)
        frame2.add_signal(signal_b)
        frame2.add_signal(signal_a)
        
        hash1 = hash_signal_frame(frame1)
        hash2 = hash_signal_frame(frame2)
        
        # Order matters for auditability
        assert hash1 != hash2


class TestHashDecision:
    """Tests for decision hashing."""

    def test_same_decision_same_hash(self):
        """Same decision details produce same hash."""
        hash1 = hash_decision(
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            surface=ExecutionSurface.SPEND,
            risk_score=0.85,
            signal_count=3,
        )
        hash2 = hash_decision(
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            surface=ExecutionSurface.SPEND,
            risk_score=0.85,
            signal_count=3,
        )
        
        assert hash1 == hash2

    def test_different_decision_different_hash(self):
        """Different decisions produce different hashes."""
        hash_deny = hash_decision(
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            surface=ExecutionSurface.SPEND,
            risk_score=0.85,
            signal_count=3,
        )
        hash_permit = hash_decision(
            decision=Decision.PERMIT,
            reason=None,
            surface=ExecutionSurface.SPEND,
            risk_score=0.1,
            signal_count=0,
        )
        
        assert hash_deny != hash_permit

    def test_risk_score_precision(self):
        """Risk score hashing handles floating point precision."""
        # These should be equal after rounding
        hash1 = hash_decision(
            decision=Decision.DENY,
            reason=DenyReason.RISK_THRESHOLD_EXCEEDED,
            surface=ExecutionSurface.SPEND,
            risk_score=0.8500001,
            signal_count=1,
        )
        hash2 = hash_decision(
            decision=Decision.DENY,
            reason=DenyReason.RISK_THRESHOLD_EXCEEDED,
            surface=ExecutionSurface.SPEND,
            risk_score=0.8500002,
            signal_count=1,
        )
        
        # Should be equal due to rounding to 6 decimal places
        assert hash1 == hash2


class TestHashReceipt:
    """Tests for receipt hashing."""

    def test_receipt_hash_chains_hashes(self):
        """Receipt hash depends on frame and decision hashes."""
        request_id = uuid4()
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        
        hash1 = hash_receipt(
            request_id=request_id,
            decision=Decision.DENY,
            frame_hash="abc123",
            decision_hash="def456",
            policy_version="v1",
            timestamp=timestamp,
        )
        
        # Different frame hash
        hash2 = hash_receipt(
            request_id=request_id,
            decision=Decision.DENY,
            frame_hash="xyz789",  # Different
            decision_hash="def456",
            policy_version="v1",
            timestamp=timestamp,
        )
        
        assert hash1 != hash2

    def test_policy_version_in_hash(self):
        """Policy version affects receipt hash."""
        request_id = uuid4()
        timestamp = datetime.utcnow()
        
        hash_v1 = hash_receipt(
            request_id=request_id,
            decision=Decision.PERMIT,
            frame_hash="abc",
            decision_hash="def",
            policy_version="v1",
            timestamp=timestamp,
        )
        hash_v2 = hash_receipt(
            request_id=request_id,
            decision=Decision.PERMIT,
            frame_hash="abc",
            decision_hash="def",
            policy_version="v2",
            timestamp=timestamp,
        )
        
        assert hash_v1 != hash_v2


class TestComputeAllHashes:
    """Tests for complete hash chain computation."""

    def test_compute_all_hashes_returns_all(self):
        """compute_all_hashes returns all three hashes."""
        frame = SignalFrame(request_id=uuid4())
        timestamp = datetime.utcnow()
        
        hashes = compute_all_hashes(
            frame=frame,
            decision=Decision.PERMIT,
            reason=None,
            surface=ExecutionSurface.INFERENCE,
            risk_score=0.1,
            signal_count=0,
            policy_version="v1",
            timestamp=timestamp,
        )
        
        assert "frame_hash" in hashes
        assert "decision_hash" in hashes
        assert "receipt_hash" in hashes
        
        # All should be valid SHA-256
        for key, value in hashes.items():
            assert len(value) == 64, f"{key} should be SHA-256"
            assert all(c in "0123456789abcdef" for c in value)

    def test_compute_all_hashes_deterministic(self):
        """compute_all_hashes is deterministic."""
        request_id = UUID("12345678-1234-5678-1234-567812345678")
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        
        frame = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.SPEND,
            timestamp=timestamp,
        )
        
        hashes1 = compute_all_hashes(
            frame=frame,
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            surface=ExecutionSurface.SPEND,
            risk_score=0.9,
            signal_count=1,
            policy_version="v1",
            timestamp=timestamp,
        )
        hashes2 = compute_all_hashes(
            frame=frame,
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            surface=ExecutionSurface.SPEND,
            risk_score=0.9,
            signal_count=1,
            policy_version="v1",
            timestamp=timestamp,
        )
        
        assert hashes1 == hashes2


class TestDeterminismEndToEnd:
    """End-to-end determinism tests."""

    def test_full_pipeline_deterministic(self):
        """
        Complete flow from frame to hashes is deterministic.
        
        This simulates the actual decision pipeline.
        """
        # Fixed inputs for reproducibility
        request_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        timestamp = datetime(2024, 6, 15, 10, 30, 0)
        
        # Create frame with signals
        frame = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.SPEND,
            timestamp=timestamp,
        )
        frame.add_signal(Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="jailbreak_detector",
            description="DAN jailbreak pattern detected",
        ))
        frame.add_signal(Signal(
            signal_type=SignalType.PROMPT_OVERRIDE,
            severity=SignalSeverity.HIGH,
            confidence=0.8,
            source="prompt_detector",
            description="Instruction override attempt",
        ))
        
        # Compute hashes
        all_hashes = compute_all_hashes(
            frame=frame,
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            surface=ExecutionSurface.SPEND,
            risk_score=frame.risk_score,
            signal_count=frame.signal_count,
            policy_version="v1.0.0",
            timestamp=timestamp,
        )
        
        # Verify hashes are stable (run multiple times)
        for _ in range(10):
            repeat_hashes = compute_all_hashes(
                frame=frame,
                decision=Decision.DENY,
                reason=DenyReason.FORBIDDEN_SIGNAL,
                surface=ExecutionSurface.SPEND,
                risk_score=frame.risk_score,
                signal_count=frame.signal_count,
                policy_version="v1.0.0",
                timestamp=timestamp,
            )
            assert repeat_hashes == all_hashes

    def test_any_change_changes_hash(self):
        """Any modification to the chain changes final hash."""
        request_id = uuid4()
        timestamp = datetime.utcnow()
        
        frame = SignalFrame(
            request_id=request_id,
            timestamp=timestamp,
        )
        frame.add_signal(Signal(
            signal_type=SignalType.ANOMALY,
            severity=SignalSeverity.LOW,
            confidence=0.5,
            source="test",
            description="test",
        ))
        
        base_hashes = compute_all_hashes(
            frame=frame,
            decision=Decision.PERMIT,
            reason=None,
            surface=ExecutionSurface.INFERENCE,
            risk_score=0.1,
            signal_count=1,
            policy_version="v1",
            timestamp=timestamp,
        )
        
        # Change decision
        modified_hashes = compute_all_hashes(
            frame=frame,
            decision=Decision.DENY,  # Changed
            reason=DenyReason.POLICY_DENIAL,
            surface=ExecutionSurface.INFERENCE,
            risk_score=0.1,
            signal_count=1,
            policy_version="v1",
            timestamp=timestamp,
        )
        
        # Decision hash and receipt hash should change
        assert base_hashes["decision_hash"] != modified_hashes["decision_hash"]
        assert base_hashes["receipt_hash"] != modified_hashes["receipt_hash"]
        # Frame hash should be the same (frame wasn't modified)
        assert base_hashes["frame_hash"] == modified_hashes["frame_hash"]
