"""
Tests for DecisionReplayEngine and ReceiptVerifier

Verifies:
- Same frame produces same decision (determinism)
- Replay matches stored receipt
- Mismatched policy version is detected
- Receipt hash integrity verification
- Chain verification for multiple receipts
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4

from trigguard.protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionSurface,
    Decision,
)
from trigguard.protocol.decision_receipt import create_receipt
from trigguard.engine.decision_engine import DecisionEngine
from trigguard.tools.receipt_verifier import (
    ReceiptVerifier,
    ReceiptVerificationStatus,
    VerificationLevel,
)
from trigguard.tools.decision_replay import (
    DecisionReplayEngine,
    ReplayStatus,
)


class TestReplayDeterminism:
    """Tests verifying decision determinism."""

    def test_same_frame_same_decision(self):
        """Same SignalFrame must produce identical decision."""
        # Create frame
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.RESOURCE_COST_HIGH,
                severity=SignalSeverity.HIGH,
                confidence=0.95,
                source="test",
                description="High cost operation",
            )
        )

        # First decision
        engine1 = DecisionEngine()
        result1 = engine1.evaluate(frame)

        # Second decision (same frame)
        engine2 = DecisionEngine()
        result2 = engine2.evaluate(frame)

        # Must be identical
        assert result1.decision == result2.decision
        assert result1.reason == result2.reason

    def test_replay_matches_original(self):
        """Replayed decision must match original receipt."""
        # Create frame and get decision
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.API,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.PERMISSION_CHECK_FAILED,
                severity=SignalSeverity.HIGH,
                confidence=0.99,
                source="test",
                description="Permission denied",
            )
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        # Replay
        replay_engine = DecisionReplayEngine()
        replay_result = replay_engine.replay_decision(frame, receipt)

        assert replay_result.status == ReplayStatus.MATCH
        assert replay_result.matches is True
        assert replay_result.original_decision == replay_result.replayed_decision

    def test_determinism_across_100_replays(self):
        """Decision must be deterministic across many replays."""
        # Create frame
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.SCOPE_EXPANSION_DETECTED,
                severity=SignalSeverity.MEDIUM,
                confidence=0.85,
                source="test",
                description="Scope expansion",
            )
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.RESOURCE_COST_HIGH,
                severity=SignalSeverity.HIGH,
                confidence=0.90,
                source="test",
                description="High cost",
            )
        )

        # Get baseline
        engine = DecisionEngine()
        baseline = engine.evaluate(frame)

        # Replay 100 times
        for i in range(100):
            new_engine = DecisionEngine()
            result = new_engine.evaluate(frame)

            assert (
                result.decision == baseline.decision
            ), f"Decision mismatch at replay {i}"
            assert result.reason == baseline.reason, f"Reason mismatch at replay {i}"


class TestReplayWithReceipt:
    """Tests for replay verification against stored receipts."""

    def test_verify_and_replay(self):
        """Full verification and replay flow."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.ESCALATION_CHAIN_BROKEN,
                severity=SignalSeverity.CRITICAL,
                confidence=0.99,
                source="test",
                description="Escalation chain broken",
            )
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        replay_engine = DecisionReplayEngine()
        verification, replay = replay_engine.verify_and_replay(receipt, frame)

        # Both should pass
        assert verification.is_valid
        assert replay.matches

    def test_batch_replay(self):
        """Batch replay multiple receipts."""
        frames_and_receipts = []

        # Create multiple frames and receipts
        for i in range(5):
            frame = SignalFrame(
                request_id=uuid4(),
                surface=ExecutionSurface.API,
                timestamp=datetime.now(timezone.utc),
            )
            frame.add_signal(
                Signal(
                    signal_type=SignalType.RESOURCE_COST_HIGH,
                    severity=SignalSeverity.MEDIUM,
                    confidence=0.7 + (i * 0.05),
                    source="test",
                    description=f"Test signal {i}",
                )
            )

            engine = DecisionEngine()
            result = engine.evaluate(frame)
            receipt = create_receipt(frame, result)

            frames_and_receipts.append((receipt, frame))

        # Batch replay
        replay_engine = DecisionReplayEngine()
        results = replay_engine.batch_replay(frames_and_receipts)

        # All should match
        assert len(results) == 5
        for result in results:
            assert result.matches


class TestPolicyVersionMismatch:
    """Tests for detecting policy version mismatches."""

    def test_detects_policy_version_mismatch(self):
        """Should detect when replay uses different policy version."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.RESOURCE_COST_HIGH,
                severity=SignalSeverity.HIGH,
                confidence=0.95,
                source="test",
                description="High cost",
            )
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        # Replay with different expected version
        replay_engine = DecisionReplayEngine()
        replay_result = replay_engine.replay_decision(
            frame,
            receipt,
            expected_policy_version="v99.0.0",  # Different version
        )

        assert replay_result.status == ReplayStatus.POLICY_MISMATCH
        assert "v99.0.0" in replay_result.differences[0]


class TestReceiptVerification:
    """Tests for receipt hash verification."""

    def test_valid_receipt_passes(self):
        """Valid receipt passes verification."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.API,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.RATE_LIMIT_EXCEEDED,
                severity=SignalSeverity.LOW,
                confidence=0.80,
                source="test",
                description="Rate limit",
            )
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        verifier = ReceiptVerifier()
        verification = verifier.verify(receipt, frame)

        assert verification.is_valid
        assert verification.status == ReceiptVerificationStatus.VALID

    def test_quick_verify(self):
        """Quick verification checks receipt hash integrity."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        verifier = ReceiptVerifier()
        quick_result = verifier.quick_verify(receipt)

        assert quick_result.is_valid
        assert "receipt_integrity" in quick_result.checks_performed


class TestChainVerification:
    """Tests for receipt chain verification."""

    def test_empty_chain(self):
        """Empty chain should be marked as valid but flagged."""
        verifier = ReceiptVerifier()
        result = verifier.verify_chain([])

        # Empty chain is technically valid but suspicious
        assert result.status == ReceiptVerificationStatus.VALID
        assert "0 receipts verified" in result.message

    def test_single_receipt_chain(self):
        """Single receipt chain should verify."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        verifier = ReceiptVerifier()
        chain_result = verifier.verify_chain([receipt])

        assert chain_result.is_valid

    def test_multi_receipt_chain(self):
        """Multiple receipts should form valid chain."""
        receipts = []

        for i in range(3):
            frame = SignalFrame(
                request_id=uuid4(),
                surface=ExecutionSurface.API,
                timestamp=datetime.now(timezone.utc),
            )

            engine = DecisionEngine()
            result = engine.evaluate(frame)
            receipt = create_receipt(frame, result)
            receipts.append(receipt)

        verifier = ReceiptVerifier()
        chain_result = verifier.verify_chain(receipts)

        assert chain_result.is_valid
        assert chain_result.level == VerificationLevel.CHAIN


class TestForbiddenSignalReplay:
    """Tests for replaying forbidden signal decisions."""

    def test_forbidden_signal_replay_matches(self):
        """Forbidden signal decision should replay identically."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.CREDENTIAL_EXFILTRATION,  # Forbidden
                severity=SignalSeverity.CRITICAL,
                confidence=0.99,
                source="test",
                description="Credential theft attempt",
            )
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)

        # Must be denied
        assert result.decision == Decision.DENY

        receipt = create_receipt(frame, result)

        # Replay should match
        replay_engine = DecisionReplayEngine()
        replay = replay_engine.replay_decision(frame, receipt)

        assert replay.status == ReplayStatus.MATCH
        assert replay.replayed_decision == Decision.DENY


class TestSilenceGapReplay:
    """Tests for replaying silence gap decisions."""

    def test_silence_gap_replay_matches(self):
        """Silence gap decision should replay identically."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.API,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.MONITORING_DISABLED,  # Silence trigger
                severity=SignalSeverity.CRITICAL,
                confidence=0.95,
                source="test",
                description="Monitoring disabled",
            )
        )

        engine = DecisionEngine()
        result = engine.evaluate(frame)

        # Must be denied (silence gap)
        assert result.decision == Decision.DENY

        receipt = create_receipt(frame, result)

        # Replay should match
        replay_engine = DecisionReplayEngine()
        replay = replay_engine.replay_decision(frame, receipt)

        assert replay.status == ReplayStatus.MATCH
        assert replay.replayed_decision == Decision.DENY


class TestEdgeCases:
    """Edge case tests for replay system."""

    def test_empty_frame_replay(self):
        """Empty frame should replay deterministically."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        # No signals

        engine = DecisionEngine()
        result = engine.evaluate(frame)
        receipt = create_receipt(frame, result)

        replay_engine = DecisionReplayEngine()
        replay = replay_engine.replay_decision(frame, receipt)

        assert replay.status == ReplayStatus.MATCH

    def test_replay_without_original_receipt(self):
        """Replay without receipt just returns decision."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.CLI,
            timestamp=datetime.now(timezone.utc),
        )
        frame.add_signal(
            Signal(
                signal_type=SignalType.RESOURCE_COST_HIGH,
                severity=SignalSeverity.HIGH,
                confidence=0.95,
                source="test",
                description="High cost",
            )
        )

        replay_engine = DecisionReplayEngine()
        replay = replay_engine.replay_decision(frame, original_receipt=None)

        # Should still return a result (no comparison)
        assert replay.replayed_decision is not None
        assert replay.status == ReplayStatus.MATCH  # No comparison = match by default
