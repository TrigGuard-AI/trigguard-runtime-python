"""
DecisionReceipt Tests

Tests for receipt generation, integrity verification, and tampering detection.
"""

import pytest
from datetime import datetime
from uuid import uuid4

from protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionSurface,
    Decision,
    DenyReason,
    DecisionReceipt,
)
from protocol.decision_receipt import (
    generate_receipt,
    verify_receipt,
    receipt_from_dict,
)


class TestGenerateReceipt:
    """Tests for receipt generation."""

    def test_generate_receipt_returns_receipt(self):
        """generate_receipt returns a DecisionReceipt."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        assert isinstance(receipt, DecisionReceipt)

    def test_generate_receipt_has_valid_hashes(self):
        """Generated receipt has all hashes populated."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        assert receipt.has_valid_hashes
        assert len(receipt.frame_hash) == 64
        assert len(receipt.decision_hash) == 64
        assert len(receipt.receipt_hash) == 64

    def test_generate_receipt_is_frozen(self):
        """Generated receipt is frozen to prevent modification."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        assert receipt.is_frozen

    def test_generate_receipt_copies_frame_data(self):
        """Receipt captures frame data correctly."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
        )
        frame.add_signal(Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.95,
            source="test",
            description="test",
        ))
        
        receipt = generate_receipt(
            frame,
            Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
        )
        
        assert receipt.request_id == frame.request_id
        assert receipt.surface == ExecutionSurface.SPEND
        assert receipt.risk_score == frame.risk_score
        assert receipt.signal_count == frame.signal_count
        assert receipt.decision == Decision.DENY
        assert receipt.reason == DenyReason.FORBIDDEN_SIGNAL

    def test_generate_receipt_deterministic(self):
        """Same inputs produce same hashes."""
        request_id = uuid4()
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        
        frame1 = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.INFERENCE,
            timestamp=timestamp,
        )
        frame2 = SignalFrame(
            request_id=request_id,
            surface=ExecutionSurface.INFERENCE,
            timestamp=timestamp,
        )
        
        receipt1 = generate_receipt(frame1, Decision.PERMIT)
        receipt2 = generate_receipt(frame2, Decision.PERMIT)
        
        # Frame hashes should match (same frame)
        assert receipt1.frame_hash == receipt2.frame_hash

    def test_generate_receipt_includes_signals_summary(self):
        """Receipt includes signals summary."""
        frame = SignalFrame(request_id=uuid4())
        frame.add_signal(Signal(
            signal_type=SignalType.PROMPT_OVERRIDE,
            severity=SignalSeverity.HIGH,
            confidence=0.8,
            source="test",
            description="test",
        ))
        
        receipt = generate_receipt(frame, Decision.DENY, reason=DenyReason.FORBIDDEN_SIGNAL)
        
        assert len(receipt.signals_summary) > 0
        assert "prompt_override:high" in receipt.signals_summary


class TestVerifyReceipt:
    """Tests for receipt verification."""

    def test_valid_receipt_verifies(self):
        """Correctly generated receipt passes verification."""
        frame = SignalFrame(request_id=uuid4())
        frame.add_signal(Signal(
            signal_type=SignalType.ANOMALY,
            severity=SignalSeverity.LOW,
            confidence=0.3,
            source="test",
            description="test",
        ))
        
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        is_valid, errors = verify_receipt(receipt, frame)
        
        assert is_valid
        assert len(errors) == 0

    def test_tampered_frame_hash_detected(self):
        """Tampering with frame_hash is detected."""
        frame = SignalFrame(request_id=uuid4())
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        # Tamper with frame hash
        # Need to unfreeze first (simulate storage/retrieval)
        tampered = DecisionReceipt(
            receipt_id=receipt.receipt_id,
            request_id=receipt.request_id,
            decision=receipt.decision,
            surface=receipt.surface,
            risk_score=receipt.risk_score,
            signal_count=receipt.signal_count,
            frame_hash="tampered_hash_value_0000000000000000000000000000",
            decision_hash=receipt.decision_hash,
            receipt_hash=receipt.receipt_hash,
            evaluated_at=receipt.evaluated_at,
            policy_version=receipt.policy_version,
        )
        
        is_valid, errors = verify_receipt(tampered, frame)
        
        assert not is_valid
        assert any("hash" in e.lower() for e in errors)

    def test_tampered_decision_hash_detected(self):
        """Tampering with decision_hash is detected."""
        frame = SignalFrame(request_id=uuid4())
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        tampered = DecisionReceipt(
            receipt_id=receipt.receipt_id,
            request_id=receipt.request_id,
            decision=receipt.decision,
            surface=receipt.surface,
            risk_score=receipt.risk_score,
            signal_count=receipt.signal_count,
            frame_hash=receipt.frame_hash,
            decision_hash="tampered_decision_hash_00000000000000000000000000",
            receipt_hash=receipt.receipt_hash,
            evaluated_at=receipt.evaluated_at,
            policy_version=receipt.policy_version,
        )
        
        is_valid, errors = verify_receipt(tampered, frame)
        
        assert not is_valid

    def test_tampered_receipt_hash_detected(self):
        """Tampering with receipt_hash is detected."""
        frame = SignalFrame(request_id=uuid4())
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        tampered = DecisionReceipt(
            receipt_id=receipt.receipt_id,
            request_id=receipt.request_id,
            decision=receipt.decision,
            surface=receipt.surface,
            risk_score=receipt.risk_score,
            signal_count=receipt.signal_count,
            frame_hash=receipt.frame_hash,
            decision_hash=receipt.decision_hash,
            receipt_hash="tampered_receipt_hash_00000000000000000000000000",
            evaluated_at=receipt.evaluated_at,
            policy_version=receipt.policy_version,
        )
        
        is_valid, errors = verify_receipt(tampered, frame)
        
        assert not is_valid


class TestReceiptChain:
    """Tests for hash chain integrity."""

    def test_decision_linked_to_frame_hash(self):
        """Receipt hash depends on frame hash."""
        frame1 = SignalFrame(request_id=uuid4())
        frame2 = SignalFrame(request_id=uuid4())  # Different request
        
        receipt1 = generate_receipt(frame1, Decision.PERMIT)
        receipt2 = generate_receipt(frame2, Decision.PERMIT)
        
        # Different frames = different frame hashes
        assert receipt1.frame_hash != receipt2.frame_hash
        # Different frame hashes = different receipt hashes
        assert receipt1.receipt_hash != receipt2.receipt_hash

    def test_receipt_hash_changes_with_decision(self):
        """Receipt hash changes when decision changes."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt_permit = generate_receipt(frame, Decision.PERMIT)
        receipt_deny = generate_receipt(
            frame, Decision.DENY, reason=DenyReason.POLICY_DENIAL
        )
        
        # Same frame = same frame hash
        assert receipt_permit.frame_hash == receipt_deny.frame_hash
        # Different decision = different decision hash
        assert receipt_permit.decision_hash != receipt_deny.decision_hash
        # Different decision hash = different receipt hash
        assert receipt_permit.receipt_hash != receipt_deny.receipt_hash

    def test_receipt_hash_changes_with_policy_version(self):
        """Receipt hash changes when policy version changes."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt_v1 = generate_receipt(frame, Decision.PERMIT, policy_version="v1")
        receipt_v2 = generate_receipt(frame, Decision.PERMIT, policy_version="v2")
        
        # Different policy version = different receipt hash
        assert receipt_v1.receipt_hash != receipt_v2.receipt_hash


class TestReceiptSerialization:
    """Tests for receipt serialization and deserialization."""

    def test_to_canonical_dict_complete(self):
        """to_canonical_dict includes all required fields."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
        )
        frame.add_signal(Signal(
            signal_type=SignalType.JAILBREAK_ATTEMPT,
            severity=SignalSeverity.CRITICAL,
            confidence=0.9,
            source="test",
            description="test",
        ))
        
        receipt = generate_receipt(
            frame,
            Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
        )
        
        data = receipt.to_canonical_dict()
        
        assert "receipt_id" in data
        assert "request_id" in data
        assert "decision" in data
        assert "reason" in data
        assert "surface" in data
        assert "frame_hash" in data
        assert "decision_hash" in data
        assert "receipt_hash" in data
        assert "policy_version" in data
        assert "evaluated_at" in data

    def test_to_audit_dict_complete(self):
        """to_audit_dict includes audit-relevant fields."""
        frame = SignalFrame(request_id=uuid4())
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        audit = receipt.to_audit_dict()
        
        assert "receipt_id" in audit
        assert "decision" in audit
        assert "frame_hash" in audit
        assert "policy_version" in audit

    def test_receipt_from_dict_roundtrip(self):
        """Receipt can be serialized and deserialized."""
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.INFERENCE,
        )
        original = generate_receipt(frame, Decision.PERMIT)
        
        # Serialize
        data = original.to_canonical_dict()
        
        # Deserialize
        restored = receipt_from_dict(data)
        
        # Core fields should match
        assert str(restored.receipt_id) == str(original.receipt_id)
        assert str(restored.request_id) == str(original.request_id)
        assert restored.decision == original.decision
        assert restored.surface == original.surface
        assert restored.frame_hash == original.frame_hash
        assert restored.decision_hash == original.decision_hash
        assert restored.receipt_hash == original.receipt_hash
        assert restored.policy_version == original.policy_version


class TestReceiptDenyReason:
    """Tests for DENY reason handling."""

    def test_deny_requires_reason(self):
        """DENY decision must have a reason."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt = generate_receipt(
            frame,
            Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
        )
        
        assert receipt.reason == DenyReason.FORBIDDEN_SIGNAL

    def test_deny_without_reason_defaults_to_fail_closed(self):
        """DENY without explicit reason defaults to FAIL_CLOSED."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt = generate_receipt(frame, Decision.DENY)
        
        assert receipt.reason == DenyReason.FAIL_CLOSED

    def test_permit_has_no_reason(self):
        """PERMIT decision has no reason."""
        frame = SignalFrame(request_id=uuid4())
        
        receipt = generate_receipt(frame, Decision.PERMIT)
        
        assert receipt.reason is None


class TestReceiptIntegrity:
    """End-to-end integrity tests."""

    def test_complete_flow_maintains_integrity(self):
        """
        Full flow: create frame → generate receipt → verify.
        
        This simulates the production authorization flow.
        """
        # 1. Create frame with signals
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
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
            description="Instruction override detected",
        ))
        
        # 2. Generate receipt (simulates DecisionEngine output)
        receipt = generate_receipt(
            frame=frame,
            decision=Decision.DENY,
            reason=DenyReason.FORBIDDEN_SIGNAL,
            policy_version="v1.0.0",
            constraint_violations=2,
            violations_summary=[
                "forbidden_signals_irreversible:critical",
                "critical_signal_block:critical",
            ],
            evaluation_time_ms=1.5,
        )
        
        # 3. Verify integrity
        is_valid, errors = verify_receipt(receipt, frame)
        
        assert is_valid, f"Integrity check failed: {errors}"
        assert receipt.has_valid_hashes
        assert receipt.is_frozen

    def test_receipt_survives_storage_roundtrip(self):
        """Receipt can be stored, retrieved, and verified."""
        import json
        
        # Create and generate
        frame = SignalFrame(
            request_id=uuid4(),
            surface=ExecutionSurface.EXTERNAL_API,
        )
        original_receipt = generate_receipt(frame, Decision.PERMIT)
        
        # Store (as JSON)
        stored = json.dumps(original_receipt.to_canonical_dict())
        
        # Retrieve
        data = json.loads(stored)
        restored_receipt = receipt_from_dict(data)
        
        # Verify restored receipt against original frame
        # Note: We need the original frame for verification
        # In production, frames would also need to be stored
        is_valid, errors = verify_receipt(restored_receipt, frame)
        
        assert is_valid, f"Verification after storage failed: {errors}"
