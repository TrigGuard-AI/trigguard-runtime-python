"""
Policy Versioning Tests

Tests for policy version tracking and integrity.
"""

import pytest
from uuid import uuid4

from trigguard.policy.policy_registry import (
    POLICY_VERSION,
    IRREVERSIBLE_FORBIDDEN,
    SILENCE_TRIGGERS,
    CRITICAL_SIGNALS,
    THRESHOLDS,
    PolicyRegistry,
    get_policy_registry,
    get_policy_version,
    TierThresholds,
)
from trigguard.signals.signal_types import SignalType as PolicySignalType
from trigguard.protocol.decision_contracts import (
    Signal,
    SignalFrame,
    SignalType,
    SignalSeverity,
    ExecutionRequest,
    ExecutionSurface,
    Decision,
)
from trigguard.authority.decision_engine import DecisionEngine


class TestPolicyVersion:
    """Tests for policy version tracking."""

    def test_policy_version_format(self):
        """Policy version follows semver format."""
        version = get_policy_version()

        # Should be like "v1.0.0"
        assert version.startswith("v")
        parts = version[1:].split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_registry_has_version(self):
        """PolicyRegistry exposes version."""
        registry = get_policy_registry()

        assert registry.version == POLICY_VERSION

    def test_version_immutable(self):
        """Policy version cannot be changed at runtime."""
        registry = get_policy_registry()
        original = registry.version

        # Should not be able to modify
        with pytest.raises(AttributeError):
            registry.version = "v2.0.0"

        assert registry.version == original


class TestPolicyRegistry:
    """Tests for PolicyRegistry interface."""

    def test_registry_singleton(self):
        """get_policy_registry returns same instance."""
        reg1 = get_policy_registry()
        reg2 = get_policy_registry()

        assert reg1 is reg2

    def test_registry_exposes_irreversible_forbidden(self):
        """Registry provides IRREVERSIBLE_FORBIDDEN signals."""
        registry = get_policy_registry()

        assert registry.irreversible_forbidden == IRREVERSIBLE_FORBIDDEN
        assert SignalType.JAILBREAK_ATTEMPT in registry.irreversible_forbidden

    def test_registry_exposes_silence_triggers(self):
        """Registry provides SILENCE_TRIGGERS signals."""
        registry = get_policy_registry()

        assert registry.silence_triggers == SILENCE_TRIGGERS
        assert SignalType.MODEL_ENUMERATION in registry.silence_triggers

    def test_registry_exposes_critical_signals(self):
        """Registry provides CRITICAL_SIGNALS."""
        registry = get_policy_registry()

        assert registry.critical_signals == CRITICAL_SIGNALS

    def test_registry_get_thresholds(self):
        """Registry provides tier thresholds."""
        registry = get_policy_registry()

        tier1 = registry.get_thresholds(1)
        assert isinstance(tier1, TierThresholds)
        assert tier1.deny_threshold < 0.5  # Tier 1 should be strict

    def test_registry_helper_methods(self):
        """Registry helper methods work correctly."""
        registry = get_policy_registry()

        assert registry.is_forbidden_on_irreversible(SignalType.JAILBREAK_ATTEMPT)
        assert not registry.is_forbidden_on_irreversible(SignalType.ANOMALY)

        assert registry.triggers_silence(SignalType.MODEL_ENUMERATION)
        assert not registry.triggers_silence(SignalType.JAILBREAK_ATTEMPT)

        assert registry.is_critical(SignalType.JAILBREAK_ATTEMPT)
        assert not registry.is_critical(SignalType.ANOMALY)

    def test_registry_to_dict(self):
        """Registry can export as dictionary."""
        registry = get_policy_registry()
        data = registry.to_dict()

        assert "version" in data
        assert "irreversible_forbidden" in data
        assert "silence_triggers" in data
        assert "critical_signals" in data
        assert "thresholds" in data


class TestPolicyThresholds:
    """Tests for policy thresholds."""

    def test_tier_1_is_strictest(self):
        """Tier 1 (irreversible) has strictest thresholds."""
        tier1 = THRESHOLDS[1]
        tier2 = THRESHOLDS[2]
        tier3 = THRESHOLDS[3]

        assert tier1.deny_threshold < tier2.deny_threshold
        assert tier2.deny_threshold < tier3.deny_threshold

    def test_thresholds_frozen(self):
        """Thresholds are immutable."""
        tier1 = THRESHOLDS[1]

        with pytest.raises(AttributeError):
            tier1.deny_threshold = 0.99

    def test_all_tiers_have_thresholds(self):
        """All three tiers have thresholds defined."""
        assert 1 in THRESHOLDS
        assert 2 in THRESHOLDS
        assert 3 in THRESHOLDS


class TestPolicySignalSets:
    """Tests for policy signal sets."""

    def test_irreversible_forbidden_not_empty(self):
        """IRREVERSIBLE_FORBIDDEN has signals."""
        assert len(IRREVERSIBLE_FORBIDDEN) >= 5

    def test_silence_triggers_not_empty(self):
        """SILENCE_TRIGGERS has signals."""
        assert len(SILENCE_TRIGGERS) >= 3

    def test_critical_signals_not_empty(self):
        """CRITICAL_SIGNALS has signals."""
        assert len(CRITICAL_SIGNALS) >= 3

    def test_sets_are_frozenset(self):
        """Policy signal sets are immutable frozensets."""
        assert isinstance(IRREVERSIBLE_FORBIDDEN, frozenset)
        assert isinstance(SILENCE_TRIGGERS, frozenset)
        assert isinstance(CRITICAL_SIGNALS, frozenset)

    def test_sets_contain_valid_signals(self):
        """All entries are valid SignalTypes."""
        for signal in IRREVERSIBLE_FORBIDDEN:
            assert isinstance(signal, PolicySignalType)
        for signal in SILENCE_TRIGGERS:
            assert isinstance(signal, PolicySignalType)
        for signal in CRITICAL_SIGNALS:
            assert isinstance(signal, PolicySignalType)


class TestDecisionEngineUsesPolicy:
    """Tests that DecisionEngine loads policy from registry."""

    def test_engine_has_policy_version(self):
        """DecisionEngine exposes policy version."""
        engine = DecisionEngine()

        assert engine.policy_version == POLICY_VERSION

    def test_engine_uses_registry(self):
        """DecisionEngine uses PolicyRegistry."""
        engine = DecisionEngine()

        assert engine.policy is not None
        assert engine.policy.version == POLICY_VERSION

    def test_receipt_includes_policy_version(self):
        """DecisionReceipt includes policy version."""
        engine = DecisionEngine()

        request = ExecutionRequest(
            request_id=uuid4(),
            action="test_action",
            surface=ExecutionSurface.INFERENCE,
        )

        frame = SignalFrame(
            request_id=request.request_id,
            surface=ExecutionSurface.INFERENCE,
        )

        receipt = engine.authorize(request, signal_frame=frame)

        assert receipt.policy_version == POLICY_VERSION

    def test_silence_uses_policy_triggers(self):
        """Engine uses SILENCE_TRIGGERS from trigguard.policy."""
        engine = DecisionEngine()

        request = ExecutionRequest(
            request_id=uuid4(),
            action="test_action",
            surface=ExecutionSurface.INFERENCE,
        )

        frame = SignalFrame(
            request_id=request.request_id,
            surface=ExecutionSurface.INFERENCE,
        )
        # Add a silence trigger signal
        frame.add_signal(
            Signal(
                signal_type=SignalType.MODEL_ENUMERATION,
                severity=SignalSeverity.MEDIUM,
                confidence=0.9,
                source="test",
                description="Model enumeration detected",
            )
        )

        receipt = engine.authorize(request, signal_frame=frame)

        # Should trigger SILENCE
        assert receipt.decision == Decision.SILENCE


class TestPolicyVersionInReceipts:
    """Tests for policy version embedding in receipts."""

    def test_different_decisions_same_policy_version(self):
        """All decisions use same policy version."""
        engine = DecisionEngine()

        # PERMIT case
        request1 = ExecutionRequest(
            request_id=uuid4(),
            surface=ExecutionSurface.INFERENCE,
        )
        frame1 = SignalFrame(request_id=request1.request_id)
        receipt1 = engine.authorize(request1, signal_frame=frame1)

        # DENY case (with critical signal)
        request2 = ExecutionRequest(
            request_id=uuid4(),
            surface=ExecutionSurface.SPEND,
        )
        frame2 = SignalFrame(
            request_id=request2.request_id,
            surface=ExecutionSurface.SPEND,
        )
        frame2.add_signal(
            Signal(
                signal_type=SignalType.JAILBREAK_ATTEMPT,
                severity=SignalSeverity.CRITICAL,
                confidence=0.95,
                source="test",
                description="Jailbreak detected",
            )
        )
        receipt2 = engine.authorize(request2, signal_frame=frame2)

        # Both should have same policy version
        assert receipt1.policy_version == receipt2.policy_version
        assert receipt1.policy_version == POLICY_VERSION
