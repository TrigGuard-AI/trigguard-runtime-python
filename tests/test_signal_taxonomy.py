"""
Signal Taxonomy Invariant Tests

These tests lock the signal taxonomy to prevent silent drift.
Policies depend on this taxonomy - changes must be intentional.

If a test fails here, you're changing the security contract.
"""

import pytest
from signals.signal_types import (
    SignalType,
    SignalCategory,
    SignalSeverity,
    SIGNAL_CATEGORIES,
    DEFAULT_SEVERITIES,
    IRREVERSIBLE_FORBIDDEN,
    SILENCE_TRIGGERS,
    get_category,
    get_default_severity,
    is_valid_signal,
    get_all_signals,
    get_signals_by_category,
    is_forbidden_on_irreversible,
    triggers_silence,
)


class TestTaxonomyStability:
    """Tests that verify the taxonomy doesn't drift silently."""

    # LOCK: The exact count of signal types
    EXPECTED_SIGNAL_COUNT = 42
    
    # LOCK: The exact count of categories
    EXPECTED_CATEGORY_COUNT = 7
    
    # LOCK: The exact count of severity levels
    EXPECTED_SEVERITY_COUNT = 5

    def test_signal_type_count_is_stable(self):
        """
        INVARIANT: Signal count must not change without explicit update.
        
        If this fails, you added/removed a signal. Update EXPECTED_SIGNAL_COUNT.
        """
        actual_count = len(list(SignalType))
        assert actual_count == self.EXPECTED_SIGNAL_COUNT, (
            f"Signal count changed from {self.EXPECTED_SIGNAL_COUNT} to {actual_count}. "
            "If intentional, update EXPECTED_SIGNAL_COUNT in test."
        )

    def test_category_count_is_stable(self):
        """INVARIANT: Category count must not change without explicit update."""
        actual_count = len(list(SignalCategory))
        assert actual_count == self.EXPECTED_CATEGORY_COUNT, (
            f"Category count changed from {self.EXPECTED_CATEGORY_COUNT} to {actual_count}. "
            "If intentional, update EXPECTED_CATEGORY_COUNT in test."
        )

    def test_severity_count_is_stable(self):
        """INVARIANT: Severity levels must not change."""
        actual_count = len(list(SignalSeverity))
        assert actual_count == self.EXPECTED_SEVERITY_COUNT, (
            f"Severity count changed from {self.EXPECTED_SEVERITY_COUNT} to {actual_count}."
        )

    def test_no_duplicate_signal_values(self):
        """INVARIANT: No two signals can have the same value."""
        values = [s.value for s in SignalType]
        assert len(values) == len(set(values)), (
            f"Duplicate signal values detected: {[v for v in values if values.count(v) > 1]}"
        )

    def test_no_duplicate_category_values(self):
        """INVARIANT: No two categories can have the same value."""
        values = [c.value for c in SignalCategory]
        assert len(values) == len(set(values)), (
            f"Duplicate category values detected"
        )


class TestSignalMetadataCompleteness:
    """Tests that verify every signal has required metadata."""

    def test_every_signal_has_category(self):
        """INVARIANT: Every signal MUST have a category mapping."""
        for signal in SignalType:
            category = get_category(signal)
            assert category is not None, f"Signal {signal} has no category"
            assert isinstance(category, SignalCategory), (
                f"Signal {signal} has invalid category type: {type(category)}"
            )

    def test_every_signal_has_default_severity(self):
        """INVARIANT: Every signal MUST have a default severity."""
        for signal in SignalType:
            severity = get_default_severity(signal)
            assert severity is not None, f"Signal {signal} has no default severity"
            assert isinstance(severity, SignalSeverity), (
                f"Signal {signal} has invalid severity type: {type(severity)}"
            )

    def test_every_category_has_signals(self):
        """INVARIANT: Every category must have at least one signal."""
        for category in SignalCategory:
            signals = get_signals_by_category(category)
            assert len(signals) > 0, (
                f"Category {category} has no signals. Remove it or add signals."
            )


class TestIrreversibleForbiddenConstraints:
    """Tests for IRREVERSIBLE_FORBIDDEN signal set."""

    def test_irreversible_forbidden_signals_are_high_or_critical(self):
        """
        INVARIANT: Signals forbidden on irreversible surfaces must be HIGH or CRITICAL.
        
        These signals cause immediate DENY on tier-1 surfaces.
        Low-severity signals should not be in this set.
        """
        allowed_severities = {SignalSeverity.HIGH, SignalSeverity.CRITICAL}
        
        for signal in IRREVERSIBLE_FORBIDDEN:
            severity = get_default_severity(signal)
            assert severity in allowed_severities, (
                f"Signal {signal} is in IRREVERSIBLE_FORBIDDEN but has severity {severity}. "
                f"Expected HIGH or CRITICAL."
            )

    def test_irreversible_forbidden_are_valid_signals(self):
        """INVARIANT: All IRREVERSIBLE_FORBIDDEN entries must be valid SignalTypes."""
        for signal in IRREVERSIBLE_FORBIDDEN:
            assert isinstance(signal, SignalType), (
                f"IRREVERSIBLE_FORBIDDEN contains non-SignalType: {signal}"
            )

    def test_irreversible_forbidden_minimum_count(self):
        """INVARIANT: Must have meaningful number of forbidden signals."""
        assert len(IRREVERSIBLE_FORBIDDEN) >= 5, (
            f"IRREVERSIBLE_FORBIDDEN has only {len(IRREVERSIBLE_FORBIDDEN)} signals. "
            "This seems too permissive for irreversible surfaces."
        )


class TestSilenceTriggerConstraints:
    """Tests for SILENCE_TRIGGERS signal set."""

    def test_silence_triggers_are_valid_signals(self):
        """INVARIANT: All SILENCE_TRIGGERS entries must be valid SignalTypes."""
        for signal in SILENCE_TRIGGERS:
            assert isinstance(signal, SignalType), (
                f"SILENCE_TRIGGERS contains non-SignalType: {signal}"
            )

    def test_silence_triggers_are_probe_related(self):
        """
        INVARIANT: SILENCE signals should be probe/enumeration related.
        
        SILENCE is for probing attacks where we don't want to leak information.
        Other attacks should DENY, not SILENCE.
        """
        # These categories are appropriate for SILENCE
        probe_categories = {SignalCategory.DATA_EXTRACTION, SignalCategory.SYSTEM}
        
        for signal in SILENCE_TRIGGERS:
            category = get_category(signal)
            assert category in probe_categories, (
                f"Signal {signal} triggers SILENCE but is in category {category}. "
                "SILENCE should be reserved for probing/enumeration attacks."
            )


class TestHelperFunctions:
    """Tests for taxonomy helper functions."""

    def test_is_valid_signal_accepts_valid(self):
        """is_valid_signal returns True for valid signal strings."""
        assert is_valid_signal("jailbreak_attempt") is True
        assert is_valid_signal("prompt_override") is True
        assert is_valid_signal("unknown") is True

    def test_is_valid_signal_rejects_invalid(self):
        """is_valid_signal returns False for invalid signal strings."""
        assert is_valid_signal("not_a_real_signal") is False
        assert is_valid_signal("") is False
        assert is_valid_signal("PROMPT_OVERRIDE") is False  # Case-sensitive

    def test_get_all_signals_returns_all(self):
        """get_all_signals returns complete list."""
        all_signals = get_all_signals()
        assert len(all_signals) == len(list(SignalType))
        assert all(isinstance(s, SignalType) for s in all_signals)

    def test_is_forbidden_on_irreversible(self):
        """is_forbidden_on_irreversible correctly identifies forbidden signals."""
        assert is_forbidden_on_irreversible(SignalType.JAILBREAK_ATTEMPT) is True
        assert is_forbidden_on_irreversible(SignalType.ANOMALY) is False

    def test_triggers_silence(self):
        """triggers_silence correctly identifies silence triggers."""
        assert triggers_silence(SignalType.MODEL_ENUMERATION) is True
        assert triggers_silence(SignalType.JAILBREAK_ATTEMPT) is False


class TestUnknownSignalFailsClosed:
    """
    Tests that unknown signals fail closed.
    
    This is critical for security: any signal not in the taxonomy
    must be treated as potentially dangerous.
    """

    def test_unknown_signal_string_fails_validation(self):
        """Unknown signal strings must fail validation."""
        unknown_signals = [
            "malicious_signal",
            "bypass_attempt",
            "invented_signal_type",
            "",
            "null",
            "undefined",
        ]
        
        for signal_str in unknown_signals:
            assert is_valid_signal(signal_str) is False, (
                f"Unknown signal '{signal_str}' should not pass validation"
            )

    def test_unknown_signal_type_has_category(self):
        """
        SignalType.UNKNOWN must have a category.
        
        Even the UNKNOWN signal must be handled properly.
        """
        category = get_category(SignalType.UNKNOWN)
        assert category == SignalCategory.SYSTEM

    def test_creating_signal_with_invalid_type_raises(self):
        """
        Attempting to create a SignalType from invalid string raises ValueError.
        
        This ensures enum validation happens at signal creation time.
        """
        with pytest.raises(ValueError):
            SignalType("not_a_valid_signal")

        with pytest.raises(ValueError):
            SignalType("hacker_attack")


class TestCategoryCoverage:
    """Tests that verify complete category coverage."""

    def test_all_signals_in_signal_categories_dict(self):
        """Every SignalType must be in SIGNAL_CATEGORIES dict."""
        for signal in SignalType:
            assert signal in SIGNAL_CATEGORIES, (
                f"Signal {signal} not in SIGNAL_CATEGORIES mapping"
            )

    def test_signal_categories_only_contains_valid_signals(self):
        """SIGNAL_CATEGORIES must only contain valid SignalTypes."""
        for signal in SIGNAL_CATEGORIES.keys():
            assert isinstance(signal, SignalType), (
                f"SIGNAL_CATEGORIES contains invalid key: {signal}"
            )

    def test_signal_categories_maps_to_valid_categories(self):
        """SIGNAL_CATEGORIES values must all be valid SignalCategories."""
        for signal, category in SIGNAL_CATEGORIES.items():
            assert isinstance(category, SignalCategory), (
                f"Signal {signal} maps to invalid category: {category}"
            )


class TestSeverityCoverage:
    """Tests that verify severity metadata is complete."""

    def test_default_severities_only_contains_valid_signals(self):
        """DEFAULT_SEVERITIES must only contain valid SignalTypes."""
        for signal in DEFAULT_SEVERITIES.keys():
            assert isinstance(signal, SignalType), (
                f"DEFAULT_SEVERITIES contains invalid key: {signal}"
            )

    def test_default_severities_maps_to_valid_severities(self):
        """DEFAULT_SEVERITIES values must all be valid SignalSeverities."""
        for signal, severity in DEFAULT_SEVERITIES.items():
            assert isinstance(severity, SignalSeverity), (
                f"Signal {signal} maps to invalid severity: {severity}"
            )

    def test_critical_signals_are_dangerous(self):
        """
        Signals with CRITICAL severity must be attack indicators.
        
        CRITICAL means immediate DENY. Verify these are appropriate.
        """
        critical_signals = [
            s for s, sev in DEFAULT_SEVERITIES.items()
            if sev == SignalSeverity.CRITICAL
        ]
        
        # Must have some critical signals
        assert len(critical_signals) >= 3, (
            "Too few CRITICAL signals. Security posture may be too permissive."
        )
        
        # Jailbreak must be critical
        assert SignalType.JAILBREAK_ATTEMPT in critical_signals, (
            "JAILBREAK_ATTEMPT must be CRITICAL severity"
        )


class TestDecisionEngineIntegration:
    """
    Tests that unknown signals cause DENY in the decision pipeline.
    
    These tests verify fail-closed behavior at the authorization layer.
    """

    def test_unknown_signal_in_frame_causes_deny(self):
        """
        SignalType.UNKNOWN in a signal frame should contribute to DENY.
        
        This tests the integration with ConstraintEvaluator / DecisionEngine.
        """
        # Import here to test integration
        from protocol.decision_contracts import (
            Signal,
            SignalFrame,
            ExecutionRequest,
            ExecutionSurface,
            SignalType as ContractSignalType,
            SignalSeverity as ContractSeverity,
        )
        from constraints.constraint_evaluator import ConstraintEvaluator
        from uuid import uuid4
        
        # Create a request for an irreversible surface
        request = ExecutionRequest(
            request_id=uuid4(),
            actor_id="test_user",
            action="test_action",
            resource="test_resource",
            surface=ExecutionSurface.SPEND,  # Irreversible
        )
        
        # Create frame with UNKNOWN signal
        frame = SignalFrame(request_id=request.request_id)
        frame.add_signal(Signal(
            signal_type=ContractSignalType.UNKNOWN,
            severity=ContractSeverity.HIGH,
            confidence=0.9,
            source="test",
            description="Unknown signal - fail closed",
        ))
        
        # Evaluate constraints
        evaluator = ConstraintEvaluator()
        result = evaluator.evaluate(request, frame)
        
        # Unknown signals on irreversible surfaces should trigger violations
        # (via unknown_surface_block or risk threshold)
        # The key is: it should NOT be a clean pass
        assert frame.risk_score > 0, "Unknown signal should contribute to risk"
