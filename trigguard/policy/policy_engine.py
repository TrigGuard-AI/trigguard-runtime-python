"""
Policy Engine

Evaluates detection results and aggregated risk against security policies.
Determines the final decision (ALLOW, BLOCK, FLAG, REDACT).
"""

from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from trigguard.protocol.detection_event import (
    AggregatedRisk,
    Detection,
    Decision,
    Severity,
)


@dataclass
class PolicyRule:
    """A single policy rule."""

    name: str
    condition: Callable[[list[Detection], Optional[AggregatedRisk]], bool]
    action: Decision
    priority: int = 0  # Higher = evaluated first


class PolicyEngine:
    """
    Evaluates detections and aggregated risk against configurable policies.

    Default behavior:
    - CRITICAL severity → BLOCK
    - HIGH severity → BLOCK
    - Risk score >= 0.8 → BLOCK
    - MEDIUM severity → FLAG
    - Risk score >= 0.5 → FLAG
    - LOW/INFO severity → ALLOW

    Custom rules can override defaults.
    """

    # Risk score thresholds
    BLOCK_THRESHOLD = 0.8
    FLAG_THRESHOLD = 0.5

    def __init__(self):
        self._rules: list[PolicyRule] = []
        self._setup_default_rules()

    def _setup_default_rules(self) -> None:
        """Configure default security policy."""
        self._rules = [
            PolicyRule(
                name="block_critical",
                condition=lambda ds, ar: any(
                    d.severity == Severity.CRITICAL for d in ds
                ),
                action=Decision.BLOCK,
                priority=100,
            ),
            PolicyRule(
                name="block_high_risk_score",
                condition=lambda ds, ar: ar is not None
                and ar.risk_score >= self.BLOCK_THRESHOLD,
                action=Decision.BLOCK,
                priority=95,
            ),
            PolicyRule(
                name="block_high",
                condition=lambda ds, ar: any(d.severity == Severity.HIGH for d in ds),
                action=Decision.BLOCK,
                priority=90,
            ),
            PolicyRule(
                name="flag_medium_risk_score",
                condition=lambda ds, ar: ar is not None
                and ar.risk_score >= self.FLAG_THRESHOLD,
                action=Decision.FLAG,
                priority=55,
            ),
            PolicyRule(
                name="flag_medium",
                condition=lambda ds, ar: any(d.severity == Severity.MEDIUM for d in ds),
                action=Decision.FLAG,
                priority=50,
            ),
        ]

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a custom policy rule."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(
        self,
        detections: list[Detection],
        aggregated_risk: Optional[AggregatedRisk] = None,
    ) -> Decision:
        """
        Evaluate detections and risk against all policy rules.

        Args:
            detections: List of detections from the pipeline.
            aggregated_risk: Aggregated risk assessment (optional).

        Returns:
            Final decision based on policy evaluation.
        """
        if not detections:
            return Decision.ALLOW

        # Evaluate rules in priority order
        for rule in self._rules:
            if rule.condition(detections, aggregated_risk):
                return rule.action

        return Decision.ALLOW

    def clear_rules(self) -> None:
        """Remove all rules including defaults."""
        self._rules = []

    def reset_to_defaults(self) -> None:
        """Reset to default rules."""
        self._setup_default_rules()
