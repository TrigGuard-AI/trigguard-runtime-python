"""
Policy Engine

Evaluates detection results against security policies.
Determines the final decision (ALLOW, BLOCK, FLAG, REDACT).
"""

from dataclasses import dataclass, field
from typing import Callable, Optional

from protocol.detection_event import Detection, Decision, Severity


@dataclass
class PolicyRule:
    """A single policy rule."""
    name: str
    condition: Callable[[list[Detection]], bool]
    action: Decision
    priority: int = 0  # Higher = evaluated first


class PolicyEngine:
    """
    Evaluates detections against configurable policies.

    Default behavior:
    - CRITICAL severity → BLOCK
    - HIGH severity → BLOCK
    - MEDIUM severity → FLAG
    - LOW/INFO severity → ALLOW

    Custom rules can override defaults.
    """

    def __init__(self):
        self._rules: list[PolicyRule] = []
        self._setup_default_rules()

    def _setup_default_rules(self) -> None:
        """Configure default security policy."""
        self._rules = [
            PolicyRule(
                name="block_critical",
                condition=lambda ds: any(d.severity == Severity.CRITICAL for d in ds),
                action=Decision.BLOCK,
                priority=100,
            ),
            PolicyRule(
                name="block_high",
                condition=lambda ds: any(d.severity == Severity.HIGH for d in ds),
                action=Decision.BLOCK,
                priority=90,
            ),
            PolicyRule(
                name="flag_medium",
                condition=lambda ds: any(d.severity == Severity.MEDIUM for d in ds),
                action=Decision.FLAG,
                priority=50,
            ),
        ]

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a custom policy rule."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(self, detections: list[Detection]) -> Decision:
        """
        Evaluate detections against all policy rules.

        Args:
            detections: List of detections from the pipeline.

        Returns:
            Final decision based on policy evaluation.
        """
        if not detections:
            return Decision.ALLOW

        # Evaluate rules in priority order
        for rule in self._rules:
            if rule.condition(detections):
                return rule.action

        return Decision.ALLOW

    def clear_rules(self) -> None:
        """Remove all rules including defaults."""
        self._rules = []

    def reset_to_defaults(self) -> None:
        """Reset to default rules."""
        self._setup_default_rules()
