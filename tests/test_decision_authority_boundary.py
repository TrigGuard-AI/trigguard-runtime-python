"""
Decision Authority Boundary Test

This test enforces that authorization logic ONLY lives in the kernel.

The kernel is the sole decision authority in TrigGuard.
All other layers may only:
- normalize
- package
- verify
- enforce
- transport
- log

Never decide.

If this test fails, someone added policy logic outside the kernel.
That breaks:
- determinism
- replayability
- auditability
- trust
"""

import re
from pathlib import Path

import pytest

ROOT = Path("trigguard")

# These paths ARE allowed to contain decision logic
ALLOWED_PATH_PATTERNS = [
    re.compile(r"^trigguard/kernel/"),
    re.compile(r"^trigguard/protocol/"),
    re.compile(r"^trigguard/engine/"),  # DetectionEngine is part of kernel
]

# These directories must NOT contain decision logic
TARGET_DIRS = [
    "trigguard/sdk",
    "trigguard/executor",
    "trigguard/server",
    "trigguard/integrations",
    "trigguard/verification",
]

# Patterns that indicate decision logic
FORBIDDEN_PATTERNS = [
    # Direct decision values (but allow in type hints, enums, imports)
    re.compile(r"^\s*return\s+Decision\.PERMIT"),
    re.compile(r"^\s*return\s+Decision\.DENY"),
    re.compile(r"^\s*return\s+Decision\.SILENCE"),
    # Risk threshold decisions
    re.compile(r"risk_score\s*[><=]\s*\d"),
    re.compile(r"if\s+.*risk.*[><=]"),
    # Inline policy decisions
    re.compile(r"^\s*if\s+.*:\s*$.*^\s*return\s+Decision\.", re.MULTILINE),
]

# Lines containing these are allowed (verification, types, etc)
ALLOWLIST_LINE_PATTERNS = [
    re.compile(r"DecisionReceipt"),
    re.compile(r"ActionGrant"),
    re.compile(r"verify"),
    re.compile(r"ExecutorDecision"),
    re.compile(r"class\s+\w+Decision"),
    re.compile(r"from\s+trigguard"),
    re.compile(r"import\s+"),
    re.compile(r"Decision\s*\["),  # Type hints like Decision[...]
    re.compile(r":\s*Decision"),  # Type annotations
    re.compile(r"->\s*Decision"),  # Return type annotations
    re.compile(r"decision\."),  # Accessing decision attributes
    re.compile(r"decision\s*=\s*contract"),  # Assignment from contract
    re.compile(r"decision\s*=\s*self"),  # Assignment from self
    re.compile(r"\.decision"),  # Attribute access
    re.compile(r"_decision"),  # Private attributes
    re.compile(r"decision_"),  # Prefixed names
    re.compile(r"Enum"),
    re.compile(r"\"\"\""),  # Docstrings
    re.compile(r"#"),  # Comments
]


def is_allowed_file(path: str) -> bool:
    """Check if file is in an allowed path (kernel, protocol)."""
    return any(pattern.search(path) for pattern in ALLOWED_PATH_PATTERNS)


def is_allowlisted_line(line: str) -> bool:
    """Check if line is allowlisted (imports, types, etc)."""
    return any(pattern.search(line) for pattern in ALLOWLIST_LINE_PATTERNS)


class TestDecisionAuthorityBoundary:
    """Tests that decision authority stays in the kernel."""

    def test_decision_authority_does_not_leak_outside_kernel(self):
        """
        Verify no authorization logic exists outside kernel.

        This is THE critical architecture guard.
        If this test fails, the system's trust model is broken.
        """
        violations = []

        for target in TARGET_DIRS:
            target_path = Path(target)
            if not target_path.exists():
                continue

            for file in target_path.rglob("*.py"):
                rel = str(file).replace("\\", "/")

                if is_allowed_file(rel):
                    continue

                try:
                    lines = file.read_text(encoding="utf-8").splitlines()
                except Exception:
                    continue

                for lineno, line in enumerate(lines, start=1):
                    stripped = line.strip()

                    # Skip empty lines and comments
                    if not stripped or stripped.startswith("#"):
                        continue

                    # Skip allowlisted patterns
                    if is_allowlisted_line(stripped):
                        continue

                    # Check forbidden patterns
                    for pattern in FORBIDDEN_PATTERNS:
                        if pattern.search(stripped):
                            violations.append(f"{rel}:{lineno}: {stripped}")
                            break

        assert not violations, "Decision logic leaked outside kernel:\n" + "\n".join(
            violations
        )

    def test_no_inline_permit_deny_outside_kernel(self):
        """
        Check for inline PERMIT/DENY decisions outside kernel.

        These exact strings should only appear in:
        - kernel (making decisions)
        - protocol (enum definitions)
        - tests (assertions)
        """
        violations = []

        for target in TARGET_DIRS:
            target_path = Path(target)
            if not target_path.exists():
                continue

            for file in target_path.rglob("*.py"):
                rel = str(file).replace("\\", "/")

                if is_allowed_file(rel):
                    continue

                try:
                    content = file.read_text(encoding="utf-8")
                except Exception:
                    continue

                lines = content.splitlines()
                for lineno, line in enumerate(lines, start=1):
                    stripped = line.strip()

                    # Skip imports, type hints, docstrings, comments
                    if is_allowlisted_line(stripped):
                        continue

                    # Check for returning decisions
                    if re.search(r"return\s+Decision\.(PERMIT|DENY|SILENCE)", stripped):
                        violations.append(f"{rel}:{lineno}: {stripped}")

        assert (
            not violations
        ), "Inline decision returns found outside kernel:\n" + "\n".join(violations)


class TestExecutorDoesNotDecide:
    """Verify executor only enforces, never decides."""

    def test_executor_uses_verification_not_policy(self):
        """
        Executor should verify grants, not evaluate policy.

        The executor may:
        - verify grant signatures
        - check grant expiry
        - enforce constraints

        The executor must NOT:
        - evaluate risk scores
        - make permit/deny decisions
        - implement policy rules
        """
        executor_path = Path("trigguard/executor")
        if not executor_path.exists():
            pytest.skip("Executor not yet implemented")

        violations = []

        for file in executor_path.rglob("*.py"):
            rel = str(file).replace("\\", "/")
            try:
                content = file.read_text(encoding="utf-8")
            except Exception:
                continue

            # Check for policy evaluation patterns
            policy_patterns = [
                (r"evaluate.*policy", "Policy evaluation in executor"),
                (r"risk_score\s*[><=]", "Risk threshold in executor"),
                (r"if.*allowed.*:", "Inline authorization logic"),
            ]

            lines = content.splitlines()
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#") or is_allowlisted_line(stripped):
                    continue

                for pattern, reason in policy_patterns:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # Allow "allowed" in ExecutorDecision context
                        if (
                            "ExecutorDecision" in stripped
                            or "decision.allowed" in stripped
                        ):
                            continue
                        if ".allowed" in stripped:
                            continue
                        violations.append(f"{rel}:{lineno}: {reason} - {stripped}")

        assert not violations, "Executor contains policy logic:\n" + "\n".join(
            violations
        )


class TestSDKDoesNotDecide:
    """Verify SDK only wraps, never decides."""

    def test_sdk_delegates_to_verification(self):
        """
        SDK should delegate to verification layer.

        The SDK may:
        - wrap functions with decorators
        - call verification SDK
        - format responses

        The SDK must NOT:
        - make authorization decisions
        - implement policy logic
        - evaluate risk
        """
        sdk_path = Path("trigguard/sdk")
        if not sdk_path.exists():
            pytest.skip("SDK not yet implemented")

        violations = []

        for file in sdk_path.rglob("*.py"):
            rel = str(file).replace("\\", "/")
            try:
                content = file.read_text(encoding="utf-8")
            except Exception:
                continue

            lines = content.splitlines()
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#") or is_allowlisted_line(stripped):
                    continue

                # Check for inline decisions
                if re.search(r"^\s*return\s+Decision\.(PERMIT|DENY)", stripped):
                    violations.append(
                        f"{rel}:{lineno}: SDK returning Decision - {stripped}"
                    )

        assert not violations, "SDK contains decision logic:\n" + "\n".join(violations)
