"""
Kernel Dependency Boundary Test.

ARCHITECTURAL INVARIANT: The kernel MUST NOT import external layers.

The kernel contains only:
- decision engine
- signal frame
- constraint evaluator
- execution surface
- decision receipt

Everything else (sdk, server, integrations, cache, observability, etc.)
lives OUTSIDE the kernel and can import FROM the kernel, but not vice versa.

If this test fails, you are breaking the architecture.
"""

import ast
import pathlib
import pytest

# Kernel directory - contains the core decision system
KERNEL_MODULES = [
    "trigguard/authority",
    "trigguard/constraints",
    "trigguard/signals",
    "trigguard/surfaces",
    "trigguard/protocol",
    "trigguard/aggregation",
    "trigguard/engine",
]

# These are EXTERNAL layers that the kernel MUST NOT import
FORBIDDEN_IMPORT_PREFIXES = [
    "trigguard.sdk",
    "trigguard.server",
    "trigguard.integrations",
    "trigguard.cache",
    "trigguard.observability",
    "trigguard.ratelimit",
    "trigguard.ha",
    "trigguard.network",
    "trigguard.tools",
    "trigguard.telemetry",
    "trigguard.policy.sync_service",  # Sync service is infra, not kernel
    "trigguard.policy.multi_tenant",  # Multi-tenant is infra, not kernel
]


def get_kernel_files():
    """Get all Python files in kernel modules."""
    kernel_files = []
    for module_path in KERNEL_MODULES:
        path = pathlib.Path(module_path)
        if path.exists():
            kernel_files.extend(path.rglob("*.py"))
    return kernel_files


def check_imports(file_path: pathlib.Path) -> list:
    """Check a file for forbidden imports."""
    violations = []

    try:
        tree = ast.parse(file_path.read_text())
    except SyntaxError:
        return []  # Skip files with syntax errors

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for forbidden in FORBIDDEN_IMPORT_PREFIXES:
                if module.startswith(forbidden):
                    violations.append(
                        {
                            "file": str(file_path),
                            "line": node.lineno,
                            "import": module,
                            "forbidden_prefix": forbidden,
                        }
                    )

        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                for forbidden in FORBIDDEN_IMPORT_PREFIXES:
                    if module.startswith(forbidden):
                        violations.append(
                            {
                                "file": str(file_path),
                                "line": node.lineno,
                                "import": module,
                                "forbidden_prefix": forbidden,
                            }
                        )

    return violations


class TestKernelDependencyBoundary:
    """
    INVARIANT: Kernel modules cannot import external layers.

    The kernel is the authorization engine - it must be:
    - Deterministic
    - No networking
    - No database
    - No external APIs
    - Minimal dependencies
    - Pure decision logic

    Direction of dependencies:
        sdk → kernel (allowed)
        server → kernel (allowed)
        kernel → sdk (FORBIDDEN)
        kernel → server (FORBIDDEN)
    """

    def test_kernel_has_no_external_dependencies(self):
        """
        Kernel modules must not import from external layers.

        If this test fails, you are violating the architectural boundary.
        The kernel must remain a small, deterministic decision engine.
        """
        all_violations = []
        kernel_files = get_kernel_files()

        for file_path in kernel_files:
            violations = check_imports(file_path)
            all_violations.extend(violations)

        if all_violations:
            violation_report = "\n".join(
                [
                    f"  {v['file']}:{v['line']} imports {v['import']} "
                    f"(forbidden prefix: {v['forbidden_prefix']})"
                    for v in all_violations
                ]
            )
            pytest.fail(
                f"KERNEL DEPENDENCY VIOLATIONS DETECTED!\n\n"
                f"The kernel must not import from external layers.\n"
                f"Found {len(all_violations)} violation(s):\n\n"
                f"{violation_report}\n\n"
                f"Fix: Move the dependency to an external layer, "
                f"or inject it as a parameter."
            )

    def test_kernel_modules_exist(self):
        """Verify kernel modules are present."""
        existing = []
        missing = []

        for module_path in KERNEL_MODULES:
            path = pathlib.Path(module_path)
            if path.exists():
                existing.append(module_path)
            else:
                missing.append(module_path)

        # At least some kernel modules should exist
        assert (
            len(existing) > 0
        ), f"No kernel modules found. Expected at least one of: {KERNEL_MODULES}"

    def test_forbidden_prefixes_are_valid(self):
        """Verify forbidden prefixes are properly defined."""
        for prefix in FORBIDDEN_IMPORT_PREFIXES:
            assert prefix.startswith(
                "trigguard."
            ), f"Forbidden prefix must start with 'trigguard.': {prefix}"
            assert prefix not in [
                "trigguard.authority",
                "trigguard.protocol",
            ], f"Kernel module incorrectly listed as forbidden: {prefix}"


def test_kernel_size_limit():
    """
    GUIDELINE: Kernel should stay small.

    Target: < 5000 lines of code

    If the kernel grows too large, it probably contains
    functionality that should be in an external layer.
    """
    total_lines = 0
    kernel_files = get_kernel_files()

    for file_path in kernel_files:
        try:
            lines = len(file_path.read_text().splitlines())
            total_lines += lines
        except Exception:
            pass

    # Warning threshold
    WARNING_THRESHOLD = 5000

    if total_lines > WARNING_THRESHOLD:
        pytest.skip(
            f"Kernel size ({total_lines} lines) exceeds guideline ({WARNING_THRESHOLD}). "
            f"Consider extracting non-essential functionality to external layers."
        )
