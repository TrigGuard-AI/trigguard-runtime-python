"""
TrigGuard Bypass Pattern Detection Tests

STATIC ANALYSIS SCANS FOR BYPASS PATTERNS.

These tests scan the codebase for dangerous patterns that could
bypass TrigGuard authorization. Run on every commit to detect
architectural violations early.

DANGEROUS PATTERNS:
1. Direct subprocess/os.system usage (should use protected_shell_command)
2. Direct exec/eval usage (should use protected_code_exec)
3. Direct HTTP requests with sensitive data (should use protected_data_export)
4. Unguarded financial API calls
5. Unguarded delegation operations

ALLOWED PATTERNS:
- Usage in tests/
- Usage in docs/examples
- Usage within protected_actions.py wrappers
- Usage in comments/docstrings

RUN: pytest tests/test_no_bypass_patterns.py -v
"""

import ast
import os
import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Set, Tuple
import pytest

# ============================================================================
# Configuration
# ============================================================================

# Root of the kernel codebase
KERNEL_ROOT = Path(__file__).parent.parent

# Directories to scan (relative to KERNEL_ROOT)
SCAN_DIRECTORIES = [
    "sdk",
    "core",
    "authority",
    "engine",
    "integrations",
    "policy",
    "server",
]

# Directories to skip
SKIP_DIRECTORIES = {
    "__pycache__",
    ".git",
    "venv",
    ".venv",
    "node_modules",
}

# Files where bypass patterns are ALLOWED
ALLOWED_FILES = {
    # Protected actions wrappers (they contain the actual dangerous calls)
    "core/protected_actions.py",
    # Test files
    "tests/",
    # Documentation
    "docs/",
    # Examples (if any)
    "examples/",
    # This file itself
    "tests/test_no_bypass_patterns.py",
}


class BypassViolation(NamedTuple):
    """A detected bypass pattern violation."""

    file: str
    line: int
    pattern: str
    code: str
    severity: str  # CRITICAL, HIGH, MEDIUM


# ============================================================================
# Pattern Definitions
# ============================================================================

# Patterns to detect with severity levels
DANGEROUS_PATTERNS: Dict[str, Tuple[str, str]] = {
    # CODE_EXECUTION bypass patterns (CRITICAL)
    r"\bsubprocess\.run\b": ("subprocess.run", "CRITICAL"),
    r"\bsubprocess\.Popen\b": ("subprocess.Popen", "CRITICAL"),
    r"\bsubprocess\.call\b": ("subprocess.call", "CRITICAL"),
    r"\bsubprocess\.check_call\b": ("subprocess.check_call", "CRITICAL"),
    r"\bsubprocess\.check_output\b": ("subprocess.check_output", "CRITICAL"),
    r"\bos\.system\b": ("os.system", "CRITICAL"),
    r"\bos\.popen\b": ("os.popen", "CRITICAL"),
    r"\bos\.spawn": ("os.spawn*", "CRITICAL"),
    r"\bos\.exec": ("os.exec*", "CRITICAL"),
    r"\bexec\s*\(": ("exec()", "CRITICAL"),
    r"\beval\s*\(": ("eval()", "CRITICAL"),
    r"\bcompile\s*\([^)]*\bexec\b": ("compile...exec", "CRITICAL"),
    # DATA_EXPORT bypass patterns (HIGH)
    r"requests\.post\s*\(": ("requests.post", "HIGH"),
    r"requests\.put\s*\(": ("requests.put", "HIGH"),
    r"httpx\.post\s*\(": ("httpx.post", "HIGH"),
    r"httpx\.put\s*\(": ("httpx.put", "HIGH"),
    r"aiohttp\.ClientSession": ("aiohttp.ClientSession", "HIGH"),
    r"urllib\.request\.urlopen": ("urllib.request.urlopen", "HIGH"),
    # SPEND bypass patterns (HIGH)
    r"stripe\.Charge\.create": ("stripe payment", "HIGH"),
    r"stripe\.PaymentIntent": ("stripe payment", "HIGH"),
    r"paypal\.": ("paypal", "HIGH"),
    r"braintree\.": ("braintree", "HIGH"),
    # DELEGATION bypass patterns (HIGH)
    r"\.grant_permission": ("permission grant", "HIGH"),
    r"\.add_role": ("role assignment", "HIGH"),
    r"\.set_capabilities": ("capability assignment", "HIGH"),
    # IDENTITY_ASSERTION bypass patterns (MEDIUM)
    r"cryptography\..*\.sign": ("cryptographic signing", "MEDIUM"),
    r"jwt\.encode": ("JWT signing", "MEDIUM"),
    r"\.sign_message": ("message signing", "MEDIUM"),
}

# ALLOW patterns (comments, docstrings, imports)
ALLOW_CONTEXT_PATTERNS = [
    r"^\s*#",  # Comments
    r'^\s*"""',  # Docstring start
    r"^\s*'''",  # Docstring start
    r"^\s*from\s+",  # Import statement
    r"^\s*import\s+",  # Import statement
]


# ============================================================================
# Scanning Functions
# ============================================================================


def is_allowed_file(file_path: Path) -> bool:
    """Check if file is in allowed list."""
    rel_path = str(file_path.relative_to(KERNEL_ROOT))

    for allowed in ALLOWED_FILES:
        if allowed.endswith("/"):
            # Directory prefix
            if rel_path.startswith(allowed):
                return True
        else:
            # Exact file match
            if rel_path == allowed:
                return True

    return False


def is_in_comment_or_string(line: str, match_start: int) -> bool:
    """Check if match is inside a comment or string literal."""
    # Check if in comment
    hash_pos = line.find("#")
    if hash_pos != -1 and hash_pos < match_start:
        return True

    # Simple string check (not perfect but catches common cases)
    before_match = line[:match_start]

    # Count quotes to determine if in string
    single_quotes = before_match.count("'") - before_match.count("\\'")
    double_quotes = before_match.count('"') - before_match.count('\\"')

    # Odd number of unescaped quotes means we're inside a string
    if single_quotes % 2 != 0 or double_quotes % 2 != 0:
        return True

    return False


def scan_file(file_path: Path) -> List[BypassViolation]:
    """Scan a single file for bypass patterns."""
    violations = []

    try:
        content = file_path.read_text(encoding="utf-8")
        lines = content.split("\n")
    except Exception:
        return []

    rel_path = str(file_path.relative_to(KERNEL_ROOT))

    # Track if we're in a docstring
    in_docstring = False

    for line_no, line in enumerate(lines, start=1):
        # Track docstrings by counting triple quotes
        triple_count = line.count('"""') + line.count("'''")
        if triple_count % 2 == 1:
            in_docstring = not in_docstring

        if in_docstring:
            continue

        # Skip if line is just a comment
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Skip import lines
        if stripped.startswith("from ") or stripped.startswith("import "):
            continue

        # Check each pattern
        for pattern, (name, severity) in DANGEROUS_PATTERNS.items():
            matches = list(re.finditer(pattern, line))
            for match in matches:
                # Skip if in comment or string
                if is_in_comment_or_string(line, match.start()):
                    continue

                violations.append(
                    BypassViolation(
                        file=rel_path,
                        line=line_no,
                        pattern=name,
                        code=line.strip()[:80],
                        severity=severity,
                    )
                )

    return violations


def scan_directory(dir_path: Path) -> List[BypassViolation]:
    """Scan a directory recursively for bypass patterns."""
    violations = []

    for root, dirs, files in os.walk(dir_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = Path(root) / file

            # Skip allowed files
            if is_allowed_file(file_path):
                continue

            violations.extend(scan_file(file_path))

    return violations


def scan_codebase() -> List[BypassViolation]:
    """Scan the entire codebase for bypass patterns."""
    all_violations = []

    for dir_name in SCAN_DIRECTORIES:
        dir_path = KERNEL_ROOT / dir_name
        if dir_path.exists():
            all_violations.extend(scan_directory(dir_path))

    return all_violations


# ============================================================================
# AST-Based Analysis
# ============================================================================


class BypassVisitor(ast.NodeVisitor):
    """AST visitor to detect bypass patterns more accurately."""

    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[BypassViolation] = []
        self._in_protected_context = False

    def visit_Call(self, node: ast.Call):
        """Check function calls for dangerous patterns."""
        call_name = self._get_call_name(node)

        if call_name:
            # Check for dangerous calls
            dangerous_calls = {
                "exec": ("exec()", "CRITICAL"),
                "eval": ("eval()", "CRITICAL"),
                "compile": ("compile()", "HIGH"),
                "os.system": ("os.system", "CRITICAL"),
                "os.popen": ("os.popen", "CRITICAL"),
                "subprocess.run": ("subprocess.run", "CRITICAL"),
                "subprocess.Popen": ("subprocess.Popen", "CRITICAL"),
                "subprocess.call": ("subprocess.call", "CRITICAL"),
            }

            if call_name in dangerous_calls:
                name, severity = dangerous_calls[call_name]
                self.violations.append(
                    BypassViolation(
                        file=self.filename,
                        line=node.lineno,
                        pattern=name,
                        code=f"AST: {call_name}(...)",
                        severity=severity,
                    )
                )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return ".".join(parts)
        return ""


def ast_scan_file(file_path: Path) -> List[BypassViolation]:
    """Scan a file using AST analysis."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content)
    except Exception:
        return []

    rel_path = str(file_path.relative_to(KERNEL_ROOT))
    visitor = BypassVisitor(rel_path)
    visitor.visit(tree)

    return visitor.violations


# ============================================================================
# Pytest Test Cases
# ============================================================================


class TestNoBypassPatterns:
    """Test suite for bypass pattern detection."""

    def test_no_critical_bypass_patterns(self):
        """CRITICAL: No critical bypass patterns in production code."""
        violations = scan_codebase()
        critical = [v for v in violations if v.severity == "CRITICAL"]

        if critical:
            msg = "\n\nCRITICAL BYPASS PATTERNS DETECTED:\n"
            for v in critical:
                msg += f"  {v.file}:{v.line} - {v.pattern}: {v.code}\n"
            msg += (
                "\nUse protected_* functions from core/protected_actions.py instead.\n"
            )
            pytest.fail(msg)

    def test_no_high_bypass_patterns(self):
        """HIGH: No high-severity bypass patterns in production code."""
        violations = scan_codebase()
        high = [v for v in violations if v.severity == "HIGH"]

        if high:
            msg = "\n\nHIGH SEVERITY BYPASS PATTERNS DETECTED:\n"
            for v in high:
                msg += f"  {v.file}:{v.line} - {v.pattern}: {v.code}\n"
            msg += (
                "\nUse protected_* functions from core/protected_actions.py instead.\n"
            )
            pytest.fail(msg)

    def test_no_medium_bypass_patterns(self):
        """MEDIUM: Warn about medium-severity patterns."""
        violations = scan_codebase()
        medium = [v for v in violations if v.severity == "MEDIUM"]

        if medium:
            msg = "\n\nMEDIUM SEVERITY BYPASS PATTERNS DETECTED (warnings):\n"
            for v in medium:
                msg += f"  {v.file}:{v.line} - {v.pattern}: {v.code}\n"
            # Warn but don't fail for medium severity
            pytest.skip(msg)

    def test_sdk_gate_no_direct_exec(self):
        """Verify sdk/gate.py doesn't have unguarded exec."""
        gate_path = KERNEL_ROOT / "sdk" / "gate.py"
        if not gate_path.exists():
            pytest.skip("sdk/gate.py not found")

        violations = scan_file(gate_path)
        critical = [v for v in violations if v.severity == "CRITICAL"]

        if critical:
            msg = "\n\nCRITICAL: sdk/gate.py contains bypass patterns:\n"
            for v in critical:
                msg += f"  Line {v.line} - {v.pattern}: {v.code}\n"
            pytest.fail(msg)

    def test_integrations_use_protected_actions(self):
        """Verify integrations use protected actions."""
        integrations_path = KERNEL_ROOT / "integrations"
        if not integrations_path.exists():
            pytest.skip("integrations/ not found")

        violations = scan_directory(integrations_path)
        critical = [v for v in violations if v.severity == "CRITICAL"]

        if critical:
            msg = "\n\nCRITICAL: integrations/ contains bypass patterns:\n"
            for v in critical:
                msg += f"  {v.file}:{v.line} - {v.pattern}: {v.code}\n"
            msg += "\nIntegrations MUST use protected_* functions.\n"
            pytest.fail(msg)


class TestAllowedPatterns:
    """Verify allowed file detection works correctly."""

    def test_protected_actions_allowed(self):
        """Verify protected_actions.py is in allowed list."""
        path = KERNEL_ROOT / "core" / "protected_actions.py"
        assert is_allowed_file(path)

    def test_tests_allowed(self):
        """Verify tests/ is in allowed list."""
        path = KERNEL_ROOT / "tests" / "test_something.py"
        assert is_allowed_file(path)

    def test_docs_allowed(self):
        """Verify docs/ is in allowed list."""
        path = KERNEL_ROOT / "docs" / "example.py"
        assert is_allowed_file(path)

    def test_production_code_not_allowed(self):
        """Verify production code is NOT in allowed list."""
        path = KERNEL_ROOT / "sdk" / "gate.py"
        assert not is_allowed_file(path)


class TestCommentDetection:
    """Verify comment/string detection works."""

    def test_comment_detected(self):
        """Verify patterns in comments are ignored."""
        line = "# subprocess.run is dangerous"
        assert is_in_comment_or_string(line, line.find("subprocess"))

    def test_string_detected(self):
        """Verify patterns in strings are detected."""
        line = 'error = "exec failed"'
        # The 'exec' in the string should be detected as in-string
        exec_pos = line.find("exec")
        assert is_in_comment_or_string(line, exec_pos)

    def test_code_not_detected_as_comment(self):
        """Verify actual code is not detected as comment."""
        line = "result = subprocess.run(cmd)"
        subprocess_pos = line.find("subprocess")
        assert not is_in_comment_or_string(line, subprocess_pos)


class TestPatternCoverage:
    """Verify all dangerous patterns are covered."""

    def test_all_subprocess_variants_covered(self):
        """Verify all subprocess patterns detected."""
        patterns = list(DANGEROUS_PATTERNS.keys())
        pattern_str = " ".join(patterns)

        subprocess_variants = [
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        ]

        for variant in subprocess_variants:
            assert any(
                re.search(p, variant) for p in patterns
            ), f"Missing pattern for {variant}"

    def test_all_exec_variants_covered(self):
        """Verify exec/eval patterns detected."""
        test_lines = [
            "exec(code)",
            "eval(expr)",
            "os.system(cmd)",
        ]

        for line in test_lines:
            found = False
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, line):
                    found = True
                    break
            assert found, f"No pattern matches: {line}"


# ============================================================================
# Report Generation
# ============================================================================


def generate_report(violations: List[BypassViolation]) -> str:
    """Generate a human-readable report of violations."""
    if not violations:
        return "✓ No bypass patterns detected.\n"

    # Group by severity
    by_severity: Dict[str, List[BypassViolation]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
    }

    for v in violations:
        by_severity[v.severity].append(v)

    report = "BYPASS PATTERN DETECTION REPORT\n"
    report += "=" * 60 + "\n\n"

    report += f"Total violations: {len(violations)}\n"
    report += f"  CRITICAL: {len(by_severity['CRITICAL'])}\n"
    report += f"  HIGH:     {len(by_severity['HIGH'])}\n"
    report += f"  MEDIUM:   {len(by_severity['MEDIUM'])}\n\n"

    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        group = by_severity[severity]
        if group:
            report += f"\n{severity} Violations:\n"
            report += "-" * 40 + "\n"
            for v in group:
                report += f"  {v.file}:{v.line}\n"
                report += f"    Pattern: {v.pattern}\n"
                report += f"    Code: {v.code}\n\n"

    return report


# ============================================================================
# CLI Entry Point
# ============================================================================

if __name__ == "__main__":
    print("Scanning codebase for bypass patterns...\n")
    violations = scan_codebase()
    report = generate_report(violations)
    print(report)

    # Exit with error if critical violations found
    critical = [v for v in violations if v.severity == "CRITICAL"]
    if critical:
        exit(1)
