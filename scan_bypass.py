#!/usr/bin/env python3
"""
TrigGuard Bypass Pattern Scanner

Scans the codebase for dangerous patterns that could bypass
TrigGuard authorization controls.

Exit codes:
    0: No violations found
    1: Violations found
"""

import re
import sys
from pathlib import Path

# Root of the kernel codebase
KERNEL_ROOT = Path(__file__).parent

# Directories to scan
SCAN_DIRECTORIES = ["trigguard"]

# Files where bypass patterns are ALLOWED
ALLOWED_PATHS = {
    "protected_actions.py",  # Contains intentional subprocess calls
    "execution_adapter.py",  # Contains protected exec() wrapper
    "sdk/",  # SDK examples showing protected usage
    "tests/",
    "docs/",
    "__pycache__",
    ".venv",
}

# Critical bypass patterns (High severity)
CRITICAL_PATTERNS = [
    (r"\bos\.system\s*\(", "os.system() - use protected_shell_command()"),
    (r"\beval\s*\(", "eval() - use protected_code_exec()"),
    (r"\bexec\s*\(", "exec() - use protected_code_exec()"),
]

# High bypass patterns
HIGH_PATTERNS = [
    (r"subprocess\.call\s*\(", "subprocess.call() - use protected_shell_command()"),
    (r"subprocess\.Popen\s*\(", "subprocess.Popen() - use protected_shell_command()"),
]


def is_allowed_path(path: Path) -> bool:
    """Check if path is in allowed list."""
    path_str = str(path)
    return any(allowed in path_str for allowed in ALLOWED_PATHS)


def is_in_comment_or_string(line: str, match_start: int) -> bool:
    """Check if match is inside a comment or string."""
    # Simple check: if # appears before match, it's a comment
    hash_pos = line.find("#")
    if hash_pos != -1 and hash_pos < match_start:
        return True
    # Check for string patterns (rough)
    if '"""' in line[:match_start] or "'''" in line[:match_start]:
        return True
    return False


def scan_file(filepath: Path) -> list:
    """Scan a single file for bypass patterns."""
    violations = []

    try:
        content = filepath.read_text()
    except Exception:
        return violations

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        # Skip empty lines
        if not line.strip():
            continue

        # Check critical patterns
        for pattern, description in CRITICAL_PATTERNS + HIGH_PATTERNS:
            match = re.search(pattern, line)
            if match and not is_in_comment_or_string(line, match.start()):
                violations.append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "pattern": description,
                        "code": line.strip()[:80],
                    }
                )

    return violations


def main():
    """Main scanner entry point."""
    violations = []
    files_scanned = 0

    for scan_dir in SCAN_DIRECTORIES:
        scan_path = KERNEL_ROOT / scan_dir
        if not scan_path.exists():
            continue

        for filepath in scan_path.rglob("*.py"):
            if is_allowed_path(filepath):
                continue

            files_scanned += 1
            file_violations = scan_file(filepath)
            violations.extend(file_violations)

    print(f"Scanned {files_scanned} files")

    if violations:
        print(f"\n❌ Found {len(violations)} bypass pattern violations:\n")
        for v in violations:
            print(f"  {v['file']}:{v['line']}")
            print(f"    Pattern: {v['pattern']}")
            print(f"    Code: {v['code']}")
            print()
        sys.exit(1)
    else:
        print("✅ No bypass patterns detected")
        sys.exit(0)


if __name__ == "__main__":
    main()
