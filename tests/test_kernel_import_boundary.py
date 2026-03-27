"""
Kernel Import Boundary Test

This test enforces that the kernel does NOT import from outer layers.

Dependency direction must be:

    kernel
       │
       ▼
    protocol
       │
       ▼
    verification
       │
       ▼
    executor
       │
       ▼
    sdk
       │
       ▼
    server

The kernel must remain pure and self-contained.
If it imports from SDK, server, or executor, the architecture collapses.
"""

import ast
from pathlib import Path

import pytest

KERNEL_DIR = Path("trigguard/kernel")

# These modules must NEVER be imported by the kernel
FORBIDDEN_IMPORT_PREFIXES = [
    "trigguard.sdk",
    "trigguard.server",
    "trigguard.executor",
    "trigguard.integrations",
    "trigguard.verification",
    "fastapi",
    "uvicorn",
    "starlette",
]

# These are allowed (kernel may use these)
ALLOWED_IMPORTS = [
    "trigguard.protocol",
    "trigguard.grants",
    "trigguard.core",
    "trigguard.kernel",
    "trigguard.engine",  # Engine is part of kernel
    "trigguard.context",  # Context building is kernel
    "trigguard.aggregation",  # Risk aggregation is kernel
    "trigguard.policy",  # Policy is kernel
    "dataclasses",
    "typing",
    "enum",
    "hashlib",
    "hmac",
    "uuid",
    "datetime",
    "json",
    "re",
    "functools",
    "collections",
    "abc",
    "copy",
    "logging",
]


class TestKernelImportBoundary:
    """Tests that kernel doesn't import from outer layers."""

    def test_kernel_imports_no_outer_layers(self):
        """
        Verify kernel does not import from SDK, server, executor, etc.

        This is a critical architecture guard.
        The kernel must be portable and self-contained.
        """
        if not KERNEL_DIR.exists():
            pytest.skip("Kernel directory not found")

        violations = []

        for file in KERNEL_DIR.rglob("*.py"):
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if any(
                        module.startswith(prefix)
                        for prefix in FORBIDDEN_IMPORT_PREFIXES
                    ):
                        violations.append(f"{file}: from {module} import ...")

                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name
                        if any(
                            name.startswith(prefix)
                            for prefix in FORBIDDEN_IMPORT_PREFIXES
                        ):
                            violations.append(f"{file}: import {name}")

        assert not violations, "Kernel import boundary violated:\n" + "\n".join(
            violations
        )

    def test_kernel_no_http_imports(self):
        """
        Verify kernel has no HTTP/web framework imports.

        The kernel must be runtime-agnostic.
        HTTP is a transport concern, not a kernel concern.
        """
        if not KERNEL_DIR.exists():
            pytest.skip("Kernel directory not found")

        http_modules = ["fastapi", "flask", "starlette", "uvicorn", "requests", "httpx"]
        violations = []

        for file in KERNEL_DIR.rglob("*.py"):
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if any(module.startswith(http) for http in http_modules):
                        violations.append(f"{file}: from {module} import ...")

                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name
                        if any(name.startswith(http) for http in http_modules):
                            violations.append(f"{file}: import {name}")

        assert not violations, "Kernel contains HTTP imports:\n" + "\n".join(violations)

    def test_kernel_no_database_imports(self):
        """
        Verify kernel has no database imports.

        The kernel must be stateless.
        Persistence is an infrastructure concern.
        """
        if not KERNEL_DIR.exists():
            pytest.skip("Kernel directory not found")

        db_modules = ["sqlalchemy", "psycopg", "pymongo", "redis", "sqlite3"]
        violations = []

        for file in KERNEL_DIR.rglob("*.py"):
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if any(module.startswith(db) for db in db_modules):
                        violations.append(f"{file}: from {module} import ...")

                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name
                        if any(name.startswith(db) for db in db_modules):
                            violations.append(f"{file}: import {name}")

        assert not violations, "Kernel contains database imports:\n" + "\n".join(
            violations
        )


class TestProtocolImportBoundary:
    """Tests that protocol layer stays pure."""

    def test_protocol_no_sdk_imports(self):
        """
        Verify protocol layer doesn't import SDK.

        Protocol defines types and contracts.
        SDK provides convenience wrappers.
        Protocol must not depend on SDK.
        """
        protocol_dirs = [
            Path("trigguard/protocol"),
            Path("trigguard/grants"),
        ]

        forbidden = ["trigguard.sdk", "trigguard.server"]
        violations = []

        for protocol_dir in protocol_dirs:
            if not protocol_dir.exists():
                continue

            for file in protocol_dir.rglob("*.py"):
                try:
                    tree = ast.parse(file.read_text(encoding="utf-8"))
                except SyntaxError:
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        if any(module.startswith(prefix) for prefix in forbidden):
                            violations.append(f"{file}: from {module} import ...")

        assert not violations, "Protocol imports SDK/server:\n" + "\n".join(violations)


class TestVerificationImportBoundary:
    """Tests that verification layer stays minimal."""

    def test_verification_no_server_imports(self):
        """
        Verify verification layer doesn't import server.

        Verification should be usable anywhere:
        - in agents
        - in CLIs
        - in other servers

        It must not depend on our server implementation.
        """
        verification_dir = Path("trigguard/verification")
        if not verification_dir.exists():
            pytest.skip("Verification directory not found")

        forbidden = ["trigguard.server", "fastapi", "uvicorn"]
        violations = []

        for file in verification_dir.rglob("*.py"):
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if any(module.startswith(prefix) for prefix in forbidden):
                        violations.append(f"{file}: from {module} import ...")

        assert not violations, "Verification imports server:\n" + "\n".join(violations)


class TestExecutorImportBoundary:
    """Tests that executor layer stays minimal."""

    def test_executor_no_server_imports(self):
        """
        Verify executor doesn't import server.

        Executor should be embeddable in any runtime.
        It must not depend on HTTP/server code.
        """
        executor_dir = Path("trigguard/executor")
        if not executor_dir.exists():
            pytest.skip("Executor directory not found")

        forbidden = ["trigguard.server", "fastapi", "uvicorn", "starlette"]
        violations = []

        for file in executor_dir.rglob("*.py"):
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if any(module.startswith(prefix) for prefix in forbidden):
                        violations.append(f"{file}: from {module} import ...")

        assert not violations, "Executor imports server:\n" + "\n".join(violations)
