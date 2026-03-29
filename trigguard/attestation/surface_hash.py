"""
TrigGuard Surface Hash Computation

Computes deterministic cryptographic fingerprints of code that implements
execution surfaces. This enables verifiable binding between surface IDs
and actual implementation.

The hash computation:
1. Extracts source code using inspect module
2. Normalizes whitespace and comments (optional)
3. Computes SHA-256 hash of the normalized source
4. Returns prefixed hash string (e.g., "sha256:6ab3c...")

Security properties:
- Deterministic: same code always produces same hash
- Collision-resistant: different code produces different hashes
- Tamper-evident: any change in code changes the hash
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, Type, Union
import ast
import hashlib
import inspect
import re
import sys


class HashAlgorithm(Enum):
    """Supported hash algorithms for surface attestation."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


@dataclass
class HashResult:
    """Result of hash computation."""

    algorithm: HashAlgorithm
    digest: str
    source_lines: int
    normalized: bool

    @property
    def prefixed(self) -> str:
        """Get hash with algorithm prefix (e.g., sha256:abc123...)."""
        return f"{self.algorithm.value}:{self.digest}"

    def __str__(self) -> str:
        return self.prefixed


def compute_surface_hash(
    func: Callable[..., Any],
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    normalize: bool = True,
    include_decorators: bool = False,
) -> str:
    """
    Compute cryptographic hash of a function's source code.

    This creates a deterministic fingerprint of the code implementing
    an execution surface, enabling verifiable attestation.

    Args:
        func: The function to hash
        algorithm: Hash algorithm to use (default: SHA-256)
        normalize: Whether to normalize whitespace/comments
        include_decorators: Whether to include decorator source

    Returns:
        Prefixed hash string (e.g., "sha256:6ab3c...")

    Example:
        >>> def transfer_funds(amount: float):
        ...     bank.transfer(amount)
        >>> hash = compute_surface_hash(transfer_funds)
        >>> print(hash)
        sha256:a1b2c3d4...
    """
    try:
        source = inspect.getsource(func)
    except (TypeError, OSError) as e:
        raise ValueError(f"Cannot get source for {func.__name__}: {e}")

    # Optionally strip decorators
    if not include_decorators:
        source = _strip_decorators(source)

    # Normalize if requested
    if normalize:
        source = _normalize_source(source)

    # Compute hash
    hasher = _get_hasher(algorithm)
    hasher.update(source.encode("utf-8"))
    digest = hasher.hexdigest()

    return f"{algorithm.value}:{digest}"


def compute_surface_hash_detailed(
    func: Callable[..., Any],
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    normalize: bool = True,
) -> HashResult:
    """
    Compute hash with detailed metadata.

    Returns a HashResult with:
    - algorithm used
    - hex digest
    - source line count
    - whether normalization was applied
    """
    try:
        source = inspect.getsource(func)
    except (TypeError, OSError) as e:
        raise ValueError(f"Cannot get source for {func.__name__}: {e}")

    original_lines = len(source.splitlines())

    if normalize:
        source = _normalize_source(source)

    hasher = _get_hasher(algorithm)
    hasher.update(source.encode("utf-8"))
    digest = hasher.hexdigest()

    return HashResult(
        algorithm=algorithm,
        digest=digest,
        source_lines=original_lines,
        normalized=normalize,
    )


def compute_module_hash(
    module: Any,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> str:
    """
    Compute hash of an entire module's source.

    Useful for attesting entire surface implementations.

    Args:
        module: The module to hash
        algorithm: Hash algorithm to use

    Returns:
        Prefixed hash string
    """
    try:
        source = inspect.getsource(module)
    except (TypeError, OSError) as e:
        raise ValueError(f"Cannot get source for module: {e}")

    hasher = _get_hasher(algorithm)
    hasher.update(source.encode("utf-8"))
    digest = hasher.hexdigest()

    return f"{algorithm.value}:{digest}"


def compute_class_hash(
    cls: Type[Any],
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    include_methods: bool = True,
) -> str:
    """
    Compute hash of a class definition.

    Args:
        cls: The class to hash
        algorithm: Hash algorithm to use
        include_methods: Whether to include all method source

    Returns:
        Prefixed hash string
    """
    try:
        source = inspect.getsource(cls)
    except (TypeError, OSError) as e:
        raise ValueError(f"Cannot get source for {cls.__name__}: {e}")

    hasher = _get_hasher(algorithm)
    hasher.update(source.encode("utf-8"))
    digest = hasher.hexdigest()

    return f"{algorithm.value}:{digest}"


def compute_combined_hash(
    *items: Union[Callable[..., Any], Type[Any], str],
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> str:
    """
    Compute combined hash of multiple items.

    Useful when a surface spans multiple functions or classes.

    Args:
        *items: Functions, classes, or raw strings to hash
        algorithm: Hash algorithm to use

    Returns:
        Prefixed hash string
    """
    hasher = _get_hasher(algorithm)

    for item in items:
        if isinstance(item, str):
            hasher.update(item.encode("utf-8"))
        elif callable(item) or isinstance(item, type):
            try:
                source = inspect.getsource(item)
                hasher.update(source.encode("utf-8"))
            except (TypeError, OSError):
                # Fall back to qualname for built-ins
                hasher.update(getattr(item, "__qualname__", str(item)).encode("utf-8"))
        else:
            hasher.update(str(item).encode("utf-8"))

    digest = hasher.hexdigest()
    return f"{algorithm.value}:{digest}"


def verify_hash(
    func: Callable[..., Any],
    expected_hash: str,
    normalize: bool = True,
) -> bool:
    """
    Verify that a function matches an expected hash.

    Args:
        func: Function to verify
        expected_hash: Expected hash string (with algorithm prefix)
        normalize: Whether to normalize source

    Returns:
        True if hashes match, False otherwise
    """
    # Parse algorithm from expected hash
    if ":" not in expected_hash:
        raise ValueError(
            "Expected hash must include algorithm prefix (e.g., sha256:...)"
        )

    algo_str, expected_digest = expected_hash.split(":", 1)

    try:
        algorithm = HashAlgorithm(algo_str)
    except ValueError:
        raise ValueError(f"Unknown hash algorithm: {algo_str}")

    computed = compute_surface_hash(func, algorithm=algorithm, normalize=normalize)
    return computed == expected_hash


# ============================================================================
# Helper Functions
# ============================================================================


def _get_hasher(algorithm: HashAlgorithm) -> "hashlib._Hash":
    """Get hashlib hasher for algorithm."""
    if algorithm == HashAlgorithm.SHA256:
        return hashlib.sha256()
    elif algorithm == HashAlgorithm.SHA384:
        return hashlib.sha384()
    elif algorithm == HashAlgorithm.SHA512:
        return hashlib.sha512()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def _normalize_source(source: str) -> str:
    """
    Normalize source code for consistent hashing.

    Removes:
    - Leading/trailing whitespace
    - Blank lines
    - Comments (single-line #)
    - Docstrings

    Preserves:
    - Functional code structure
    - Indentation relationships
    """
    lines = []
    in_docstring = False
    docstring_char = None

    for line in source.splitlines():
        stripped = line.strip()

        # Handle docstrings
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                docstring_char = stripped[:3]
                if stripped.count(docstring_char) >= 2:
                    # Single-line docstring
                    continue
                in_docstring = True
                continue
        else:
            if docstring_char and docstring_char in stripped:
                in_docstring = False
            continue

        # Skip empty lines
        if not stripped:
            continue

        # Skip comment-only lines
        if stripped.startswith("#"):
            continue

        # Remove inline comments (simple approach)
        if "#" in line and not ('"' in line or "'" in line):
            line = line.split("#")[0].rstrip()

        lines.append(line)

    return "\n".join(lines)


def _strip_decorators(source: str) -> str:
    """
    Remove decorator lines from function source.

    Keeps the function definition and body intact.
    """
    lines = source.splitlines()
    result = []
    in_decorator = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("@"):
            in_decorator = True
            continue

        if in_decorator:
            # Check if this is continuation of decorator or start of def
            if stripped.startswith("def ") or stripped.startswith("async def "):
                in_decorator = False
                result.append(line)
            continue

        result.append(line)

    return "\n".join(result)
