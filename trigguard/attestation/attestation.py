"""
TrigGuard Surface Attestation

Cryptographic attestation that binds execution surfaces to their implementations.

An attestation proves:
1. Which surface was invoked
2. Which code version executed
3. Which runtime produced the decision

This creates verifiable execution contracts that:
- Tools cannot silently change behavior
- Policy decisions are reproducible
- Receipts prove exact runtime state

Usage:
    from trigguard.attestation import SurfaceAttestation, AttestationRegistry

    # Register attestation for a surface
    registry = AttestationRegistry()
    registry.register(
        surface_id="trigguard.spend.transfer",
        func=transfer_funds,
    )

    # Get attestation
    attestation = registry.get("trigguard.spend.transfer")
    print(attestation.code_hash)  # sha256:6ab3c...

    # Verify attestation
    valid = verify_attestation(attestation, expected_hash)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Type
import platform
import sys

from trigguard._version import __version__
from trigguard.attestation.surface_hash import (
    compute_surface_hash,
    compute_class_hash,
    compute_combined_hash,
    HashAlgorithm,
    verify_hash,
)


class AttestationError(Exception):
    """Base exception for attestation errors."""

    pass


class AttestationMismatchError(AttestationError):
    """Raised when attestation verification fails."""

    def __init__(self, surface_id: str, expected: str, actual: str):
        self.surface_id = surface_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Attestation mismatch for {surface_id}: "
            f"expected {expected[:20]}..., got {actual[:20]}..."
        )


@dataclass(frozen=True)
class RuntimeInfo:
    """Information about the runtime environment."""

    name: str = "trigguard-runtime"
    version: str = __version__
    python_version: str = field(default_factory=lambda: platform.python_version())
    platform: str = field(default_factory=lambda: platform.system())

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "python_version": self.python_version,
            "platform": self.platform,
        }

    @property
    def fingerprint(self) -> str:
        """Unique identifier for this runtime configuration."""
        return f"{self.name}@{self.version}"


@dataclass
class SurfaceAttestation:
    """
    Cryptographic attestation for an execution surface.

    Binds a surface ID to:
    - The code hash of its implementation
    - The runtime that produced the attestation
    - Timestamp of attestation creation
    """

    surface_id: str
    code_hash: str
    runtime_version: str = __version__
    runtime_name: str = "trigguard-runtime"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def runtime_fingerprint(self) -> str:
        """Combined runtime identifier."""
        return f"{self.runtime_name}@{self.runtime_version}"

    @property
    def short_hash(self) -> str:
        """Short form of code hash (first 12 chars of digest)."""
        if ":" in self.code_hash:
            algo, digest = self.code_hash.split(":", 1)
            return f"{algo}:{digest[:12]}"
        return self.code_hash[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Export attestation as dictionary."""
        return {
            "surface_id": self.surface_id,
            "code_hash": self.code_hash,
            "runtime": {
                "name": self.runtime_name,
                "version": self.runtime_version,
            },
            "created_at": self.created_at.isoformat(),
            "algorithm": self.algorithm.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SurfaceAttestation":
        """Create attestation from dictionary."""
        runtime = data.get("runtime", {})
        return cls(
            surface_id=data["surface_id"],
            code_hash=data["code_hash"],
            runtime_version=runtime.get("version", __version__),
            runtime_name=runtime.get("name", "trigguard-runtime"),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if "created_at" in data
                else datetime.now(timezone.utc)
            ),
            algorithm=HashAlgorithm(data.get("algorithm", "sha256")),
            metadata=data.get("metadata", {}),
        )


class AttestationRegistry:
    """
    Registry of surface attestations.

    Maintains mapping between surface IDs and their code attestations.
    Enables verification that surfaces are implemented correctly.
    """

    _global_registry: Optional["AttestationRegistry"] = None

    def __init__(self):
        self._attestations: Dict[str, SurfaceAttestation] = {}
        self._runtime_info = RuntimeInfo()

    @classmethod
    def get_global(cls) -> "AttestationRegistry":
        """Get the global attestation registry."""
        if cls._global_registry is None:
            cls._global_registry = cls()
        return cls._global_registry

    def register(
        self,
        surface_id: str,
        func: Optional[Callable[..., Any]] = None,
        cls: Optional[Type[Any]] = None,
        code_hash: Optional[str] = None,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SurfaceAttestation:
        """
        Register an attestation for a surface.

        Either provide a function/class to hash, or a pre-computed code_hash.

        Args:
            surface_id: The surface identifier
            func: Function implementing the surface
            cls: Class implementing the surface
            code_hash: Pre-computed code hash
            algorithm: Hash algorithm to use
            metadata: Additional metadata

        Returns:
            The created SurfaceAttestation
        """
        if code_hash is None:
            if func is not None:
                code_hash = compute_surface_hash(func, algorithm=algorithm)
            elif cls is not None:
                code_hash = compute_class_hash(cls, algorithm=algorithm)
            else:
                raise ValueError("Must provide func, cls, or code_hash")

        attestation = SurfaceAttestation(
            surface_id=surface_id,
            code_hash=code_hash,
            runtime_version=self._runtime_info.version,
            runtime_name=self._runtime_info.name,
            algorithm=algorithm,
            metadata=metadata or {},
        )

        self._attestations[surface_id] = attestation
        return attestation

    def register_combined(
        self,
        surface_id: str,
        *items: Any,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SurfaceAttestation:
        """
        Register attestation from multiple code items.

        Args:
            surface_id: The surface identifier
            *items: Functions, classes, or strings to combine
            algorithm: Hash algorithm
            metadata: Additional metadata

        Returns:
            The created SurfaceAttestation
        """
        code_hash = compute_combined_hash(*items, algorithm=algorithm)
        return self.register(
            surface_id=surface_id,
            code_hash=code_hash,
            algorithm=algorithm,
            metadata=metadata,
        )

    def get(self, surface_id: str) -> Optional[SurfaceAttestation]:
        """Get attestation for a surface."""
        return self._attestations.get(surface_id)

    def get_or_raise(self, surface_id: str) -> SurfaceAttestation:
        """Get attestation or raise if not found."""
        attestation = self.get(surface_id)
        if attestation is None:
            raise AttestationError(f"No attestation for surface: {surface_id}")
        return attestation

    def exists(self, surface_id: str) -> bool:
        """Check if attestation exists for surface."""
        return surface_id in self._attestations

    def list_all(self) -> List[SurfaceAttestation]:
        """List all registered attestations."""
        return list(self._attestations.values())

    def list_surface_ids(self) -> List[str]:
        """List all attested surface IDs."""
        return list(self._attestations.keys())

    def verify(
        self,
        surface_id: str,
        func: Optional[Callable[..., Any]] = None,
        expected_hash: Optional[str] = None,
    ) -> bool:
        """
        Verify attestation for a surface.

        Args:
            surface_id: Surface to verify
            func: Function to verify against (computes hash)
            expected_hash: Expected hash to verify against

        Returns:
            True if attestation matches

        Raises:
            AttestationMismatchError: If verification fails
            AttestationError: If no attestation exists
        """
        attestation = self.get_or_raise(surface_id)

        if func is not None:
            computed = compute_surface_hash(func, algorithm=attestation.algorithm)
            if computed != attestation.code_hash:
                raise AttestationMismatchError(
                    surface_id, attestation.code_hash, computed
                )
        elif expected_hash is not None:
            if attestation.code_hash != expected_hash:
                raise AttestationMismatchError(
                    surface_id, expected_hash, attestation.code_hash
                )

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Export all attestations as dictionary."""
        return {
            "runtime": self._runtime_info.to_dict(),
            "attestations": {
                surface_id: att.to_dict()
                for surface_id, att in self._attestations.items()
            },
        }

    def clear(self) -> None:
        """Clear all attestations."""
        self._attestations.clear()


# ============================================================================
# Convenience Functions
# ============================================================================


def verify_attestation(
    attestation: SurfaceAttestation,
    expected_hash: str,
) -> bool:
    """
    Verify that attestation matches expected hash.

    Args:
        attestation: The attestation to verify
        expected_hash: Expected code hash

    Returns:
        True if hashes match
    """
    return attestation.code_hash == expected_hash


def get_runtime_attestation() -> RuntimeInfo:
    """Get attestation of the current runtime environment."""
    return RuntimeInfo()


def attest_surface(surface_id: str, func: Callable[..., Any]) -> SurfaceAttestation:
    """
    Create and register attestation for a surface.

    Convenience function that uses the global registry.

    Args:
        surface_id: Surface identifier
        func: Function implementing the surface

    Returns:
        The created attestation
    """
    return AttestationRegistry.get_global().register(surface_id, func=func)


def get_surface_attestation(surface_id: str) -> Optional[SurfaceAttestation]:
    """
    Get attestation for a surface from global registry.

    Args:
        surface_id: Surface identifier

    Returns:
        Attestation or None if not found
    """
    return AttestationRegistry.get_global().get(surface_id)
