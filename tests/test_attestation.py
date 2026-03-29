"""
Tests for Surface Attestation

Tests cryptographic binding between surfaces and their implementations.
"""

import pytest
from datetime import datetime, timezone

from trigguard.attestation import (
    compute_surface_hash,
    SurfaceAttestation,
    AttestationRegistry,
    verify_attestation,
    attest_surface,
    get_surface_attestation,
    HashAlgorithm,
)
from trigguard.attestation.attestation import (
    AttestationError,
    AttestationMismatchError,
    RuntimeInfo,
)

# ============================================================================
# Test Fixtures
# ============================================================================


def sample_function():
    """A sample function for testing."""
    return "hello"


def sample_function_v2():
    """Same logic, different code."""
    return "hello"


def complex_function(x: int, y: int) -> int:
    """
    A more complex function.

    With multiple lines and computations.
    """
    result = x + y
    result = result * 2
    return result


class SampleClass:
    """Sample class for testing."""

    def __init__(self, value: int):
        self.value = value

    def compute(self) -> int:
        return self.value * 2


# ============================================================================
# Surface Hash Tests
# ============================================================================


class TestComputeSurfaceHash:
    """Tests for hash computation."""

    def test_basic_hash(self):
        """Basic function hashing works."""
        hash_value = compute_surface_hash(sample_function)
        assert hash_value.startswith("sha256:")
        assert len(hash_value) == 64 + 7  # sha256: prefix + hex digest

    def test_deterministic(self):
        """Same function produces same hash."""
        hash1 = compute_surface_hash(sample_function)
        hash2 = compute_surface_hash(sample_function)
        assert hash1 == hash2

    def test_different_functions_different_hashes(self):
        """Different functions produce different hashes."""
        hash1 = compute_surface_hash(sample_function)
        hash2 = compute_surface_hash(sample_function_v2)
        assert hash1 != hash2

    def test_complex_function(self):
        """Complex functions hash correctly."""
        hash_value = compute_surface_hash(complex_function)
        assert hash_value.startswith("sha256:")

    def test_algorithm_sha384(self):
        """SHA-384 algorithm works."""
        hash_value = compute_surface_hash(
            sample_function, algorithm=HashAlgorithm.SHA384
        )
        assert hash_value.startswith("sha384:")
        assert len(hash_value) == 96 + 7  # sha384: prefix + hex digest

    def test_algorithm_sha512(self):
        """SHA-512 algorithm works."""
        hash_value = compute_surface_hash(
            sample_function, algorithm=HashAlgorithm.SHA512
        )
        assert hash_value.startswith("sha512:")
        assert len(hash_value) == 128 + 7  # sha512: prefix + hex digest


# ============================================================================
# Surface Attestation Tests
# ============================================================================


class TestSurfaceAttestation:
    """Tests for SurfaceAttestation dataclass."""

    def test_create_attestation(self):
        """Create attestation with defaults."""
        attestation = SurfaceAttestation(
            surface_id="test.surface",
            code_hash="sha256:abc123",
        )
        assert attestation.surface_id == "test.surface"
        assert attestation.code_hash == "sha256:abc123"
        assert attestation.runtime_name == "trigguard-runtime"

    def test_short_hash(self):
        """Short hash format works."""
        attestation = SurfaceAttestation(
            surface_id="test.surface",
            code_hash="sha256:abcdef123456789012345678901234567890",
        )
        assert attestation.short_hash == "sha256:abcdef123456"

    def test_runtime_fingerprint(self):
        """Runtime fingerprint combines name and version."""
        attestation = SurfaceAttestation(
            surface_id="test.surface",
            code_hash="sha256:abc123",
            runtime_name="test-runtime",
            runtime_version="1.2.3",
        )
        assert attestation.runtime_fingerprint == "test-runtime@1.2.3"

    def test_to_dict(self):
        """Export to dictionary."""
        attestation = SurfaceAttestation(
            surface_id="test.surface",
            code_hash="sha256:abc123",
        )
        data = attestation.to_dict()
        assert data["surface_id"] == "test.surface"
        assert data["code_hash"] == "sha256:abc123"
        assert "runtime" in data
        assert "created_at" in data

    def test_from_dict(self):
        """Import from dictionary."""
        data = {
            "surface_id": "test.surface",
            "code_hash": "sha256:abc123",
            "runtime": {"name": "test", "version": "1.0"},
            "created_at": "2026-03-28T12:00:00+00:00",
            "algorithm": "sha256",
        }
        attestation = SurfaceAttestation.from_dict(data)
        assert attestation.surface_id == "test.surface"
        assert attestation.code_hash == "sha256:abc123"

    def test_roundtrip(self):
        """Export and import preserve data."""
        original = SurfaceAttestation(
            surface_id="test.surface",
            code_hash="sha256:abc123",
            metadata={"key": "value"},
        )
        exported = original.to_dict()
        restored = SurfaceAttestation.from_dict(exported)
        assert restored.surface_id == original.surface_id
        assert restored.code_hash == original.code_hash


# ============================================================================
# Attestation Registry Tests
# ============================================================================


class TestAttestationRegistry:
    """Tests for AttestationRegistry."""

    def test_register_function(self):
        """Register attestation from function."""
        registry = AttestationRegistry()
        attestation = registry.register(
            surface_id="test.surface",
            func=sample_function,
        )
        assert attestation.surface_id == "test.surface"
        assert attestation.code_hash.startswith("sha256:")

    def test_register_class(self):
        """Register attestation from class."""
        registry = AttestationRegistry()
        attestation = registry.register(
            surface_id="test.class",
            cls=SampleClass,
        )
        assert attestation.surface_id == "test.class"
        assert attestation.code_hash.startswith("sha256:")

    def test_register_precomputed_hash(self):
        """Register with pre-computed hash."""
        registry = AttestationRegistry()
        attestation = registry.register(
            surface_id="test.surface",
            code_hash="sha256:precomputed123",
        )
        assert attestation.code_hash == "sha256:precomputed123"

    def test_register_requires_input(self):
        """Register fails without func, cls, or hash."""
        registry = AttestationRegistry()
        with pytest.raises(ValueError):
            registry.register(surface_id="test.surface")

    def test_get_attestation(self):
        """Retrieve registered attestation."""
        registry = AttestationRegistry()
        registry.register("test.surface", func=sample_function)
        attestation = registry.get("test.surface")
        assert attestation is not None
        assert attestation.surface_id == "test.surface"

    def test_get_missing(self):
        """Get returns None for missing surface."""
        registry = AttestationRegistry()
        assert registry.get("nonexistent") is None

    def test_get_or_raise(self):
        """Get or raise throws for missing surface."""
        registry = AttestationRegistry()
        with pytest.raises(AttestationError):
            registry.get_or_raise("nonexistent")

    def test_exists(self):
        """Check existence of attestation."""
        registry = AttestationRegistry()
        registry.register("test.surface", func=sample_function)
        assert registry.exists("test.surface") is True
        assert registry.exists("other.surface") is False

    def test_list_all(self):
        """List all attestations."""
        registry = AttestationRegistry()
        registry.register("test.a", func=sample_function)
        registry.register("test.b", func=sample_function_v2)
        attestations = registry.list_all()
        assert len(attestations) == 2

    def test_list_surface_ids(self):
        """List all attested surface IDs."""
        registry = AttestationRegistry()
        registry.register("test.a", func=sample_function)
        registry.register("test.b", func=sample_function_v2)
        surface_ids = registry.list_surface_ids()
        assert "test.a" in surface_ids
        assert "test.b" in surface_ids

    def test_verify_with_function(self):
        """Verify attestation against function."""
        registry = AttestationRegistry()
        registry.register("test.surface", func=sample_function)
        assert registry.verify("test.surface", func=sample_function) is True

    def test_verify_mismatch(self):
        """Verify fails for different function."""
        registry = AttestationRegistry()
        registry.register("test.surface", func=sample_function)
        with pytest.raises(AttestationMismatchError):
            registry.verify("test.surface", func=sample_function_v2)

    def test_verify_with_hash(self):
        """Verify attestation against expected hash."""
        registry = AttestationRegistry()
        attestation = registry.register("test.surface", func=sample_function)
        assert (
            registry.verify("test.surface", expected_hash=attestation.code_hash) is True
        )

    def test_to_dict(self):
        """Export registry to dictionary."""
        registry = AttestationRegistry()
        registry.register("test.surface", func=sample_function)
        data = registry.to_dict()
        assert "runtime" in data
        assert "attestations" in data
        assert "test.surface" in data["attestations"]

    def test_clear(self):
        """Clear all attestations."""
        registry = AttestationRegistry()
        registry.register("test.surface", func=sample_function)
        registry.clear()
        assert registry.list_all() == []


# ============================================================================
# Convenience Function Tests
# ============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_verify_attestation(self):
        """Verify attestation helper function."""
        attestation = SurfaceAttestation(
            surface_id="test.surface",
            code_hash="sha256:abc123",
        )
        assert verify_attestation(attestation, "sha256:abc123") is True
        assert verify_attestation(attestation, "sha256:different") is False

    def test_attest_surface(self):
        """Attest surface using global registry."""
        # Clear global state first
        AttestationRegistry._global_registry = None

        attestation = attest_surface("global.test", sample_function)
        assert attestation.surface_id == "global.test"

        # Verify it's in global registry
        retrieved = get_surface_attestation("global.test")
        assert retrieved is not None
        assert retrieved.code_hash == attestation.code_hash


# ============================================================================
# Runtime Info Tests
# ============================================================================


class TestRuntimeInfo:
    """Tests for RuntimeInfo."""

    def test_default_values(self):
        """RuntimeInfo has sensible defaults."""
        info = RuntimeInfo()
        assert info.name == "trigguard-runtime"
        assert info.python_version is not None
        assert info.platform is not None

    def test_to_dict(self):
        """Export to dictionary."""
        info = RuntimeInfo()
        data = info.to_dict()
        assert "name" in data
        assert "version" in data
        assert "python_version" in data
        assert "platform" in data

    def test_fingerprint(self):
        """Fingerprint format is correct."""
        info = RuntimeInfo(name="test", version="1.0.0")
        assert info.fingerprint == "test@1.0.0"


# ============================================================================
# Integration Tests
# ============================================================================


class TestAttestationIntegration:
    """Integration tests for attestation workflow."""

    def test_full_attestation_workflow(self):
        """Complete attestation workflow."""
        # 1. Register surface with attestation
        registry = AttestationRegistry()
        attestation = registry.register(
            surface_id="trigguard.test.transfer",
            func=complex_function,
            metadata={"owner": "test"},
        )

        # 2. Verify attestation matches
        assert registry.verify("trigguard.test.transfer", func=complex_function)

        # 3. Export for external verification
        exported = attestation.to_dict()
        assert exported["surface_id"] == "trigguard.test.transfer"
        assert exported["code_hash"].startswith("sha256:")
        assert exported["metadata"]["owner"] == "test"

        # 4. Restore attestation
        restored = SurfaceAttestation.from_dict(exported)
        assert restored.code_hash == attestation.code_hash

    def test_tampering_detection(self):
        """Changed code is detected."""
        registry = AttestationRegistry()

        # Register original
        original = registry.register(
            surface_id="trigguard.protected",
            func=sample_function,
        )

        # Try to verify with modified function
        with pytest.raises(AttestationMismatchError) as exc_info:
            registry.verify("trigguard.protected", func=sample_function_v2)

        error = exc_info.value
        assert error.surface_id == "trigguard.protected"
        assert error.expected != error.actual
