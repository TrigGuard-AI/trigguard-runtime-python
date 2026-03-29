"""
Tests for Surface Attestation Verifier

Tests the runtime verification of surface attestation hashes.
"""

import pytest

from trigguard.attestation import (
    AttestationRegistry,
    SurfaceAttestation,
    SurfaceAttestationVerifier,
    AttestationVerificationError,
    HashMismatchError,
    SurfaceNotAttestedError,
)


class TestSurfaceAttestationVerifier:
    """Tests for SurfaceAttestationVerifier."""

    def test_verify_matching_hash(self):
        """Matching hash passes verification."""
        registry = AttestationRegistry()
        registry.register(
            surface_id="test.surface",
            code_hash="sha256:abc123",
        )

        verifier = SurfaceAttestationVerifier(registry=registry)
        result = verifier.verify(
            surface_id="test.surface",
            expected_hash="sha256:abc123",
        )

        assert result.valid is True
        assert result.actual_hash == "sha256:abc123"

    def test_verify_mismatched_hash(self):
        """Mismatched hash fails verification."""
        registry = AttestationRegistry()
        registry.register(
            surface_id="test.surface",
            code_hash="sha256:actual_hash",
        )

        verifier = SurfaceAttestationVerifier(registry=registry, strict=False)
        result = verifier.verify(
            surface_id="test.surface",
            expected_hash="sha256:expected_hash",
        )

        assert result.valid is False
        assert "mismatch" in result.error.lower()

    def test_verify_strict_raises(self):
        """Strict mode raises on mismatch."""
        registry = AttestationRegistry()
        registry.register(
            surface_id="test.surface",
            code_hash="sha256:actual",
        )

        verifier = SurfaceAttestationVerifier(registry=registry, strict=True)

        with pytest.raises(HashMismatchError):
            verifier.verify(
                surface_id="test.surface",
                expected_hash="sha256:expected",
            )

    def test_verify_no_attestation_lenient(self):
        """Missing attestation passes when not required."""
        registry = AttestationRegistry()
        verifier = SurfaceAttestationVerifier(
            registry=registry,
            require_attestation=False,
        )

        result = verifier.verify(surface_id="unknown.surface")
        assert result.valid is True

    def test_verify_no_attestation_strict(self):
        """Missing attestation fails when required."""
        registry = AttestationRegistry()
        verifier = SurfaceAttestationVerifier(
            registry=registry,
            require_attestation=True,
            strict=False,
        )

        result = verifier.verify(surface_id="unknown.surface")
        assert result.valid is False

    def test_verify_no_attestation_raises(self):
        """Missing attestation raises when required and strict."""
        registry = AttestationRegistry()
        verifier = SurfaceAttestationVerifier(
            registry=registry,
            require_attestation=True,
            strict=True,
        )

        with pytest.raises(SurfaceNotAttestedError):
            verifier.verify(surface_id="unknown.surface")

    def test_verify_without_expected_hash(self):
        """Verification without expected hash checks attestation exists."""
        registry = AttestationRegistry()
        registry.register(
            surface_id="test.surface",
            code_hash="sha256:abc123",
        )

        verifier = SurfaceAttestationVerifier(registry=registry)
        result = verifier.verify(surface_id="test.surface")

        assert result.valid is True
        assert result.actual_hash == "sha256:abc123"

    def test_verify_batch(self):
        """Batch verification works."""
        registry = AttestationRegistry()
        registry.register("surface.a", code_hash="sha256:aaa")
        registry.register("surface.b", code_hash="sha256:bbb")

        verifier = SurfaceAttestationVerifier(registry=registry, strict=False)
        results = verifier.verify_batch(
            {
                "surface.a": "sha256:aaa",  # Match
                "surface.b": "sha256:xxx",  # Mismatch
            }
        )

        assert results["surface.a"].valid is True
        assert results["surface.b"].valid is False


class TestVerifierIntegration:
    """Integration tests for verifier with executor patterns."""

    def test_executor_style_verification(self):
        """Test verifier in executor-style workflow."""
        registry = AttestationRegistry()
        registry.register(
            surface_id="trigguard.spend.transfer",
            code_hash="sha256:transfer_implementation_hash",
        )

        verifier = SurfaceAttestationVerifier(
            registry=registry,
            strict=True,
            require_attestation=True,
        )

        # Simulate grant with surface_hash
        class MockGrant:
            surface = "trigguard.spend.transfer"
            surface_hash = "sha256:transfer_implementation_hash"

        grant = MockGrant()

        # Verify grant attestation
        result = verifier.verify_grant(grant)
        assert result.valid is True

    def test_tampering_detection(self):
        """Verify detects code tampering."""
        registry = AttestationRegistry()
        registry.register(
            surface_id="trigguard.spend.transfer",
            code_hash="sha256:original_code_hash",
        )

        verifier = SurfaceAttestationVerifier(
            registry=registry,
            strict=True,
        )

        # Grant was issued with different code
        class TamperedGrant:
            surface = "trigguard.spend.transfer"
            surface_hash = "sha256:tampered_code_hash"

        with pytest.raises(HashMismatchError) as exc:
            verifier.verify_grant(TamperedGrant())

        assert exc.value.surface_id == "trigguard.spend.transfer"
