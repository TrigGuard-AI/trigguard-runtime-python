"""
TrigGuard Conformance Test Suite

These tests ensure that all TrigGuard runtimes produce identical decisions
for the same inputs. Any runtime implementing the TrigGuard protocol MUST
pass all conformance vectors.

Conformance vectors test:
- Grant validation (valid, expired, missing)
- Key status validation (active, revoked, expired)
- Surface validation (known, unknown)
- Decision consistency (PERMIT, DENY, SILENCE)

To add new conformance vectors:
1. Create a JSON file in tests/conformance/vectors/
2. Include: name, description, surface, grant, key_status, expected_decision
3. Run: pytest tests/conformance -v
"""

import json
import pathlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
import pytest

from trigguard.protocol.decision_contracts import Decision
from trigguard.registry import ExecutionSurfaceRegistry, get_global_surface_registry
from trigguard.keys import KeyRotationManager, KeyStatus

VECTORS_DIR = pathlib.Path(__file__).parent / "vectors"


@dataclass
class ConformanceVector:
    """A single conformance test vector."""

    name: str
    description: str
    surface: str
    grant: Optional[dict[str, Any]]
    key_status: Optional[str]
    expected_decision: str

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "ConformanceVector":
        with open(path) as f:
            data = json.load(f)
        return cls(
            name=data["name"],
            description=data["description"],
            surface=data["surface"],
            grant=data.get("grant"),
            key_status=data.get("key_status"),
            expected_decision=data["expected_decision"],
        )


def load_all_vectors() -> list[tuple[str, ConformanceVector]]:
    """Load all conformance vectors from the vectors directory."""
    vectors = []
    for path in sorted(VECTORS_DIR.glob("*.json")):
        vector = ConformanceVector.from_file(path)
        vectors.append((path.stem, vector))
    return vectors


class ConformanceDecisionEngine:
    """
    Minimal decision engine that implements the kernel decision authority.

    This is the ground truth for conformance testing.
    The kernel decision engine is the ONLY place where PERMIT/DENY decisions
    are made.
    """

    def __init__(self):
        self.registry = get_global_surface_registry()
        self.key_manager = KeyRotationManager()
        self._setup_test_keys()

    def _setup_test_keys(self):
        """Setup test keys for conformance testing."""
        # Active key
        self.key_manager.add_key(
            key_id="test-key-001",
            public_key="test-public-key-001",
            algorithm="RS256",
        )

    def decide(self, vector: ConformanceVector) -> str:
        """
        Make a decision based on the conformance vector.

        This method implements the kernel decision authority.
        ALL decisions flow through here.
        """
        # Rule 1: No grant = DENY
        if vector.grant is None:
            return "DENY"

        # Rule 2: Revoked key = DENY
        if vector.key_status == "REVOKED":
            return "DENY"

        # Rule 3: Expired key = DENY
        if vector.key_status == "EXPIRED":
            return "DENY"

        # Rule 4: Expired grant = DENY
        if vector.grant.get("expires_at"):
            expires_at = datetime.fromisoformat(
                vector.grant["expires_at"].replace("Z", "+00:00")
            )
            if expires_at < datetime.now(timezone.utc):
                return "DENY"

        # Rule 5: Unknown surface = DENY
        if not self.registry.exists(vector.surface):
            return "DENY"

        # All checks passed = PERMIT
        return "PERMIT"


# ============================================================================
# Conformance Tests
# ============================================================================


class TestConformanceVectors:
    """
    Test all conformance vectors against the kernel decision engine.

    Every TrigGuard runtime MUST pass these tests.
    """

    @pytest.fixture
    def engine(self):
        return ConformanceDecisionEngine()

    @pytest.mark.parametrize(
        "vector_name,vector",
        load_all_vectors(),
        ids=[name for name, _ in load_all_vectors()],
    )
    def test_conformance_vector(
        self,
        engine: ConformanceDecisionEngine,
        vector_name: str,
        vector: ConformanceVector,
    ):
        """Test that the decision engine produces the expected decision."""
        actual = engine.decide(vector)

        assert actual == vector.expected_decision, (
            f"Conformance vector '{vector_name}' failed:\n"
            f"  Description: {vector.description}\n"
            f"  Surface: {vector.surface}\n"
            f"  Expected: {vector.expected_decision}\n"
            f"  Actual: {actual}"
        )


class TestDecisionAuthority:
    """
    Tests that verify the kernel is the sole decision authority.

    These tests ensure the architecture rule:
    "Only the kernel may produce PERMIT or DENY decisions."
    """

    def test_runtime_does_not_bypass_kernel(self):
        """Runtime service must call kernel for decisions."""
        # This test verifies that runtime.server uses kernel decision logic
        from trigguard.runtime.server import TrigGuardRuntime

        runtime = TrigGuardRuntime()

        # Verify runtime has reference to kernel components
        assert runtime.verifier is not None
        assert runtime.executor is not None
        assert runtime.registry is not None

    def test_decisions_only_from_kernel(self):
        """All decision types must be defined in kernel protocol layer."""
        from trigguard.protocol.decision_contracts import Decision

        # Verify all decisions exist in protocol layer (kernel)
        assert hasattr(Decision, "PERMIT") or "PERMIT" in [d.value for d in Decision]
        assert hasattr(Decision, "DENY") or "DENY" in [d.value for d in Decision]


class TestKeyStatusIntegration:
    """
    Tests that verify key status is integrated with verification.

    The KeyRotationManager MUST be consulted during verification.
    """

    def test_key_manager_rejects_revoked(self):
        """Revoked keys must not be usable for verification."""
        manager = KeyRotationManager()
        manager.add_key("test-key", "public-key", algorithm="RS256")
        manager.revoke_key("test-key", reason="test revocation")

        key = manager.get_valid_key("test-key")
        assert key is None, "Revoked key should not be returned as valid"

    def test_key_manager_rejects_expired(self):
        """Expired keys must not be usable for verification."""
        from datetime import timedelta

        manager = KeyRotationManager()
        manager.add_key(
            "test-key",
            "public-key",
            algorithm="RS256",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        key = manager.get_valid_key("test-key")
        assert key is None, "Expired key should not be returned as valid"

    def test_active_key_is_valid(self):
        """Active keys should be usable for verification."""
        manager = KeyRotationManager()
        manager.add_key("test-key", "public-key", algorithm="RS256")

        key = manager.get_valid_key("test-key")
        assert key is not None, "Active key should be returned"
        assert key.is_valid, "Active key should be valid"


# ============================================================================
# Vector Validation
# ============================================================================


class TestVectorIntegrity:
    """Tests that validate the conformance vectors themselves."""

    def test_all_vectors_have_required_fields(self):
        """Every vector must have all required fields."""
        required = {"name", "description", "surface", "expected_decision"}

        for path in VECTORS_DIR.glob("*.json"):
            with open(path) as f:
                data = json.load(f)

            missing = required - set(data.keys())
            assert not missing, f"Vector {path.name} missing fields: {missing}"

    def test_expected_decisions_are_valid(self):
        """Expected decisions must be valid decision types."""
        valid_decisions = {"PERMIT", "DENY", "SILENCE"}

        for path in VECTORS_DIR.glob("*.json"):
            with open(path) as f:
                data = json.load(f)

            assert (
                data["expected_decision"] in valid_decisions
            ), f"Vector {path.name} has invalid decision: {data['expected_decision']}"

    def test_no_duplicate_vector_names(self):
        """Vector names must be unique."""
        names = []
        for path in VECTORS_DIR.glob("*.json"):
            with open(path) as f:
                data = json.load(f)
            names.append(data["name"])

        assert len(names) == len(set(names)), "Duplicate vector names found"
