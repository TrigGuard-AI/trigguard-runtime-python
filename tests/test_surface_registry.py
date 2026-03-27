"""
Tests for Execution Surface Registry

Tests cover:
- Canonical surfaces preloaded
- Alias resolution
- Duplicate registration handling
- Deterministic export
- Risk tier lookup
- Unknown surface handling
"""

import json
import pytest
from datetime import datetime, timezone

from trigguard.registry.surface_types import (
    SurfaceRiskTier,
    ExecutionSurfaceDefinition,
    CANONICAL_SURFACES,
    get_canonical_surfaces,
    get_canonical_surface,
)
from trigguard.registry.surface_registry import (
    ExecutionSurfaceRegistry,
    DuplicateSurfaceError,
    UnknownSurfaceError,
    get_global_surface_registry,
    reset_global_surface_registry,
    normalize_surface,
    is_registered_surface,
    get_surface_definition,
)


class TestSurfaceRiskTier:
    """Tests for SurfaceRiskTier enum."""

    def test_tier_ordering(self):
        """Test that tiers are ordered correctly."""
        assert SurfaceRiskTier.LOW < SurfaceRiskTier.MEDIUM
        assert SurfaceRiskTier.MEDIUM < SurfaceRiskTier.HIGH
        assert SurfaceRiskTier.HIGH < SurfaceRiskTier.IRREVERSIBLE

    def test_requires_grant(self):
        """Test requires_grant property."""
        assert not SurfaceRiskTier.LOW.requires_grant
        assert not SurfaceRiskTier.MEDIUM.requires_grant
        assert SurfaceRiskTier.HIGH.requires_grant
        assert SurfaceRiskTier.IRREVERSIBLE.requires_grant

    def test_fail_closed(self):
        """Test fail_closed property."""
        assert not SurfaceRiskTier.LOW.fail_closed
        assert not SurfaceRiskTier.MEDIUM.fail_closed
        assert not SurfaceRiskTier.HIGH.fail_closed
        assert SurfaceRiskTier.IRREVERSIBLE.fail_closed


class TestExecutionSurfaceDefinition:
    """Tests for ExecutionSurfaceDefinition dataclass."""

    def test_create_surface(self):
        """Test creating a surface definition."""
        surface = ExecutionSurfaceDefinition(
            surface_id="test.spend.transfer",
            namespace="test",
            display_name="Test Transfer",
            description="A test transfer surface",
            risk_tier=SurfaceRiskTier.IRREVERSIBLE,
            reversible=False,
            tags=["test", "money"],
        )
        assert surface.surface_id == "test.spend.transfer"
        assert surface.namespace == "test"
        assert surface.risk_tier == SurfaceRiskTier.IRREVERSIBLE
        assert not surface.reversible

    def test_surface_id_validation(self):
        """Test that surface_id must be namespaced."""
        with pytest.raises(ValueError, match="must be namespaced"):
            ExecutionSurfaceDefinition(
                surface_id="invalid",
                namespace="test",
                display_name="Invalid",
                description="Missing namespace",
                risk_tier=SurfaceRiskTier.LOW,
                reversible=True,
            )

    def test_namespace_mismatch_rejected(self):
        """Test that namespace must match surface_id prefix."""
        with pytest.raises(ValueError, match="does not match"):
            ExecutionSurfaceDefinition(
                surface_id="test.spend.transfer",
                namespace="wrong",
                display_name="Wrong Namespace",
                description="Namespace mismatch",
                risk_tier=SurfaceRiskTier.LOW,
                reversible=True,
            )

    def test_to_dict(self):
        """Test serialization to dict."""
        surface = ExecutionSurfaceDefinition(
            surface_id="test.spend.transfer",
            namespace="test",
            display_name="Test Transfer",
            description="A test transfer surface",
            risk_tier=SurfaceRiskTier.IRREVERSIBLE,
            reversible=False,
            tags=["test", "money"],
        )
        data = surface.to_dict()
        assert data["surface_id"] == "test.spend.transfer"
        assert data["risk_tier"] == "irreversible"
        assert data["reversible"] is False
        assert "test" in data["tags"]

    def test_from_dict(self):
        """Test deserialization from dict."""
        data = {
            "surface_id": "test.spend.transfer",
            "namespace": "test",
            "display_name": "Test Transfer",
            "description": "A test transfer surface",
            "risk_tier": "irreversible",
            "reversible": False,
            "tags": ["test"],
        }
        surface = ExecutionSurfaceDefinition.from_dict(data)
        assert surface.surface_id == "test.spend.transfer"
        assert surface.risk_tier == SurfaceRiskTier.IRREVERSIBLE

    def test_canonical_json_is_deterministic(self):
        """Test that canonical JSON is deterministic."""
        surface = ExecutionSurfaceDefinition(
            surface_id="test.a.b",
            namespace="test",
            display_name="Test",
            description="Test",
            risk_tier=SurfaceRiskTier.LOW,
            reversible=True,
            tags=["z", "a", "m"],
        )
        json1 = surface.to_canonical_json()
        json2 = surface.to_canonical_json()
        assert json1 == json2


class TestCanonicalSurfaces:
    """Tests for preloaded canonical surfaces."""

    def test_canonical_surfaces_exist(self):
        """Test that canonical surfaces are defined."""
        surfaces = get_canonical_surfaces()
        assert len(surfaces) > 0

    def test_spend_transfer_exists(self):
        """Test spend transfer surface exists."""
        surface = get_canonical_surface("trigguard.spend.transfer")
        assert surface is not None
        assert surface.risk_tier == SurfaceRiskTier.IRREVERSIBLE
        assert not surface.reversible

    def test_code_exec_exists(self):
        """Test code execution surface exists."""
        surface = get_canonical_surface("trigguard.code.exec")
        assert surface is not None
        assert surface.risk_tier == SurfaceRiskTier.IRREVERSIBLE

    def test_all_canonical_surfaces_have_valid_ids(self):
        """Test all canonical surfaces have valid namespaced IDs."""
        for surface_id, surface in get_canonical_surfaces().items():
            assert "." in surface_id
            assert surface.namespace == surface_id.split(".")[0]


class TestExecutionSurfaceRegistry:
    """Tests for ExecutionSurfaceRegistry."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset global registry before each test."""
        reset_global_surface_registry()
        yield
        reset_global_surface_registry()

    def test_preload_canonical_surfaces(self):
        """Test that canonical surfaces are preloaded."""
        registry = ExecutionSurfaceRegistry(preload_canonical=True)
        assert len(registry) > 0
        assert registry.exists("trigguard.spend.transfer")

    def test_get_surface(self):
        """Test getting a surface by ID."""
        registry = ExecutionSurfaceRegistry()
        surface = registry.get("trigguard.spend.transfer")
        assert surface is not None
        assert surface.surface_id == "trigguard.spend.transfer"

    def test_get_nonexistent_surface(self):
        """Test getting a nonexistent surface returns None."""
        registry = ExecutionSurfaceRegistry()
        assert registry.get("nonexistent.surface") is None

    def test_alias_resolution_uppercase(self):
        """Test alias resolution with uppercase."""
        registry = ExecutionSurfaceRegistry()
        surface = registry.resolve("SPEND")
        assert surface is not None
        assert surface.surface_id == "trigguard.spend.transfer"

    def test_alias_resolution_lowercase(self):
        """Test alias resolution with lowercase."""
        registry = ExecutionSurfaceRegistry()
        surface = registry.resolve("spend")
        assert surface is not None
        assert surface.surface_id == "trigguard.spend.transfer"

    def test_alias_resolution_legacy(self):
        """Test alias resolution with legacy names."""
        registry = ExecutionSurfaceRegistry()

        # CODE_EXEC -> trigguard.code.exec
        surface = registry.resolve("CODE_EXEC")
        assert surface is not None
        assert surface.surface_id == "trigguard.code.exec"

        # CODE_EXECUTION -> trigguard.code.exec
        surface = registry.resolve("CODE_EXECUTION")
        assert surface is not None
        assert surface.surface_id == "trigguard.code.exec"

    def test_normalize_surface(self):
        """Test surface normalization."""
        registry = ExecutionSurfaceRegistry()

        # Already canonical
        assert (
            registry.normalize("trigguard.spend.transfer") == "trigguard.spend.transfer"
        )

        # Alias
        assert registry.normalize("SPEND") == "trigguard.spend.transfer"

        # Unknown
        assert registry.normalize("unknown_action") == "unknown.unknown_action"

    def test_register_custom_surface(self):
        """Test registering a custom surface."""
        registry = ExecutionSurfaceRegistry()

        custom = ExecutionSurfaceDefinition(
            surface_id="myapp.payment.charge",
            namespace="myapp",
            display_name="Payment Charge",
            description="Charge a payment method",
            risk_tier=SurfaceRiskTier.IRREVERSIBLE,
            reversible=False,
        )

        registry.register(custom)
        assert registry.exists("myapp.payment.charge")

        retrieved = registry.get("myapp.payment.charge")
        assert retrieved.surface_id == "myapp.payment.charge"

    def test_duplicate_registration_same_definition(self):
        """Test that duplicate registration with same definition is allowed."""
        registry = ExecutionSurfaceRegistry()

        custom = ExecutionSurfaceDefinition(
            surface_id="myapp.test.surface",
            namespace="myapp",
            display_name="Test",
            description="Test",
            risk_tier=SurfaceRiskTier.LOW,
            reversible=True,
        )

        registry.register(custom)
        registry.register(custom)  # Should not raise

        assert registry.exists("myapp.test.surface")

    def test_duplicate_registration_different_definition_rejected(self):
        """Test that duplicate with different definition is rejected."""
        registry = ExecutionSurfaceRegistry()

        custom1 = ExecutionSurfaceDefinition(
            surface_id="myapp.test.surface",
            namespace="myapp",
            display_name="Test 1",
            description="Test 1",
            risk_tier=SurfaceRiskTier.LOW,
            reversible=True,
        )

        custom2 = ExecutionSurfaceDefinition(
            surface_id="myapp.test.surface",
            namespace="myapp",
            display_name="Test 2",  # Different
            description="Test 2",
            risk_tier=SurfaceRiskTier.HIGH,  # Different
            reversible=True,
        )

        registry.register(custom1)

        with pytest.raises(DuplicateSurfaceError):
            registry.register(custom2)

    def test_list_by_risk_tier(self):
        """Test listing surfaces by risk tier."""
        registry = ExecutionSurfaceRegistry()

        irreversible = registry.list_by_risk(SurfaceRiskTier.IRREVERSIBLE)
        assert len(irreversible) > 0

        for surface in irreversible:
            assert surface.risk_tier == SurfaceRiskTier.IRREVERSIBLE

    def test_list_by_namespace(self):
        """Test listing surfaces by namespace."""
        registry = ExecutionSurfaceRegistry()

        trigguard_surfaces = registry.list_by_namespace("trigguard")
        assert len(trigguard_surfaces) > 0

        for surface in trigguard_surfaces:
            assert surface.namespace == "trigguard"

    def test_list_by_tags(self):
        """Test listing surfaces by tags."""
        registry = ExecutionSurfaceRegistry()

        money_surfaces = registry.list_by_tags("money", "payment")
        assert len(money_surfaces) > 0

    def test_requires_grant(self):
        """Test requires_grant check."""
        registry = ExecutionSurfaceRegistry()

        # IRREVERSIBLE requires grant
        assert registry.requires_grant("trigguard.spend.transfer") is True

        # LOW does not require grant
        assert registry.requires_grant("trigguard.retrieval.search") is False

        # Unknown surfaces require grants (fail-safe)
        assert registry.requires_grant("unknown.thing") is True

    def test_fail_on_unknown(self):
        """Test fail_on_unknown mode."""
        registry = ExecutionSurfaceRegistry(fail_on_unknown=True)

        with pytest.raises(UnknownSurfaceError):
            registry.resolve("nonexistent.surface")

    def test_export_manifest_deterministic(self):
        """Test that registry export is deterministic."""
        registry = ExecutionSurfaceRegistry()

        manifest1 = registry.export_manifest()
        manifest2 = registry.export_manifest()

        # Surface list should be sorted same way
        assert len(manifest1["surfaces"]) == len(manifest2["surfaces"])
        for s1, s2 in zip(manifest1["surfaces"], manifest2["surfaces"]):
            assert s1["surface_id"] == s2["surface_id"]


class TestGlobalRegistry:
    """Tests for global registry functions."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset global registry before each test."""
        reset_global_surface_registry()
        yield
        reset_global_surface_registry()

    def test_get_global_registry(self):
        """Test getting global registry."""
        registry = get_global_surface_registry()
        assert registry is not None
        assert len(registry) > 0

    def test_global_registry_singleton(self):
        """Test that global registry is a singleton."""
        registry1 = get_global_surface_registry()
        registry2 = get_global_surface_registry()
        assert registry1 is registry2

    def test_normalize_surface_function(self):
        """Test normalize_surface convenience function."""
        assert normalize_surface("SPEND") == "trigguard.spend.transfer"
        assert normalize_surface("trigguard.code.exec") == "trigguard.code.exec"

    def test_is_registered_surface_function(self):
        """Test is_registered_surface convenience function."""
        assert is_registered_surface("trigguard.spend.transfer") is True
        assert is_registered_surface("SPEND") is True
        assert is_registered_surface("nonexistent.surface") is False

    def test_get_surface_definition_function(self):
        """Test get_surface_definition convenience function."""
        surface = get_surface_definition("SPEND")
        assert surface is not None
        assert surface.surface_id == "trigguard.spend.transfer"


class TestSurfaceIntegration:
    """Integration tests for surface registry."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset global registry before each test."""
        reset_global_surface_registry()
        yield
        reset_global_surface_registry()

    def test_third_party_namespace_registration(self):
        """Test registering third-party surfaces."""
        registry = get_global_surface_registry()

        # Register an OpenAI tool surface
        openai_surface = ExecutionSurfaceDefinition(
            surface_id="openai.tool.call",
            namespace="openai",
            display_name="OpenAI Tool Call",
            description="Call an OpenAI tool",
            risk_tier=SurfaceRiskTier.MEDIUM,
            reversible=True,
            tags=["openai", "tool", "ai"],
        )
        registry.register(openai_surface)

        assert registry.exists("openai.tool.call")

        # Register an alias
        registry.register_alias("openai_tool", "openai.tool.call")

        surface = registry.resolve("openai_tool")
        assert surface.surface_id == "openai.tool.call"

    def test_all_irreversible_surfaces_require_grant(self):
        """Test that all irreversible surfaces require grants."""
        registry = get_global_surface_registry()

        for surface in registry.list_irreversible():
            assert (
                surface.requires_grant
            ), f"Irreversible surface {surface.surface_id} should require grant"
