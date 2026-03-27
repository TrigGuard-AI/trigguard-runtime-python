"""
Tests for Discovery Contract

Tests cover:
- Discovery manifest serialization
- Well-known endpoint response shapes
- Manifest deterministic export
- ToolSurfaceManifest conversion
- Grant binding to canonical surface_id
"""

import json
import pytest
from datetime import datetime, timezone

from trigguard.discovery.discovery_contract import (
    ConstraintSchema,
    SurfaceDiscoveryRecord,
    DiscoveryManifest,
    build_discovery_manifest,
    merge_manifests,
)
from trigguard.discovery.tool_manifest import (
    ToolSurfaceManifest,
    declares_surface,
    get_declared_surface,
    collect_surfaces_from_module,
    infer_surface_from_name,
    infer_constraints_from_parameters,
)
from trigguard.registry.surface_registry import (
    get_global_surface_registry,
    reset_global_surface_registry,
)


class TestConstraintSchema:
    """Tests for ConstraintSchema."""

    def test_empty_schema(self):
        """Test empty constraint schema."""
        schema = ConstraintSchema()
        assert schema.to_dict() == {}

    def test_schema_with_amount(self):
        """Test schema with max_amount support."""
        schema = ConstraintSchema(supports_max_amount=True)
        data = schema.to_dict()
        assert "max_amount" in data
        assert data["max_amount"]["type"] == "number"

    def test_schema_with_currency(self):
        """Test schema with currency support."""
        schema = ConstraintSchema(supports_currency=True)
        data = schema.to_dict()
        assert "currency" in data

    def test_schema_with_all(self):
        """Test schema with all constraints."""
        schema = ConstraintSchema(
            supports_max_amount=True,
            supports_currency=True,
            supports_command_allowlist=True,
            supports_resource_binding=True,
            supports_one_time_use=True,
        )
        data = schema.to_dict()
        assert "max_amount" in data
        assert "currency" in data
        assert "allowed_command" in data
        assert "resource" in data
        assert "one_time_use" in data

    def test_from_dict(self):
        """Test schema from_dict."""
        data = {
            "max_amount": {"type": "number"},
            "currency": {"type": "string"},
        }
        schema = ConstraintSchema.from_dict(data)
        assert schema.supports_max_amount
        assert schema.supports_currency
        assert not schema.supports_command_allowlist


class TestSurfaceDiscoveryRecord:
    """Tests for SurfaceDiscoveryRecord."""

    def test_create_record(self):
        """Test creating a discovery record."""
        record = SurfaceDiscoveryRecord(
            surface_id="trigguard.spend.transfer",
            supported_actions=["transfer", "send"],
            grant_required=True,
        )
        assert record.surface_id == "trigguard.spend.transfer"
        assert record.grant_required is True
        assert "transfer" in record.supported_actions

    def test_record_to_dict(self):
        """Test record serialization."""
        record = SurfaceDiscoveryRecord(
            surface_id="trigguard.spend.transfer",
            supported_actions=["transfer"],
            resource_types=["account"],
            verifier_required=True,
            grant_required=True,
        )
        data = record.to_dict()
        assert data["surface_id"] == "trigguard.spend.transfer"
        assert data["supported_actions"] == ["transfer"]
        assert data["verifier_required"] is True
        assert data["grant_required"] is True

    def test_record_from_dict(self):
        """Test record deserialization."""
        data = {
            "surface_id": "trigguard.code.exec",
            "supported_actions": ["run", "eval"],
            "grant_required": True,
            "verifier_required": True,
        }
        record = SurfaceDiscoveryRecord.from_dict(data)
        assert record.surface_id == "trigguard.code.exec"
        assert "run" in record.supported_actions

    def test_record_with_constraint_schema(self):
        """Test record with constraint schema."""
        schema = ConstraintSchema(supports_max_amount=True)
        record = SurfaceDiscoveryRecord(
            surface_id="trigguard.spend.transfer",
            constraint_schema=schema,
        )
        data = record.to_dict()
        assert "constraint_schema" in data
        assert "max_amount" in data["constraint_schema"]


class TestDiscoveryManifest:
    """Tests for DiscoveryManifest."""

    def test_create_manifest(self):
        """Test creating a manifest."""
        manifest = DiscoveryManifest(issuer="test-tool")
        assert manifest.issuer == "test-tool"
        assert len(manifest.surfaces) == 0

    def test_add_surface(self):
        """Test adding a surface to manifest."""
        manifest = DiscoveryManifest(issuer="test-tool")
        record = SurfaceDiscoveryRecord(
            surface_id="trigguard.spend.transfer",
            grant_required=True,
        )
        manifest.add_surface(record)
        assert len(manifest.surfaces) == 1
        assert manifest.supports_surface("trigguard.spend.transfer")

    def test_duplicate_surface_replaces(self):
        """Test that adding duplicate surface replaces it."""
        manifest = DiscoveryManifest(issuer="test-tool")

        record1 = SurfaceDiscoveryRecord(
            surface_id="trigguard.spend.transfer",
            supported_actions=["v1"],
        )
        record2 = SurfaceDiscoveryRecord(
            surface_id="trigguard.spend.transfer",
            supported_actions=["v2"],
        )

        manifest.add_surface(record1)
        manifest.add_surface(record2)

        assert len(manifest.surfaces) == 1
        assert manifest.get_surface("trigguard.spend.transfer").supported_actions == [
            "v2"
        ]

    def test_supports_action(self):
        """Test action support check."""
        manifest = DiscoveryManifest(issuer="test-tool")
        manifest.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                supported_actions=["transfer", "send"],
            )
        )

        assert manifest.supports_action("trigguard.spend.transfer", "transfer")
        assert manifest.supports_action("trigguard.spend.transfer", "send")
        assert not manifest.supports_action("trigguard.spend.transfer", "delete")

    def test_empty_actions_means_all_supported(self):
        """Test that empty actions list means all actions supported."""
        manifest = DiscoveryManifest(issuer="test-tool")
        manifest.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                supported_actions=[],  # Empty = all
            )
        )

        assert manifest.supports_action("trigguard.spend.transfer", "anything")

    def test_manifest_to_dict(self):
        """Test manifest serialization."""
        manifest = DiscoveryManifest(issuer="test-tool", version="1.0")
        manifest.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                grant_required=True,
            )
        )

        data = manifest.to_dict()
        assert data["issuer"] == "test-tool"
        assert data["version"] == "1.0"
        assert "updated_at" in data
        assert data["surface_count"] == 1
        assert len(data["surfaces"]) == 1

    def test_manifest_from_dict(self):
        """Test manifest deserialization."""
        data = {
            "issuer": "test-tool",
            "version": "2.0",
            "updated_at": "2026-03-27T12:00:00+00:00",
            "surfaces": [
                {
                    "surface_id": "trigguard.code.exec",
                    "supported_actions": ["run"],
                    "grant_required": True,
                    "verifier_required": True,
                }
            ],
        }
        manifest = DiscoveryManifest.from_dict(data)
        assert manifest.issuer == "test-tool"
        assert manifest.version == "2.0"
        assert len(manifest.surfaces) == 1

    def test_canonical_json_deterministic(self):
        """Test manifest canonical JSON is deterministic."""
        manifest = DiscoveryManifest(issuer="test")
        manifest.add_surface(
            SurfaceDiscoveryRecord(surface_id="trigguard.spend.transfer")
        )
        manifest.add_surface(SurfaceDiscoveryRecord(surface_id="trigguard.code.exec"))

        json1 = manifest.to_canonical_json()
        json2 = manifest.to_canonical_json()
        assert json1 == json2

    def test_list_grant_required_surfaces(self):
        """Test listing surfaces that require grants."""
        manifest = DiscoveryManifest(issuer="test")
        manifest.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                grant_required=True,
            )
        )
        manifest.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.retrieval.search",
                grant_required=False,
            )
        )

        grant_surfaces = manifest.list_grant_required_surfaces()
        assert "trigguard.spend.transfer" in grant_surfaces
        assert "trigguard.retrieval.search" not in grant_surfaces


class TestBuildDiscoveryManifest:
    """Tests for build_discovery_manifest helper."""

    def test_build_manifest(self):
        """Test building manifest from config."""
        configs = [
            {
                "surface_id": "trigguard.spend.transfer",
                "supported_actions": ["transfer"],
                "grant_required": True,
                "verifier_required": True,
            }
        ]

        manifest = build_discovery_manifest("my-tool", configs)
        assert manifest.issuer == "my-tool"
        assert len(manifest.surfaces) == 1


class TestMergeManifests:
    """Tests for merge_manifests helper."""

    def test_merge_manifests(self):
        """Test merging multiple manifests."""
        m1 = DiscoveryManifest(issuer="tool1")
        m1.add_surface(SurfaceDiscoveryRecord(surface_id="trigguard.spend.transfer"))

        m2 = DiscoveryManifest(issuer="tool2")
        m2.add_surface(SurfaceDiscoveryRecord(surface_id="trigguard.code.exec"))

        merged = merge_manifests(m1, m2)
        assert len(merged.surfaces) == 2
        assert merged.supports_surface("trigguard.spend.transfer")
        assert merged.supports_surface("trigguard.code.exec")

    def test_merge_manifests_override(self):
        """Test that later manifests override earlier ones."""
        m1 = DiscoveryManifest(issuer="tool1")
        m1.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                supported_actions=["v1"],
            )
        )

        m2 = DiscoveryManifest(issuer="tool2")
        m2.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                supported_actions=["v2"],
            )
        )

        merged = merge_manifests(m1, m2)
        record = merged.get_surface("trigguard.spend.transfer")
        assert record.supported_actions == ["v2"]


class TestInferSurfaceFromName:
    """Tests for surface inference from function names."""

    def test_infer_payment(self):
        """Test inferring payment surfaces."""
        assert infer_surface_from_name("pay") == "trigguard.spend.transfer"
        assert infer_surface_from_name("send_payment") == "trigguard.spend.transfer"
        assert infer_surface_from_name("process_payment") == "trigguard.spend.transfer"

    def test_infer_code(self):
        """Test inferring code execution surfaces."""
        assert infer_surface_from_name("exec") == "trigguard.code.exec"
        assert infer_surface_from_name("run_command") == "trigguard.code.exec"
        assert infer_surface_from_name("shell") == "trigguard.code.exec"

    def test_infer_data(self):
        """Test inferring data surfaces."""
        assert infer_surface_from_name("export") == "trigguard.data.export"
        assert infer_surface_from_name("download_file") == "trigguard.data.export"
        assert infer_surface_from_name("delete") == "trigguard.data.delete"

    def test_unknown_name(self):
        """Test unknown function names."""
        assert infer_surface_from_name("do_something_unknown") is None


class TestInferConstraintsFromParameters:
    """Tests for constraint inference from parameters."""

    def test_infer_amount(self):
        """Test inferring amount constraints."""
        params = {"amount": {"type": "number"}}
        schema = infer_constraints_from_parameters(params)
        assert schema.supports_max_amount

    def test_infer_currency(self):
        """Test inferring currency constraints."""
        params = {"currency": {"type": "string"}}
        schema = infer_constraints_from_parameters(params)
        assert schema.supports_currency

    def test_infer_command(self):
        """Test inferring command constraints."""
        params = {"command": {"type": "string"}}
        schema = infer_constraints_from_parameters(params)
        assert schema.supports_command_allowlist

    def test_infer_resource(self):
        """Test inferring resource binding."""
        params = {"account_id": {"type": "string"}}
        schema = infer_constraints_from_parameters(params)
        assert schema.supports_resource_binding


class TestToolSurfaceManifest:
    """Tests for ToolSurfaceManifest."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset global registry."""
        reset_global_surface_registry()
        yield
        reset_global_surface_registry()

    def test_declare_surface(self):
        """Test declaring a surface."""
        manifest = ToolSurfaceManifest(issuer="my-tool")
        manifest.declare_surface(
            surface_id="trigguard.spend.transfer",
            actions=["transfer"],
        )

        assert "trigguard.spend.transfer" in manifest.records

    def test_from_tool_definition(self):
        """Test creating manifest from tool definition."""
        tool_def = {
            "name": "send_payment",
            "description": "Send a payment",
            "parameters": {
                "amount": {"type": "number"},
                "currency": {"type": "string"},
            },
        }

        manifest = ToolSurfaceManifest.from_tool_definition(tool_def)
        assert manifest.issuer == "send_payment"

        # Should infer spend.transfer from name
        discovery = manifest.to_discovery_manifest()
        assert discovery.supports_surface("trigguard.spend.transfer")

    def test_from_tool_definition_with_nested_params(self):
        """Test with OpenAPI-style nested parameters."""
        tool_def = {
            "name": "execute_command",
            "parameters": {
                "properties": {
                    "command": {"type": "string"},
                }
            },
        }

        manifest = ToolSurfaceManifest.from_tool_definition(tool_def)
        discovery = manifest.to_discovery_manifest()

        # Should infer code.exec
        assert discovery.supports_surface("trigguard.code.exec")

    def test_from_callable(self):
        """Test creating manifest from callable."""

        def transfer_money(amount: float, currency: str) -> bool:
            """Transfer money to recipient."""
            return True

        manifest = ToolSurfaceManifest.from_callable(transfer_money)
        discovery = manifest.to_discovery_manifest()

        # Should infer spend.transfer
        assert discovery.supports_surface("trigguard.spend.transfer")

        # Should detect amount and currency constraints
        record = discovery.get_surface("trigguard.spend.transfer")
        assert record.constraint_schema.supports_max_amount
        assert record.constraint_schema.supports_currency


class TestDeclaresSurfaceDecorator:
    """Tests for @declares_surface decorator."""

    def test_decorator_stores_metadata(self):
        """Test that decorator stores surface metadata."""

        @declares_surface("trigguard.spend.transfer")
        def my_payment_function():
            pass

        assert get_declared_surface(my_payment_function) == "trigguard.spend.transfer"

    def test_decorator_with_actions(self):
        """Test decorator with custom actions."""

        @declares_surface("trigguard.code.exec", actions=["run", "eval"])
        def my_exec_function():
            pass

        assert my_exec_function._trigguard_actions == ["run", "eval"]

    def test_decorator_preserves_function(self):
        """Test that decorator preserves function behavior."""

        @declares_surface("trigguard.spend.transfer")
        def add(a: int, b: int) -> int:
            return a + b

        assert add(2, 3) == 5


class TestWellKnownEndpointShapes:
    """Tests for expected well-known endpoint response shapes."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset global registry."""
        reset_global_surface_registry()
        yield
        reset_global_surface_registry()

    def test_surfaces_response_shape(self):
        """Test /.well-known/trigguard-surfaces response shape."""
        registry = get_global_surface_registry()
        manifest = registry.export_manifest()

        # Required fields
        assert "issuer" in manifest
        assert "version" in manifest
        assert "surfaces" in manifest

        # Surfaces should be a list
        assert isinstance(manifest["surfaces"], list)

        # Each surface should have required fields
        for surface in manifest["surfaces"]:
            assert "surface_id" in surface
            assert "namespace" in surface
            assert "risk_tier" in surface

    def test_discovery_response_shape(self):
        """Test /.well-known/trigguard-discovery response shape."""
        manifest = DiscoveryManifest(issuer="trigguard", version="1.0")
        manifest.add_surface(
            SurfaceDiscoveryRecord(
                surface_id="trigguard.spend.transfer",
                grant_required=True,
            )
        )

        data = manifest.to_dict()

        # Required fields
        assert "issuer" in data
        assert "version" in data
        assert "updated_at" in data
        assert "surface_count" in data
        assert "surfaces" in data

        # Each surface record should have required fields
        for record in data["surfaces"]:
            assert "surface_id" in record
            assert "verifier_required" in record
            assert "grant_required" in record


class TestGrantSurfaceBinding:
    """Tests for grant binding to canonical surface_id."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset global registry."""
        reset_global_surface_registry()
        yield
        reset_global_surface_registry()

    def test_grant_surface_id_normalization(self):
        """Test that grants normalize surface to canonical ID."""
        from trigguard.grants.action_grant import ActionGrant, GrantConstraints
        from uuid import uuid4
        from datetime import timedelta

        now = datetime.now(timezone.utc)

        grant = ActionGrant(
            grant_id=uuid4(),
            issuer="test",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            subject=None,
            surface="SPEND",  # Alias
            action="transfer",
            resource=None,
            constraints=GrantConstraints(),
            policy_version="1.0",
            decision_hash="abc123",
            receipt_hash="def456",
        )

        # surface_id property should normalize
        assert grant.surface_id == "trigguard.spend.transfer"

    def test_grant_is_registered_surface(self):
        """Test grant's is_registered_surface property."""
        from trigguard.grants.action_grant import ActionGrant, GrantConstraints
        from uuid import uuid4
        from datetime import timedelta

        now = datetime.now(timezone.utc)

        # Registered surface
        grant1 = ActionGrant(
            grant_id=uuid4(),
            issuer="test",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            subject=None,
            surface="trigguard.spend.transfer",
            action="transfer",
            resource=None,
            constraints=GrantConstraints(),
            policy_version="1.0",
            decision_hash="abc123",
            receipt_hash="def456",
        )
        assert grant1.is_registered_surface is True

        # Unknown surface
        grant2 = ActionGrant(
            grant_id=uuid4(),
            issuer="test",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            subject=None,
            surface="unknown.weird.thing",
            action="whatever",
            resource=None,
            constraints=GrantConstraints(),
            policy_version="1.0",
            decision_hash="abc123",
            receipt_hash="def456",
        )
        assert grant2.is_registered_surface is False
