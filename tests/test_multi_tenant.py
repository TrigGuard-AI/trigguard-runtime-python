"""
TrigGuard Multi-Tenant Policy Tests

Unit tests for tenant policy management.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from trigguard.policy.multi_tenant import (
    TenantPolicy,
    TenantTier,
    TenantLimits,
    PolicyInheritance,
    SurfaceOverride,
    TenantContext,
    TenantPolicyManager,
    InMemoryTenantStore,
    TenantAwareEvaluator,
    get_tenant_manager,
    get_tenant_policy,
    register_tenant,
)


class TestTenantTier:
    """Test tenant tier enum."""

    def test_tier_values(self):
        """Test tier enum values."""
        assert TenantTier.FREE.value == "free"
        assert TenantTier.STANDARD.value == "standard"
        assert TenantTier.ENTERPRISE.value == "enterprise"


class TestTenantLimits:
    """Test tenant resource limits."""

    def test_default_limits(self):
        """Test default limit values."""
        limits = TenantLimits()

        assert limits.max_requests_per_second == 100.0
        assert limits.max_batch_size == 100

    def test_limits_for_free_tier(self):
        """Test limits for free tier."""
        limits = TenantLimits.for_tier(TenantTier.FREE)

        assert limits.max_requests_per_second == 10.0
        assert limits.max_requests_per_day == 10000
        assert limits.max_batch_size == 10

    def test_limits_for_enterprise_tier(self):
        """Test limits for enterprise tier."""
        limits = TenantLimits.for_tier(TenantTier.ENTERPRISE)

        assert limits.max_requests_per_second == 10000.0
        assert limits.max_requests_per_day == 10000000


class TestTenantPolicy:
    """Test TenantPolicy dataclass."""

    def test_policy_creation(self):
        """Test creating tenant policy."""
        policy = TenantPolicy(
            tenant_id="test-tenant",
            tier=TenantTier.STANDARD,
        )

        assert policy.tenant_id == "test-tenant"
        assert policy.tier == TenantTier.STANDARD
        assert policy.inheritance == PolicyInheritance.MERGE
        assert policy.fail_open is False

    def test_allows_surface_default(self):
        """Test surface allowed by default."""
        policy = TenantPolicy(tenant_id="test")

        assert policy.allows_surface("read") is True
        assert policy.allows_surface("write") is True

    def test_allows_surface_with_allowed_list(self):
        """Test surface allowed with allowlist."""
        policy = TenantPolicy(
            tenant_id="test",
            allowed_surfaces={"read", "write"},
        )

        assert policy.allows_surface("read") is True
        assert policy.allows_surface("spend") is False

    def test_allows_surface_with_denied_list(self):
        """Test surface denied with denylist."""
        policy = TenantPolicy(
            tenant_id="test",
            denied_surfaces={"code_execution"},
        )

        assert policy.allows_surface("read") is True
        assert policy.allows_surface("code_execution") is False

    def test_allows_surface_with_override_disabled(self):
        """Test disabled surface override."""
        policy = TenantPolicy(
            tenant_id="test",
            surface_overrides={
                "spend": SurfaceOverride(surface="spend", disabled=True),
            },
        )

        assert policy.allows_surface("read") is True
        assert policy.allows_surface("spend") is False

    def test_get_surface_override(self):
        """Test getting surface override."""
        override = SurfaceOverride(
            surface="spend",
            default_decision="deny",
        )
        policy = TenantPolicy(
            tenant_id="test",
            surface_overrides={"spend": override},
        )

        assert policy.get_surface_override("spend") == override
        assert policy.get_surface_override("read") is None


class TestTenantContext:
    """Test tenant runtime context."""

    def test_context_to_dict(self):
        """Test context serialization."""
        policy = TenantPolicy(
            tenant_id="test",
            tier=TenantTier.ENTERPRISE,
            version="2.0",
        )
        context = TenantContext(
            tenant_id="test",
            policy=policy,
            is_rate_limited=True,
        )

        data = context.to_dict()

        assert data["tenant_id"] == "test"
        assert data["tier"] == "enterprise"
        assert data["version"] == "2.0"
        assert data["is_rate_limited"] is True


class TestInMemoryTenantStore:
    """Test in-memory tenant storage."""

    def test_get_nonexistent(self):
        """Test getting nonexistent tenant."""
        store = InMemoryTenantStore()
        assert store.get("nonexistent") is None

    def test_put_and_get(self):
        """Test storing and retrieving tenant."""
        store = InMemoryTenantStore()
        policy = TenantPolicy(tenant_id="test")

        store.put(policy)
        retrieved = store.get("test")

        assert retrieved is not None
        assert retrieved.tenant_id == "test"

    def test_delete(self):
        """Test deleting tenant."""
        store = InMemoryTenantStore()
        store.put(TenantPolicy(tenant_id="test"))

        assert store.delete("test") is True
        assert store.get("test") is None
        assert store.delete("test") is False

    def test_list_all(self):
        """Test listing all tenants."""
        store = InMemoryTenantStore()
        store.put(TenantPolicy(tenant_id="a"))
        store.put(TenantPolicy(tenant_id="b"))
        store.put(TenantPolicy(tenant_id="c"))

        tenants = store.list_all()
        assert set(tenants) == {"a", "b", "c"}


class TestTenantPolicyManager:
    """Test tenant policy manager."""

    def test_register_tenant(self):
        """Test registering new tenant."""
        manager = TenantPolicyManager()

        policy = manager.register_tenant(
            "new-tenant",
            tier=TenantTier.STANDARD,
        )

        assert policy.tenant_id == "new-tenant"
        assert policy.tier == TenantTier.STANDARD

    def test_register_duplicate_fails(self):
        """Test registering duplicate tenant fails."""
        manager = TenantPolicyManager()
        manager.register_tenant("existing")

        with pytest.raises(ValueError, match="already exists"):
            manager.register_tenant("existing")

    def test_get_tenant(self):
        """Test getting registered tenant."""
        manager = TenantPolicyManager()
        manager.register_tenant("test")

        policy = manager.get_tenant("test")
        assert policy is not None
        assert policy.tenant_id == "test"

    def test_update_tenant(self):
        """Test updating tenant configuration."""
        manager = TenantPolicyManager()
        manager.register_tenant("test", tier=TenantTier.FREE)

        updated = manager.update_tenant("test", tier=TenantTier.ENTERPRISE)

        assert updated.tier == TenantTier.ENTERPRISE

    def test_update_nonexistent_fails(self):
        """Test updating nonexistent tenant fails."""
        manager = TenantPolicyManager()

        with pytest.raises(ValueError, match="not found"):
            manager.update_tenant("nonexistent", tier=TenantTier.ENTERPRISE)

    def test_delete_tenant(self):
        """Test deleting tenant."""
        manager = TenantPolicyManager()
        manager.register_tenant("test")

        assert manager.delete_tenant("test") is True
        assert manager.get_tenant("test") is None

    def test_list_tenants(self):
        """Test listing all tenants."""
        manager = TenantPolicyManager()
        manager.register_tenant("a")
        manager.register_tenant("b")

        tenants = manager.list_tenants()
        assert set(tenants) == {"a", "b"}

    def test_resolve_policy_unknown_tenant(self):
        """Test resolving policy for unknown tenant."""
        base_policy = {"default_decision": "deny"}
        manager = TenantPolicyManager(base_policy=base_policy)

        resolved = manager.resolve_policy("unknown", "read")

        assert resolved["default_decision"] == "deny"

    def test_resolve_policy_merge(self):
        """Test policy merge inheritance."""
        base_policy = {"base_key": "base_value"}
        manager = TenantPolicyManager(base_policy=base_policy)
        manager.register_tenant(
            "test",
            inheritance=PolicyInheritance.MERGE,
        )

        resolved = manager.resolve_policy("test", "read")

        assert resolved["base_key"] == "base_value"
        assert resolved["tenant_id"] == "test"

    def test_tenant_hook(self):
        """Test tenant registration hook."""
        manager = TenantPolicyManager()
        hook_called = []

        def my_hook(tenant_id, policy):
            hook_called.append(tenant_id)

        manager.add_tenant_hook(my_hook)
        manager.register_tenant("test")

        assert "test" in hook_called

    def test_get_context(self):
        """Test getting tenant context."""
        manager = TenantPolicyManager()
        manager.register_tenant("test", tier=TenantTier.ENTERPRISE)

        context = manager.get_context("test")

        assert context.tenant_id == "test"
        assert context.policy.tier == TenantTier.ENTERPRISE

    def test_get_context_unknown_tenant(self):
        """Test context for unknown tenant."""
        manager = TenantPolicyManager()

        context = manager.get_context("unknown")

        assert context.tenant_id == "unknown"
        assert context.policy.tier == TenantTier.FREE  # Default


class TestTenantAwareEvaluator:
    """Test tenant-aware evaluation."""

    def test_evaluate_without_tenant(self):
        """Test evaluation without tenant uses base."""
        manager = TenantPolicyManager()
        base_evaluator = Mock(return_value={"permit": True})

        evaluator = TenantAwareEvaluator(manager, base_evaluator)
        result = evaluator.evaluate({"surface": "read"})

        base_evaluator.assert_called_once()
        assert result["permit"] is True

    def test_evaluate_with_tenant_context(self):
        """Test evaluation with tenant from trigguard.context."""
        manager = TenantPolicyManager()
        manager.register_tenant("test-tenant")

        base_evaluator = Mock(return_value={"permit": True})
        evaluator = TenantAwareEvaluator(manager, base_evaluator)

        result = evaluator.evaluate(
            {
                "surface": "read",
                "context": {"tenant_id": "test-tenant"},
            }
        )

        assert result["permit"] is True
        assert "tenant_context" in result

    def test_evaluate_denied_surface(self):
        """Test evaluation with denied surface."""
        manager = TenantPolicyManager()
        manager.register_tenant(
            "restricted",
            denied_surfaces={"code_execution"},
        )

        base_evaluator = Mock(return_value={"permit": True})
        evaluator = TenantAwareEvaluator(manager, base_evaluator)

        result = evaluator.evaluate(
            {"surface": "code_execution"},
            tenant_id="restricted",
        )

        assert result["permit"] is False
        assert "not allowed" in result["reason"]
        base_evaluator.assert_not_called()

    def test_evaluate_surface_override(self):
        """Test evaluation with surface override."""
        manager = TenantPolicyManager()
        manager.register_tenant(
            "test",
            surface_overrides={
                "spend": SurfaceOverride(
                    surface="spend",
                    default_decision="deny",
                ),
            },
        )

        base_evaluator = Mock(return_value={"permit": True})
        evaluator = TenantAwareEvaluator(manager, base_evaluator)

        result = evaluator.evaluate(
            {"surface": "spend"},
            tenant_id="test",
        )

        assert result["permit"] is False
        assert result["decision"] == "deny"
        base_evaluator.assert_not_called()


class TestGlobalManager:
    """Test global manager functions."""

    def test_get_tenant_manager_singleton(self):
        """Test global manager is singleton."""
        # Reset
        import trigguard.policy.multi_tenant as module

        module._manager = None

        manager1 = get_tenant_manager()
        manager2 = get_tenant_manager()

        assert manager1 is manager2

    def test_register_tenant_global(self):
        """Test global tenant registration."""
        import trigguard.policy.multi_tenant as module

        module._manager = None

        policy = register_tenant("global-test")

        assert get_tenant_policy("global-test") is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
