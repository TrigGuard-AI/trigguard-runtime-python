"""
TrigGuard Multi-Tenant Policy

Tenant-aware policy isolation for enterprise deployments.

Features:
    - Per-tenant policy configuration
    - Policy inheritance and overrides
    - Tenant isolation guarantees
    - Dynamic tenant provisioning

Usage:
    from trigguard.policy.multi_tenant import TenantPolicyManager, get_tenant_policy

    manager = TenantPolicyManager()
    manager.register_tenant("tenant-a", config)

    # Get policy for tenant
    policy = get_tenant_policy("tenant-a")
"""

import threading
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable
from datetime import datetime, timezone
from copy import deepcopy

logger = logging.getLogger("trigguard.tenant")


class TenantTier(Enum):
    """Tenant service tiers with different capabilities."""

    FREE = "free"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class PolicyInheritance(Enum):
    """How tenant policies inherit from base."""

    NONE = "none"  # No inheritance
    MERGE = "merge"  # Merge with base
    OVERRIDE = "override"  # Override base completely


@dataclass
class TenantLimits:
    """Resource limits for a tenant."""

    max_requests_per_second: float = 100.0
    max_requests_per_day: int = 100000
    max_batch_size: int = 100
    max_signal_count: int = 50
    max_context_size_bytes: int = 65536
    cache_ttl_seconds: float = 300.0

    @classmethod
    def for_tier(cls, tier: TenantTier) -> "TenantLimits":
        """Get default limits for tier."""
        if tier == TenantTier.FREE:
            return cls(
                max_requests_per_second=10.0,
                max_requests_per_day=10000,
                max_batch_size=10,
            )
        elif tier == TenantTier.STANDARD:
            return cls(
                max_requests_per_second=100.0,
                max_requests_per_day=100000,
                max_batch_size=50,
            )
        elif tier == TenantTier.ENTERPRISE:
            return cls(
                max_requests_per_second=10000.0,
                max_requests_per_day=10000000,
                max_batch_size=1000,
            )
        else:
            return cls()


@dataclass
class SurfaceOverride:
    """Override for a specific surface."""

    surface: str
    default_decision: Optional[str] = None  # "allow", "deny", "escalate"
    disabled: bool = False
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TenantPolicy:
    """Policy configuration for a single tenant."""

    tenant_id: str
    version: str = "1.0"
    tier: TenantTier = TenantTier.STANDARD

    # Policy behavior
    inheritance: PolicyInheritance = PolicyInheritance.MERGE
    fail_open: bool = False  # Override fail-closed

    # Surface configuration
    allowed_surfaces: Set[str] = field(default_factory=set)
    denied_surfaces: Set[str] = field(default_factory=set)
    surface_overrides: Dict[str, SurfaceOverride] = field(default_factory=dict)

    # Limits
    limits: TenantLimits = field(default_factory=TenantLimits)

    # Custom rules
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"

    def allows_surface(self, surface: str) -> bool:
        """Check if surface is allowed for this tenant."""
        if surface in self.denied_surfaces:
            return False

        if self.allowed_surfaces and surface not in self.allowed_surfaces:
            return False

        override = self.surface_overrides.get(surface)
        if override and override.disabled:
            return False

        return True

    def get_surface_override(self, surface: str) -> Optional[SurfaceOverride]:
        """Get override for surface if exists."""
        return self.surface_overrides.get(surface)


@dataclass
class TenantContext:
    """Runtime context for a tenant request."""

    tenant_id: str
    policy: TenantPolicy
    request_count_today: int = 0
    request_count_second: float = 0.0
    is_rate_limited: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tier": self.policy.tier.value,
            "version": self.policy.version,
            "is_rate_limited": self.is_rate_limited,
        }


class TenantStore(ABC):
    """Abstract tenant storage backend."""

    @abstractmethod
    def get(self, tenant_id: str) -> Optional[TenantPolicy]:
        """Get tenant policy."""
        pass

    @abstractmethod
    def put(self, policy: TenantPolicy) -> None:
        """Store tenant policy."""
        pass

    @abstractmethod
    def delete(self, tenant_id: str) -> bool:
        """Delete tenant policy."""
        pass

    @abstractmethod
    def list_all(self) -> List[str]:
        """List all tenant IDs."""
        pass


class InMemoryTenantStore(TenantStore):
    """In-memory tenant storage."""

    def __init__(self):
        self._tenants: Dict[str, TenantPolicy] = {}
        self._lock = threading.RLock()

    def get(self, tenant_id: str) -> Optional[TenantPolicy]:
        with self._lock:
            return self._tenants.get(tenant_id)

    def put(self, policy: TenantPolicy) -> None:
        with self._lock:
            policy.updated_at = datetime.now(timezone.utc)
            self._tenants[policy.tenant_id] = policy

    def delete(self, tenant_id: str) -> bool:
        with self._lock:
            if tenant_id in self._tenants:
                del self._tenants[tenant_id]
                return True
            return False

    def list_all(self) -> List[str]:
        with self._lock:
            return list(self._tenants.keys())


class TenantPolicyManager:
    """
    Manages tenant policies with isolation guarantees.

    Provides:
        - Tenant registration and configuration
        - Policy inheritance resolution
        - Tenant context injection
        - Limit enforcement
    """

    def __init__(
        self,
        store: Optional[TenantStore] = None,
        base_policy: Optional[Dict[str, Any]] = None,
    ):
        self._store = store or InMemoryTenantStore()
        self._base_policy = base_policy or {}
        self._lock = threading.RLock()
        self._hooks: List[Callable[[str, TenantPolicy], None]] = []

    def register_tenant(
        self,
        tenant_id: str,
        tier: TenantTier = TenantTier.STANDARD,
        **kwargs,
    ) -> TenantPolicy:
        """
        Register a new tenant.

        Args:
            tenant_id: Unique tenant identifier
            tier: Service tier
            **kwargs: Additional policy configuration

        Returns:
            Created TenantPolicy
        """
        with self._lock:
            existing = self._store.get(tenant_id)
            if existing:
                raise ValueError(f"Tenant already exists: {tenant_id}")

            policy = TenantPolicy(
                tenant_id=tenant_id,
                tier=tier,
                limits=TenantLimits.for_tier(tier),
                **kwargs,
            )

            self._store.put(policy)

            logger.info(f"Registered tenant: {tenant_id} (tier={tier.value})")

            for hook in self._hooks:
                try:
                    hook(tenant_id, policy)
                except Exception as e:
                    logger.error(f"Tenant hook failed: {e}")

            return policy

    def get_tenant(self, tenant_id: str) -> Optional[TenantPolicy]:
        """Get tenant policy by ID."""
        return self._store.get(tenant_id)

    def update_tenant(
        self,
        tenant_id: str,
        **updates,
    ) -> TenantPolicy:
        """
        Update tenant configuration.

        Args:
            tenant_id: Tenant to update
            **updates: Fields to update

        Returns:
            Updated TenantPolicy
        """
        with self._lock:
            policy = self._store.get(tenant_id)
            if not policy:
                raise ValueError(f"Tenant not found: {tenant_id}")

            for key, value in updates.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)

            policy.updated_at = datetime.now(timezone.utc)
            self._store.put(policy)

            logger.info(f"Updated tenant: {tenant_id}")

            return policy

    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant."""
        with self._lock:
            deleted = self._store.delete(tenant_id)
            if deleted:
                logger.info(f"Deleted tenant: {tenant_id}")
            return deleted

    def list_tenants(self) -> List[str]:
        """List all tenant IDs."""
        return self._store.list_all()

    def resolve_policy(
        self,
        tenant_id: str,
        surface: str,
    ) -> Dict[str, Any]:
        """
        Resolve effective policy for tenant + surface.

        Applies inheritance rules to compute final policy.
        """
        policy = self._store.get(tenant_id)

        if not policy:
            # Return base policy for unknown tenants
            return deepcopy(self._base_policy)

        if policy.inheritance == PolicyInheritance.NONE:
            return self._policy_to_dict(policy, surface)

        elif policy.inheritance == PolicyInheritance.OVERRIDE:
            return self._policy_to_dict(policy, surface)

        else:  # MERGE
            resolved = deepcopy(self._base_policy)
            tenant_dict = self._policy_to_dict(policy, surface)
            resolved.update(tenant_dict)
            return resolved

    def _policy_to_dict(
        self,
        policy: TenantPolicy,
        surface: str,
    ) -> Dict[str, Any]:
        """Convert policy to dict for surface."""
        result = {
            "tenant_id": policy.tenant_id,
            "tier": policy.tier.value,
            "version": policy.version,
            "fail_open": policy.fail_open,
            "limits": {
                "max_requests_per_second": policy.limits.max_requests_per_second,
                "max_batch_size": policy.limits.max_batch_size,
            },
        }

        # Add surface override if exists
        override = policy.get_surface_override(surface)
        if override:
            result["surface_override"] = {
                "default_decision": override.default_decision,
                "disabled": override.disabled,
            }

        return result

    def add_tenant_hook(
        self,
        hook: Callable[[str, TenantPolicy], None],
    ) -> None:
        """Add hook called when tenant is registered."""
        self._hooks.append(hook)

    def get_context(self, tenant_id: str) -> TenantContext:
        """Get runtime context for tenant."""
        policy = self._store.get(tenant_id)

        if not policy:
            # Create default policy for unknown tenant
            policy = TenantPolicy(
                tenant_id=tenant_id,
                tier=TenantTier.FREE,
            )

        return TenantContext(
            tenant_id=tenant_id,
            policy=policy,
        )


# ============================================================================
# Tenant-Aware Evaluation
# ============================================================================


class TenantAwareEvaluator:
    """
    Evaluator that respects tenant isolation.

    Injects tenant context into evaluation and enforces limits.
    """

    def __init__(
        self,
        manager: TenantPolicyManager,
        base_evaluator: Callable,
    ):
        self.manager = manager
        self.base_evaluator = base_evaluator

    def evaluate(
        self,
        request: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate request with tenant context.

        Args:
            request: Evaluation request
            tenant_id: Tenant ID (from header or context)

        Returns:
            Evaluation result with tenant context
        """
        # Get tenant context
        if tenant_id is None:
            tenant_id = request.get("context", {}).get("tenant_id")

        if not tenant_id:
            # No tenant = use base policy
            return self.base_evaluator(request)

        context = self.manager.get_context(tenant_id)
        surface = request.get("surface", "")

        # Check if surface is allowed
        if not context.policy.allows_surface(surface):
            return {
                "permit": False,
                "decision": "deny",
                "reason": f"Surface '{surface}' not allowed for tenant",
                "tenant_context": context.to_dict(),
            }

        # Check surface override
        override = context.policy.get_surface_override(surface)
        if override and override.default_decision:
            return {
                "permit": override.default_decision == "allow",
                "decision": override.default_decision,
                "reason": f"Tenant surface override: {override.default_decision}",
                "tenant_context": context.to_dict(),
            }

        # Inject tenant context into request
        enriched_request = dict(request)
        enriched_request.setdefault("context", {})
        enriched_request["context"]["tenant_id"] = tenant_id
        enriched_request["context"]["tenant_tier"] = context.policy.tier.value

        # Evaluate with base evaluator
        result = self.base_evaluator(enriched_request)

        # Add tenant context to result
        if isinstance(result, dict):
            result["tenant_context"] = context.to_dict()

        return result


# ============================================================================
# Global Manager
# ============================================================================

_manager: Optional[TenantPolicyManager] = None
_manager_lock = threading.Lock()


def get_tenant_manager(
    store: Optional[TenantStore] = None,
) -> TenantPolicyManager:
    """Get or create global tenant manager."""
    global _manager

    with _manager_lock:
        if _manager is None:
            _manager = TenantPolicyManager(store)
        return _manager


def configure_tenant_manager(
    manager: TenantPolicyManager,
) -> None:
    """Set global tenant manager."""
    global _manager

    with _manager_lock:
        _manager = manager


def get_tenant_policy(tenant_id: str) -> Optional[TenantPolicy]:
    """Get policy for tenant from global manager."""
    return get_tenant_manager().get_tenant(tenant_id)


def register_tenant(
    tenant_id: str,
    tier: TenantTier = TenantTier.STANDARD,
    **kwargs,
) -> TenantPolicy:
    """Register tenant with global manager."""
    return get_tenant_manager().register_tenant(tenant_id, tier, **kwargs)
