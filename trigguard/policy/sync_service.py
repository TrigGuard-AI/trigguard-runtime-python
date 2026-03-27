"""
TrigGuard Policy Sync Service

Distributed policy synchronization for multi-node deployments.

Features:
    - Push-based policy updates
    - Pull-based periodic sync
    - Version consistency checks
    - Atomic policy transitions
    - Rollback support

Usage:
    from trigguard.policy.sync_service import PolicySyncService, start_sync

    sync = PolicySyncService(
        source_url="http://policy-server:8080",
        poll_interval=60,
    )
    await sync.start()
"""

import asyncio
import hashlib
import json
import time
import threading
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Tuple
from datetime import datetime, timezone
from contextlib import asynccontextmanager

logger = logging.getLogger("trigguard.policy.sync")


class SyncMode(Enum):
    """Policy sync mode."""

    PUSH = "push"  # Server pushes updates
    PULL = "pull"  # Client polls for updates
    HYBRID = "hybrid"  # Both modes


class SyncStatus(Enum):
    """Sync status."""

    IDLE = "idle"
    SYNCING = "syncing"
    SYNCHRONIZED = "synchronized"
    ERROR = "error"
    DEGRADED = "degraded"


@dataclass
class PolicyVersion:
    """Policy version metadata."""

    version: str
    hash: str
    created_at: datetime
    created_by: str = "system"
    description: str = ""

    @classmethod
    def compute_hash(cls, policy_data: Dict[str, Any]) -> str:
        """Compute deterministic hash of policy."""
        canonical = json.dumps(policy_data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "hash": self.hash,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "description": self.description,
        }


@dataclass
class PolicyBundle:
    """Full policy bundle for sync."""

    version: PolicyVersion
    policy_data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def verify_integrity(self) -> bool:
        """Verify hash matches policy data."""
        computed = PolicyVersion.compute_hash(self.policy_data)
        return computed == self.version.hash


@dataclass
class SyncConfig:
    """Configuration for policy sync."""

    mode: SyncMode = SyncMode.PULL

    # Pull mode settings
    source_url: str = ""
    poll_interval_seconds: float = 60.0

    # Push mode settings
    webhook_secret: str = ""

    # Retry settings
    max_retries: int = 3
    retry_delay_seconds: float = 5.0

    # Consistency settings
    require_hash_match: bool = True
    allow_rollback: bool = True
    max_version_age_seconds: float = 3600.0

    # Callbacks
    on_update: Optional[Callable[[PolicyBundle], None]] = None
    on_error: Optional[Callable[[Exception], None]] = None


@dataclass
class SyncState:
    """Current sync state."""

    status: SyncStatus = SyncStatus.IDLE
    current_version: Optional[str] = None
    current_hash: Optional[str] = None
    last_sync_at: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "current_version": self.current_version,
            "current_hash": self.current_hash,
            "last_sync_at": (
                self.last_sync_at.isoformat() if self.last_sync_at else None
            ),
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
        }


class PolicySource(ABC):
    """Abstract policy source."""

    @abstractmethod
    async def fetch_current_version(self) -> PolicyVersion:
        """Fetch current version metadata."""
        pass

    @abstractmethod
    async def fetch_policy(self, version: Optional[str] = None) -> PolicyBundle:
        """Fetch full policy bundle."""
        pass

    @abstractmethod
    async def list_versions(self, limit: int = 10) -> List[PolicyVersion]:
        """List available versions."""
        pass


class HttpPolicySource(PolicySource):
    """HTTP-based policy source."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = None

    async def _get_client(self):
        """Get or create HTTP client."""
        if self._client is None:
            try:
                import httpx

                headers = {}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                self._client = httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=self.timeout,
                    headers=headers,
                )
            except ImportError:
                raise ImportError("httpx required. pip install httpx")
        return self._client

    async def fetch_current_version(self) -> PolicyVersion:
        """Fetch current version from trigguard.server."""
        client = await self._get_client()
        response = await client.get("/policy/version")
        response.raise_for_status()
        data = response.json()

        return PolicyVersion(
            version=data["version"],
            hash=data["hash"],
            created_at=datetime.fromisoformat(data["created_at"]),
            created_by=data.get("created_by", "unknown"),
        )

    async def fetch_policy(self, version: Optional[str] = None) -> PolicyBundle:
        """Fetch policy bundle from trigguard.server."""
        client = await self._get_client()

        url = "/policy"
        if version:
            url = f"/policy/versions/{version}"

        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

        version_info = PolicyVersion(
            version=data["version"]["version"],
            hash=data["version"]["hash"],
            created_at=datetime.fromisoformat(data["version"]["created_at"]),
        )

        return PolicyBundle(
            version=version_info,
            policy_data=data["policy"],
            metadata=data.get("metadata", {}),
        )

    async def list_versions(self, limit: int = 10) -> List[PolicyVersion]:
        """List available versions."""
        client = await self._get_client()
        response = await client.get(f"/policy/versions?limit={limit}")
        response.raise_for_status()
        data = response.json()

        return [
            PolicyVersion(
                version=v["version"],
                hash=v["hash"],
                created_at=datetime.fromisoformat(v["created_at"]),
            )
            for v in data["versions"]
        ]

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class PolicyApplier:
    """Applies policy updates atomically."""

    def __init__(
        self,
        on_apply: Optional[Callable[[PolicyBundle], None]] = None,
    ):
        self._current_bundle: Optional[PolicyBundle] = None
        self._history: List[PolicyBundle] = []
        self._max_history = 10
        self._lock = threading.Lock()
        self._on_apply = on_apply

    def apply(self, bundle: PolicyBundle) -> bool:
        """
        Apply new policy bundle.

        Returns True if applied, False if skipped (same version).
        """
        with self._lock:
            # Check if same version
            if self._current_bundle:
                if self._current_bundle.version.version == bundle.version.version:
                    return False

            # Verify integrity
            if not bundle.verify_integrity():
                raise ValueError(
                    f"Policy integrity check failed: "
                    f"hash mismatch for {bundle.version.version}"
                )

            # Store previous for rollback
            if self._current_bundle:
                self._history.append(self._current_bundle)
                if len(self._history) > self._max_history:
                    self._history.pop(0)

            # Apply
            self._current_bundle = bundle

            logger.info(
                f"Applied policy version {bundle.version.version} "
                f"(hash: {bundle.version.hash})"
            )

            if self._on_apply:
                try:
                    self._on_apply(bundle)
                except Exception as e:
                    logger.error(f"Policy apply callback failed: {e}")

            return True

    def rollback(self) -> Optional[PolicyBundle]:
        """Rollback to previous version."""
        with self._lock:
            if not self._history:
                return None

            previous = self._history.pop()
            self._current_bundle = previous

            logger.warning(f"Rolled back to version {previous.version.version}")

            return previous

    @property
    def current(self) -> Optional[PolicyBundle]:
        """Get current policy bundle."""
        return self._current_bundle

    @property
    def current_version(self) -> Optional[str]:
        """Get current version string."""
        if self._current_bundle:
            return self._current_bundle.version.version
        return None


class PolicySyncService:
    """
    Policy synchronization service.

    Manages policy updates from remote source with consistency guarantees.
    """

    def __init__(
        self,
        source: Optional[PolicySource] = None,
        config: Optional[SyncConfig] = None,
    ):
        self.config = config or SyncConfig()

        if source:
            self._source = source
        elif self.config.source_url:
            self._source = HttpPolicySource(self.config.source_url)
        else:
            self._source = None

        self._applier = PolicyApplier(on_apply=self.config.on_update)
        self._state = SyncState()
        self._running = False
        self._sync_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> SyncState:
        """Get current sync state."""
        return self._state

    @property
    def current_version(self) -> Optional[str]:
        """Get current policy version."""
        return self._applier.current_version

    async def start(self) -> None:
        """Start sync service."""
        if self._running:
            return

        if not self._source:
            raise ValueError("No policy source configured")

        self._running = True

        # Initial sync
        await self._sync_once()

        # Start background task for pull mode
        if self.config.mode in (SyncMode.PULL, SyncMode.HYBRID):
            self._sync_task = asyncio.create_task(self._poll_loop())

        logger.info(f"Policy sync started (mode={self.config.mode.value})")

    async def stop(self) -> None:
        """Stop sync service."""
        self._running = False

        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass

        if isinstance(self._source, HttpPolicySource):
            await self._source.close()

        logger.info("Policy sync stopped")

    async def _poll_loop(self) -> None:
        """Background polling loop."""
        while self._running:
            try:
                await asyncio.sleep(self.config.poll_interval_seconds)
                await self._sync_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sync poll failed: {e}")
                await asyncio.sleep(self.config.retry_delay_seconds)

    async def _sync_once(self) -> bool:
        """
        Perform one sync cycle.

        Returns True if policy was updated.
        """
        async with self._lock:
            self._state.status = SyncStatus.SYNCING

            try:
                # Check version first
                remote_version = await self._source.fetch_current_version()

                # Skip if same version
                if self._state.current_version == remote_version.version:
                    self._state.status = SyncStatus.SYNCHRONIZED
                    return False

                # Fetch full policy
                bundle = await self._source.fetch_policy(remote_version.version)

                # Apply
                applied = self._applier.apply(bundle)

                if applied:
                    self._state.current_version = bundle.version.version
                    self._state.current_hash = bundle.version.hash

                self._state.status = SyncStatus.SYNCHRONIZED
                self._state.last_sync_at = datetime.now(timezone.utc)
                self._state.consecutive_failures = 0
                self._state.last_error = None

                return applied

            except Exception as e:
                self._state.status = SyncStatus.ERROR
                self._state.last_error = str(e)
                self._state.consecutive_failures += 1

                logger.error(f"Policy sync failed: {e}")

                if self.config.on_error:
                    self.config.on_error(e)

                # Trigger degraded mode after multiple failures
                if self._state.consecutive_failures >= self.config.max_retries:
                    self._state.status = SyncStatus.DEGRADED

                return False

    async def force_sync(self) -> bool:
        """Force immediate sync."""
        return await self._sync_once()

    async def handle_webhook(self, payload: Dict[str, Any]) -> bool:
        """
        Handle push webhook notification.

        Args:
            payload: Webhook payload with version info

        Returns:
            True if policy was updated
        """
        if self.config.mode not in (SyncMode.PUSH, SyncMode.HYBRID):
            raise ValueError("Webhook not enabled in current mode")

        # Verify webhook secret if configured
        if self.config.webhook_secret:
            payload_secret = payload.get("secret")
            if payload_secret != self.config.webhook_secret:
                raise ValueError("Invalid webhook secret")

        # Trigger sync
        return await self._sync_once()

    def rollback(self) -> Optional[PolicyBundle]:
        """Rollback to previous version."""
        if not self.config.allow_rollback:
            raise ValueError("Rollback not allowed")

        bundle = self._applier.rollback()

        if bundle:
            self._state.current_version = bundle.version.version
            self._state.current_hash = bundle.version.hash

        return bundle

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()


# ============================================================================
# Global Service
# ============================================================================

_sync_service: Optional[PolicySyncService] = None
_sync_lock = threading.Lock()


def get_sync_service() -> Optional[PolicySyncService]:
    """Get global sync service."""
    return _sync_service


def configure_sync_service(
    source_url: str,
    **kwargs,
) -> PolicySyncService:
    """Configure global sync service."""
    global _sync_service

    with _sync_lock:
        config = SyncConfig(source_url=source_url, **kwargs)
        _sync_service = PolicySyncService(config=config)
        return _sync_service


async def start_sync(
    source_url: str,
    **kwargs,
) -> PolicySyncService:
    """Start global sync service."""
    service = configure_sync_service(source_url, **kwargs)
    await service.start()
    return service


# ============================================================================
# Webhook Handler
# ============================================================================


def create_webhook_handler():
    """
    Create FastAPI webhook handler.

    Usage:
        app.include_router(create_webhook_handler())
    """
    try:
        from fastapi import APIRouter, HTTPException, Header
        from pydantic import BaseModel
    except ImportError:
        return None

    router = APIRouter(prefix="/policy", tags=["policy-sync"])

    class WebhookPayload(BaseModel):
        version: str
        hash: str
        secret: Optional[str] = None

    @router.post("/webhook")
    async def policy_webhook(payload: WebhookPayload):
        """Receive policy update notification."""
        service = get_sync_service()
        if not service:
            raise HTTPException(503, "Sync service not configured")

        try:
            updated = await service.handle_webhook(payload.model_dump())
            return {"updated": updated, "version": service.current_version}
        except ValueError as e:
            raise HTTPException(400, str(e))

    @router.get("/status")
    async def sync_status():
        """Get sync status."""
        service = get_sync_service()
        if not service:
            return {"status": "not_configured"}

        return service.state.to_dict()

    @router.post("/sync")
    async def force_sync():
        """Force immediate sync."""
        service = get_sync_service()
        if not service:
            raise HTTPException(503, "Sync service not configured")

        updated = await service.force_sync()
        return {"updated": updated, "version": service.current_version}

    return router
