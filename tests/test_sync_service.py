"""
TrigGuard Policy Sync Service Tests

Unit tests for distributed policy synchronization.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from trigguard.policy.sync_service import (
    PolicyVersion,
    PolicyBundle,
    SyncConfig,
    SyncState,
    SyncMode,
    SyncStatus,
    PolicyApplier,
    PolicySyncService,
    HttpPolicySource,
    get_sync_service,
    configure_sync_service,
)


class TestPolicyVersion:
    """Test PolicyVersion class."""

    def test_compute_hash(self):
        """Test hash computation is deterministic."""
        policy = {"rule": "allow", "surface": "read"}

        hash1 = PolicyVersion.compute_hash(policy)
        hash2 = PolicyVersion.compute_hash(policy)

        assert hash1 == hash2
        assert len(hash1) == 16

    def test_compute_hash_different(self):
        """Test different policies have different hashes."""
        hash1 = PolicyVersion.compute_hash({"rule": "allow"})
        hash2 = PolicyVersion.compute_hash({"rule": "deny"})

        assert hash1 != hash2

    def test_to_dict(self):
        """Test serialization."""
        version = PolicyVersion(
            version="1.0.0",
            hash="abc123",
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            created_by="test",
        )

        data = version.to_dict()

        assert data["version"] == "1.0.0"
        assert data["hash"] == "abc123"
        assert "2024" in data["created_at"]


class TestPolicyBundle:
    """Test PolicyBundle class."""

    def test_verify_integrity_valid(self):
        """Test integrity check passes for valid bundle."""
        policy_data = {"rule": "allow"}
        hash_val = PolicyVersion.compute_hash(policy_data)

        version = PolicyVersion(
            version="1.0",
            hash=hash_val,
            created_at=datetime.now(timezone.utc),
        )

        bundle = PolicyBundle(version=version, policy_data=policy_data)

        assert bundle.verify_integrity() is True

    def test_verify_integrity_invalid(self):
        """Test integrity check fails for tampered bundle."""
        policy_data = {"rule": "allow"}

        version = PolicyVersion(
            version="1.0",
            hash="wrong-hash",
            created_at=datetime.now(timezone.utc),
        )

        bundle = PolicyBundle(version=version, policy_data=policy_data)

        assert bundle.verify_integrity() is False


class TestSyncConfig:
    """Test SyncConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = SyncConfig()

        assert config.mode == SyncMode.PULL
        assert config.poll_interval_seconds == 60.0
        assert config.max_retries == 3


class TestSyncState:
    """Test SyncState."""

    def test_to_dict(self):
        """Test state serialization."""
        state = SyncState(
            status=SyncStatus.SYNCHRONIZED,
            current_version="1.0.0",
        )

        data = state.to_dict()

        assert data["status"] == "synchronized"
        assert data["current_version"] == "1.0.0"


class TestPolicyApplier:
    """Test PolicyApplier."""

    def _make_bundle(self, version: str) -> PolicyBundle:
        """Create test bundle."""
        policy_data = {"version": version}
        return PolicyBundle(
            version=PolicyVersion(
                version=version,
                hash=PolicyVersion.compute_hash(policy_data),
                created_at=datetime.now(timezone.utc),
            ),
            policy_data=policy_data,
        )

    def test_apply_new_policy(self):
        """Test applying new policy."""
        applier = PolicyApplier()
        bundle = self._make_bundle("1.0.0")

        applied = applier.apply(bundle)

        assert applied is True
        assert applier.current_version == "1.0.0"

    def test_apply_same_version_skipped(self):
        """Test applying same version is skipped."""
        applier = PolicyApplier()
        bundle = self._make_bundle("1.0.0")

        applier.apply(bundle)
        applied = applier.apply(bundle)

        assert applied is False

    def test_apply_invalid_hash_rejected(self):
        """Test applying bundle with invalid hash fails."""
        applier = PolicyApplier()

        bundle = PolicyBundle(
            version=PolicyVersion(
                version="1.0.0",
                hash="invalid-hash",
                created_at=datetime.now(timezone.utc),
            ),
            policy_data={"key": "value"},
        )

        with pytest.raises(ValueError, match="integrity"):
            applier.apply(bundle)

    def test_rollback(self):
        """Test rollback to previous version."""
        applier = PolicyApplier()

        applier.apply(self._make_bundle("1.0.0"))
        applier.apply(self._make_bundle("2.0.0"))

        assert applier.current_version == "2.0.0"

        rolled_back = applier.rollback()

        assert rolled_back is not None
        assert applier.current_version == "1.0.0"

    def test_rollback_empty(self):
        """Test rollback with no history."""
        applier = PolicyApplier()

        result = applier.rollback()
        assert result is None

    def test_on_apply_callback(self):
        """Test apply callback is called."""
        callback = Mock()
        applier = PolicyApplier(on_apply=callback)

        bundle = self._make_bundle("1.0.0")
        applier.apply(bundle)

        callback.assert_called_once_with(bundle)


class TestPolicySyncService:
    """Test PolicySyncService."""

    def _make_bundle(self, version: str) -> PolicyBundle:
        """Create test bundle."""
        policy_data = {"version": version}
        return PolicyBundle(
            version=PolicyVersion(
                version=version,
                hash=PolicyVersion.compute_hash(policy_data),
                created_at=datetime.now(timezone.utc),
            ),
            policy_data=policy_data,
        )

    @pytest.fixture
    def mock_source(self):
        """Create mock policy source."""
        source = AsyncMock()
        source.fetch_current_version = AsyncMock(
            return_value=PolicyVersion(
                version="1.0.0",
                hash=PolicyVersion.compute_hash({"version": "1.0.0"}),
                created_at=datetime.now(timezone.utc),
            )
        )
        source.fetch_policy = AsyncMock(return_value=self._make_bundle("1.0.0"))
        return source

    @pytest.mark.asyncio
    async def test_sync_once(self, mock_source):
        """Test single sync cycle."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL),
        )

        updated = await service._sync_once()

        assert updated is True
        assert service.current_version == "1.0.0"
        assert service.state.status == SyncStatus.SYNCHRONIZED

    @pytest.mark.asyncio
    async def test_sync_same_version_skipped(self, mock_source):
        """Test sync skips same version."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL),
        )

        await service._sync_once()
        updated = await service._sync_once()

        assert updated is False

    @pytest.mark.asyncio
    async def test_sync_error_handling(self, mock_source):
        """Test sync error is handled."""
        mock_source.fetch_current_version.side_effect = Exception("Network error")

        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL),
        )

        updated = await service._sync_once()

        assert updated is False
        assert service.state.status == SyncStatus.ERROR
        assert service.state.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_sync_degraded_mode(self, mock_source):
        """Test degraded mode after multiple failures."""
        mock_source.fetch_current_version.side_effect = Exception("Error")

        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL, max_retries=2),
        )

        await service._sync_once()
        await service._sync_once()

        assert service.state.status == SyncStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_force_sync(self, mock_source):
        """Test force sync."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL),
        )

        updated = await service.force_sync()

        assert updated is True

    @pytest.mark.asyncio
    async def test_rollback(self, mock_source):
        """Test rollback functionality."""

        def make_bundle_for_version(v):
            policy_data = {"version": v}
            return PolicyBundle(
                version=PolicyVersion(
                    version=v,
                    hash=PolicyVersion.compute_hash(policy_data),
                    created_at=datetime.now(timezone.utc),
                ),
                policy_data=policy_data,
            )

        # Version 1.0
        mock_source.fetch_current_version.return_value = PolicyVersion(
            version="1.0.0",
            hash=PolicyVersion.compute_hash({"version": "1.0.0"}),
            created_at=datetime.now(timezone.utc),
        )
        mock_source.fetch_policy.return_value = make_bundle_for_version("1.0.0")

        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL, allow_rollback=True),
        )

        await service._sync_once()

        # Version 2.0
        mock_source.fetch_current_version.return_value = PolicyVersion(
            version="2.0.0",
            hash=PolicyVersion.compute_hash({"version": "2.0.0"}),
            created_at=datetime.now(timezone.utc),
        )
        mock_source.fetch_policy.return_value = make_bundle_for_version("2.0.0")

        await service._sync_once()
        assert service.current_version == "2.0.0"

        # Rollback
        bundle = service.rollback()

        assert bundle is not None
        assert service.current_version == "1.0.0"

    @pytest.mark.asyncio
    async def test_rollback_disabled(self, mock_source):
        """Test rollback when disabled."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(allow_rollback=False),
        )

        with pytest.raises(ValueError, match="not allowed"):
            service.rollback()

    @pytest.mark.asyncio
    async def test_webhook_handler(self, mock_source):
        """Test webhook notification."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PUSH),
        )

        updated = await service.handle_webhook(
            {
                "version": "1.0.0",
                "hash": "abc",
            }
        )

        assert updated is True

    @pytest.mark.asyncio
    async def test_webhook_wrong_mode(self, mock_source):
        """Test webhook rejected in pull mode."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL),
        )

        with pytest.raises(ValueError, match="not enabled"):
            await service.handle_webhook({})

    @pytest.mark.asyncio
    async def test_context_manager(self, mock_source):
        """Test async context manager."""
        service = PolicySyncService(
            source=mock_source,
            config=SyncConfig(mode=SyncMode.PULL, poll_interval_seconds=0.1),
        )

        async with service:
            assert service._running is True
            await asyncio.sleep(0.05)

        assert service._running is False


class TestGlobalService:
    """Test global service functions."""

    def test_configure_sync_service(self):
        """Test configuring global service."""
        import trigguard.policy.sync_service as module

        module._sync_service = None

        service = configure_sync_service(
            source_url="http://test:8080",
            poll_interval_seconds=30,
        )

        assert service is not None
        assert service.config.source_url == "http://test:8080"
        assert service.config.poll_interval_seconds == 30

    def test_get_sync_service(self):
        """Test getting configured service."""
        import trigguard.policy.sync_service as module

        module._sync_service = None

        assert get_sync_service() is None

        configure_sync_service("http://test:8080")

        assert get_sync_service() is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
