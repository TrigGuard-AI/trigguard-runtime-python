"""
TrigGuard Key Rotation Manager

Manages public keys for grant verification with support for:
- Key registration and revocation
- Key rotation policies
- Grace periods for old keys
- Key discovery endpoint integration
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional
import hashlib
import logging

logger = logging.getLogger(__name__)


class KeyStatus(Enum):
    """Status of a registered key."""

    ACTIVE = "active"
    ROTATING = "rotating"  # Being phased out
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class KeyEntry:
    """A registered public key entry."""

    key_id: str
    public_key: str
    algorithm: str = "RS256"
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """Check if key is currently valid for verification."""
        if self.status == KeyStatus.REVOKED:
            return False
        if self.status == KeyStatus.EXPIRED:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    @property
    def is_active(self) -> bool:
        """Check if key is active (not rotating or revoked)."""
        return self.status == KeyStatus.ACTIVE and self.is_valid

    def to_jwk(self) -> dict[str, Any]:
        """Export key as JWK format."""
        return {
            "kid": self.key_id,
            "kty": "RSA",  # Assuming RSA for now
            "alg": self.algorithm,
            "use": "sig",
            "key_ops": ["verify"],
            "n": self.public_key,  # Base64url encoded modulus
            "e": "AQAB",  # Standard public exponent
        }


@dataclass
class KeyRotationPolicy:
    """Policy for automatic key rotation."""

    rotation_period: timedelta = field(default_factory=lambda: timedelta(days=90))
    grace_period: timedelta = field(default_factory=lambda: timedelta(days=7))
    max_concurrent_keys: int = 3
    auto_revoke_expired: bool = True


class KeyRotationManager:
    """
    Manages TrigGuard public keys with rotation support.

    Features:
    - Register new keys with unique IDs
    - Rotate keys with grace periods
    - Revoke compromised keys immediately
    - Automatic expiration handling
    - JWKS endpoint integration
    """

    def __init__(self, policy: Optional[KeyRotationPolicy] = None):
        self._keys: dict[str, KeyEntry] = {}
        self._policy = policy or KeyRotationPolicy()
        self._primary_key_id: Optional[str] = None

    def add_key(
        self,
        key_id: str,
        public_key: str,
        algorithm: str = "RS256",
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> KeyEntry:
        """
        Add a new public key.

        Args:
            key_id: Unique identifier for the key
            public_key: The public key material (PEM or base64)
            algorithm: Signing algorithm (default: RS256)
            expires_at: Optional expiration time
            metadata: Optional metadata

        Returns:
            The created KeyEntry
        """
        if key_id in self._keys:
            raise ValueError(f"Key already exists: {key_id}")

        # Check max concurrent keys
        active_keys = [k for k in self._keys.values() if k.is_valid]
        if len(active_keys) >= self._policy.max_concurrent_keys:
            raise ValueError(
                f"Maximum concurrent keys ({self._policy.max_concurrent_keys}) reached"
            )

        entry = KeyEntry(
            key_id=key_id,
            public_key=public_key,
            algorithm=algorithm,
            expires_at=expires_at,
            metadata=metadata or {},
        )

        self._keys[key_id] = entry

        # Set as primary if first key
        if self._primary_key_id is None:
            self._primary_key_id = key_id

        logger.info(f"Added key: {key_id}")
        return entry

    def revoke_key(self, key_id: str, reason: Optional[str] = None) -> None:
        """
        Immediately revoke a key.

        Args:
            key_id: The key to revoke
            reason: Optional reason for revocation
        """
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")

        entry = self._keys[key_id]
        entry.status = KeyStatus.REVOKED
        entry.revoked_at = datetime.now(timezone.utc)
        if reason:
            entry.metadata["revocation_reason"] = reason

        # Update primary if needed
        if self._primary_key_id == key_id:
            self._elect_new_primary()

        logger.warning(f"Revoked key: {key_id} (reason: {reason})")

    def rotate_key(self, key_id: str, new_key_id: str, new_public_key: str) -> KeyEntry:
        """
        Rotate an existing key to a new key.

        The old key enters ROTATING status with a grace period.

        Args:
            key_id: The key to rotate
            new_key_id: ID for the new key
            new_public_key: New public key material

        Returns:
            The new KeyEntry
        """
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")

        old_entry = self._keys[key_id]

        # Mark old key as rotating with grace period expiration
        old_entry.status = KeyStatus.ROTATING
        old_entry.expires_at = datetime.now(timezone.utc) + self._policy.grace_period

        # Add new key
        new_entry = self.add_key(
            key_id=new_key_id,
            public_key=new_public_key,
            algorithm=old_entry.algorithm,
            metadata={"rotated_from": key_id},
        )

        # Update primary
        if self._primary_key_id == key_id:
            self._primary_key_id = new_key_id

        logger.info(f"Rotated key {key_id} -> {new_key_id}")
        return new_entry

    def get_key(self, key_id: str) -> Optional[KeyEntry]:
        """Get a key by ID."""
        return self._keys.get(key_id)

    def get_valid_key(self, key_id: str) -> Optional[KeyEntry]:
        """Get a key by ID, only if it's valid for verification."""
        entry = self._keys.get(key_id)
        if entry and entry.is_valid:
            return entry
        return None

    def get_primary_key(self) -> Optional[KeyEntry]:
        """Get the current primary (active) key."""
        if self._primary_key_id:
            return self._keys.get(self._primary_key_id)
        return None

    def list_keys(self, include_revoked: bool = False) -> list[KeyEntry]:
        """List all keys, optionally including revoked ones."""
        self._cleanup_expired()
        if include_revoked:
            return list(self._keys.values())
        return [k for k in self._keys.values() if k.status != KeyStatus.REVOKED]

    def list_valid_keys(self) -> list[KeyEntry]:
        """List only keys valid for verification."""
        self._cleanup_expired()
        return [k for k in self._keys.values() if k.is_valid]

    def to_jwks(self) -> dict[str, Any]:
        """
        Export all valid keys as a JWKS (JSON Web Key Set).

        This can be served at /.well-known/trigguard-keys
        """
        valid_keys = self.list_valid_keys()
        return {
            "keys": [k.to_jwk() for k in valid_keys],
        }

    def _elect_new_primary(self) -> None:
        """Elect a new primary key from active keys."""
        for entry in self._keys.values():
            if entry.is_active:
                self._primary_key_id = entry.key_id
                logger.info(f"Elected new primary key: {entry.key_id}")
                return
        self._primary_key_id = None
        logger.warning("No active keys available for primary")

    def _cleanup_expired(self) -> None:
        """Mark expired keys appropriately."""
        now = datetime.now(timezone.utc)
        for entry in self._keys.values():
            if entry.expires_at and now > entry.expires_at:
                if entry.status not in (KeyStatus.REVOKED, KeyStatus.EXPIRED):
                    entry.status = KeyStatus.EXPIRED
                    logger.info(f"Key expired: {entry.key_id}")

    @property
    def primary_key_id(self) -> Optional[str]:
        """Get the current primary key ID."""
        return self._primary_key_id

    @property
    def policy(self) -> KeyRotationPolicy:
        """Get the rotation policy."""
        return self._policy

    def needs_rotation(self) -> list[str]:
        """Get list of key IDs that need rotation based on policy."""
        results = []
        now = datetime.now(timezone.utc)
        rotation_threshold = now - self._policy.rotation_period

        for entry in self._keys.values():
            if entry.is_active and entry.created_at < rotation_threshold:
                results.append(entry.key_id)

        return results


def generate_key_id(public_key: str) -> str:
    """Generate a key ID from public key material."""
    return hashlib.sha256(public_key.encode()).hexdigest()[:16]
