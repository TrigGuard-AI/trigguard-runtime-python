"""
Public Key Discovery

Data structures for public key discovery via /.well-known/trigguard-keys.

This enables offline verification of Action Grants by providing:
- Key records with kid (key ID) for rotation
- Key sets with issuer identity
- Canonical serialization for deterministic output

Third-party executors can:
1. Fetch keys from /.well-known/trigguard-keys
2. Cache the key set
3. Verify grants offline using cached keys
"""

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Union


@dataclass
class PublicKeyRecord:
    """
    A single public key record for grant verification.

    Fields:
        kid: Key ID for rotation support (e.g., "tg-root-1")
        alg: Algorithm (e.g., "Ed25519", "HMAC-SHA256")
        public_key: Base64-encoded public key bytes
        status: Key status ("active", "rotated", "revoked")
        created_at: When the key was created (ISO 8601)
    """

    kid: str
    alg: str
    public_key: str
    status: str = "active"
    created_at: Optional[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "alg": self.alg,
            "created_at": self.created_at,
            "kid": self.kid,
            "public_key": self.public_key,
            "status": self.status,
        }

    def to_canonical_json(self) -> str:
        """Canonical JSON for deterministic output."""
        return json.dumps(
            self.to_dict(),
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PublicKeyRecord":
        """Create from dictionary."""
        return cls(
            kid=data["kid"],
            alg=data["alg"],
            public_key=data["public_key"],
            status=data.get("status", "active"),
            created_at=data.get("created_at"),
        )

    def get_public_key_bytes(self) -> bytes:
        """Decode the public key to bytes."""
        return base64.b64decode(self.public_key)

    @classmethod
    def from_bytes(
        cls,
        kid: str,
        public_key_bytes: bytes,
        alg: str = "Ed25519",
        status: str = "active",
    ) -> "PublicKeyRecord":
        """Create from raw public key bytes."""
        return cls(
            kid=kid,
            alg=alg,
            public_key=base64.b64encode(public_key_bytes).decode("ascii"),
            status=status,
        )


@dataclass
class PublicKeySet:
    """
    A set of public keys from a TrigGuard issuer.

    This is the response format for /.well-known/trigguard-keys.

    Fields:
        issuer: Issuer identity (e.g., "trigguard-kernel")
        keys: List of public key records
        updated_at: When the key set was last updated (ISO 8601)
    """

    issuer: str
    keys: list[PublicKeyRecord] = field(default_factory=list)
    updated_at: Optional[str] = None

    def __post_init__(self):
        if self.updated_at is None:
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "issuer": self.issuer,
            "keys": [k.to_dict() for k in self.keys],
            "updated_at": self.updated_at,
        }

    def to_canonical_json(self) -> str:
        """Canonical JSON for deterministic output."""
        return json.dumps(
            self.to_dict(),
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PublicKeySet":
        """Create from dictionary (e.g., from API response)."""
        return cls(
            issuer=data["issuer"],
            keys=[PublicKeyRecord.from_dict(k) for k in data.get("keys", [])],
            updated_at=data.get("updated_at"),
        )

    def get_key(self, kid: str) -> Optional[PublicKeyRecord]:
        """Get a key by its ID."""
        for key in self.keys:
            if key.kid == kid:
                return key
        return None

    def get_active_keys(self) -> list[PublicKeyRecord]:
        """Get all active keys."""
        return [k for k in self.keys if k.status == "active"]

    def add_key(self, key: PublicKeyRecord) -> None:
        """Add a key to the set."""
        self.keys.append(key)
        self.updated_at = datetime.now(timezone.utc).isoformat()


def build_public_key_set(
    issuer: str,
    keys: list[tuple[str, bytes, str]],
) -> PublicKeySet:
    """
    Build a PublicKeySet from raw key data.

    Args:
        issuer: Issuer identity
        keys: List of (kid, public_key_bytes, alg) tuples

    Returns:
        PublicKeySet ready for serialization
    """
    key_set = PublicKeySet(issuer=issuer)
    for kid, public_key_bytes, alg in keys:
        key_set.add_key(
            PublicKeyRecord.from_bytes(
                kid=kid,
                public_key_bytes=public_key_bytes,
                alg=alg,
            )
        )
    return key_set
