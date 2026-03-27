"""
Well-Known Endpoints for TrigGuard

Provides public verification keys at standardized endpoints.
This makes Action Grants verifiable by any trusted executor
without requiring network calls to the issuing authority.

Endpoint:
    GET /.well-known/trigguard-keys

Response:
    {
        "keys": [
            {
                "kid": "tg-root-1",
                "alg": "Ed25519",
                "use": "sig",
                "public_key": "base64-encoded-public-key"
            }
        ],
        "issuer": "trigguard-kernel",
        "expires_at": "2026-12-31T23:59:59Z"
    }

This follows the JWKS pattern but adapted for TrigGuard grants.
Executors cache these keys and verify grants offline.
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends

router = APIRouter(tags=["well-known"])


# Key storage (in production, this would be injected/configured)
_PUBLIC_KEYS: list[dict] = []
_ISSUER: str = "trigguard-kernel"
_EXPIRES_AT: Optional[datetime] = None


def configure_keys(
    keys: list[dict],
    issuer: str = "trigguard-kernel",
    expires_at: Optional[datetime] = None,
) -> None:
    """
    Configure the public keys served by /.well-known/trigguard-keys.

    Args:
        keys: List of key dicts with kid, alg, public_key
        issuer: Issuer identifier
        expires_at: When these keys expire (optional)
    """
    global _PUBLIC_KEYS, _ISSUER, _EXPIRES_AT
    _PUBLIC_KEYS = keys
    _ISSUER = issuer
    _EXPIRES_AT = expires_at


@router.get("/.well-known/trigguard-keys")
def get_trigguard_keys() -> dict:
    """
    Return public keys for Action Grant verification.

    This endpoint enables offline verification of Action Grants.
    Executors fetch these keys once and cache them.

    Response format follows JWKS-style pattern:
    - keys: Array of key objects
    - issuer: Identity of the key issuer
    - expires_at: When to refresh keys (optional)
    """
    response = {
        "keys": _PUBLIC_KEYS,
        "issuer": _ISSUER,
    }

    if _EXPIRES_AT:
        response["expires_at"] = _EXPIRES_AT.isoformat()

    return response


@router.get("/.well-known/trigguard-config")
def get_trigguard_config() -> dict:
    """
    Return TrigGuard configuration metadata.

    This helps executors discover:
    - Supported algorithms
    - Grant verification endpoint
    - Key rotation schedule
    """
    return {
        "issuer": _ISSUER,
        "supported_algorithms": ["Ed25519", "HMAC-SHA256"],
        "grant_version": "1.0",
        "keys_endpoint": "/.well-known/trigguard-keys",
        "documentation": "https://docs.trigguard.ai/grants",
    }


class TrigGuardKeyProvider:
    """
    Key provider for programmatic key management.

    Usage:
        provider = TrigGuardKeyProvider()
        provider.add_key(kid="tg-root-1", public_key=pk_bytes, alg="Ed25519")
        configure_keys(provider.keys)
    """

    def __init__(self, issuer: str = "trigguard-kernel"):
        self.issuer = issuer
        self.keys: list[dict] = []

    def add_key(
        self,
        kid: str,
        public_key: bytes,
        alg: str = "Ed25519",
        use: str = "sig",
    ) -> None:
        """Add a public key to the provider."""
        import base64

        self.keys.append(
            {
                "kid": kid,
                "alg": alg,
                "use": use,
                "public_key": base64.b64encode(public_key).decode("ascii"),
            }
        )

    def remove_key(self, kid: str) -> bool:
        """Remove a key by kid. Returns True if found."""
        for i, key in enumerate(self.keys):
            if key["kid"] == kid:
                self.keys.pop(i)
                return True
        return False

    def activate(self, expires_at: Optional[datetime] = None) -> None:
        """Activate this provider's keys globally."""
        configure_keys(
            keys=self.keys,
            issuer=self.issuer,
            expires_at=expires_at,
        )
