"""
Well-Known Endpoints for TrigGuard

Provides public verification keys at standardized endpoints.
This makes Action Grants verifiable by any trusted executor
without requiring network calls to the issuing authority.

Endpoint:
    GET /.well-known/trigguard-keys

Response:
    {
        "issuer": "trigguard",
        "updated_at": "2026-03-27T12:00:00Z",
        "keys": [
            {
                "kid": "tg-root-1",
                "alg": "Ed25519",
                "public_key": "base64-encoded-public-key",
                "status": "active"
            }
        ]
    }

This follows the JWKS pattern but adapted for TrigGuard grants.
Executors cache these keys and verify grants offline.
"""

try:
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

    class APIRouter:
        def __init__(self, **kwargs):
            pass

        def get(self, *args, **kwargs):
            def decorator(f):
                return f

            return decorator

    class JSONResponse:
        def __init__(self, content, headers=None):
            self.content = content
            self.headers = headers or {}


from datetime import datetime, timezone
from typing import Optional

from trigguard.verification.public_keys import PublicKeySet, PublicKeyRecord

# Router for well-known endpoints
well_known_router = APIRouter(tags=["well-known"])

# Also export as 'router' for backwards compatibility
router = well_known_router

# Key set storage (configured at startup)
_current_key_set: Optional[PublicKeySet] = None

# Legacy key storage (for backwards compatibility)
_PUBLIC_KEYS: list[dict] = []
_ISSUER: str = "trigguard"
_EXPIRES_AT: Optional[datetime] = None


def configure_key_set(key_set: PublicKeySet) -> None:
    """
    Configure the public key set for discovery.

    Called during server startup to set the keys that will be
    served via /.well-known/trigguard-keys.

    Args:
        key_set: PublicKeySet to serve
    """
    global _current_key_set
    _current_key_set = key_set


def configure_keys(
    keys: list[dict],
    issuer: str = "trigguard",
    expires_at: Optional[datetime] = None,
) -> None:
    """
    Configure the public keys served by /.well-known/trigguard-keys.

    Legacy API - prefer configure_key_set() for new code.

    Args:
        keys: List of key dicts with kid, alg, public_key
        issuer: Issuer identifier
        expires_at: When these keys expire (optional)
    """
    global _PUBLIC_KEYS, _ISSUER, _EXPIRES_AT
    _PUBLIC_KEYS = keys
    _ISSUER = issuer
    _EXPIRES_AT = expires_at


def get_current_key_set() -> Optional[PublicKeySet]:
    """Get the currently configured key set."""
    return _current_key_set


def create_default_key_set(issuer: str = "trigguard") -> PublicKeySet:
    """
    Create a default key set for development/testing.

    In production, this should be replaced with actual keys.
    """
    return PublicKeySet(
        issuer=issuer,
        keys=[
            PublicKeyRecord(
                kid="tg-dev-1",
                alg="HMAC-SHA256",
                public_key="ZGV2LXNlY3JldC1mb3ItdGVzdGluZy1vbmx5",  # base64 placeholder
                status="active",
            )
        ],
    )


@well_known_router.get("/.well-known/trigguard-keys")
async def get_trigguard_keys():
    """
    Public key discovery endpoint.

    Returns the public keys used for Action Grant signature verification.
    Third-party executors can fetch these keys once and cache them.

    Response:
        {
            "issuer": "trigguard",
            "updated_at": "2026-03-27T12:00:00Z",
            "keys": [
                {
                    "kid": "tg-root-1",
                    "alg": "Ed25519",
                    "public_key": "...",
                    "status": "active",
                    "created_at": "..."
                }
            ]
        }
    """
    global _current_key_set

    # Use PublicKeySet if configured
    if _current_key_set is not None:
        return JSONResponse(
            content=_current_key_set.to_dict(),
            headers={
                "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
            },
        )

    # Fall back to legacy key storage
    if _PUBLIC_KEYS:
        response = {
            "keys": _PUBLIC_KEYS,
            "issuer": _ISSUER,
        }
        if _EXPIRES_AT:
            response["expires_at"] = _EXPIRES_AT.isoformat()
        return response

    # Return default for development
    _current_key_set = create_default_key_set()
    return JSONResponse(
        content=_current_key_set.to_dict(),
        headers={
            "Cache-Control": "public, max-age=3600",
        },
    )


@well_known_router.get("/.well-known/trigguard-config")
async def get_trigguard_config():
    """
    Configuration metadata endpoint.

    Returns TrigGuard configuration for executor discovery.
    """
    global _current_key_set

    issuer = _current_key_set.issuer if _current_key_set else _ISSUER

    return {
        "issuer": issuer,
        "supported_algorithms": ["Ed25519", "HMAC-SHA256"],
        "grant_version": "1.0",
        "protocol_version": "1.0",
        "keys_endpoint": "/.well-known/trigguard-keys",
        "documentation": "https://docs.trigguard.ai/verification-protocol",
    }


class TrigGuardKeyProvider:
    """
    Key provider for programmatic key management.

    Usage:
        provider = TrigGuardKeyProvider()
        provider.add_key(kid="tg-root-1", public_key=pk_bytes, alg="Ed25519")
        configure_keys(provider.keys)
    """

    def __init__(self, issuer: str = "trigguard"):
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
