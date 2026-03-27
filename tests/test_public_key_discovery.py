"""
Tests for Public Key Discovery

Tests for:
- PublicKeyRecord serialization
- PublicKeySet serialization
- Key lookup by kid
- Canonical JSON output
- build_public_key_set helper
"""

import pytest
import json
from datetime import datetime, timezone

from trigguard.verification.public_keys import (
    PublicKeyRecord,
    PublicKeySet,
    build_public_key_set,
)


class TestPublicKeyRecord:
    """Tests for PublicKeyRecord."""

    def test_create_record(self):
        """Can create a key record."""
        record = PublicKeyRecord(
            kid="tg-root-1",
            alg="Ed25519",
            public_key="YWJjZGVmMTIzNDU2",
            status="active",
        )

        assert record.kid == "tg-root-1"
        assert record.alg == "Ed25519"
        assert record.status == "active"
        assert record.created_at is not None

    def test_record_to_dict(self):
        """Record serializes to dict."""
        record = PublicKeyRecord(
            kid="tg-root-1",
            alg="Ed25519",
            public_key="YWJjZGVmMTIzNDU2",
            status="active",
            created_at="2026-03-27T12:00:00Z",
        )

        data = record.to_dict()

        assert data["kid"] == "tg-root-1"
        assert data["alg"] == "Ed25519"
        assert data["public_key"] == "YWJjZGVmMTIzNDU2"
        assert data["status"] == "active"
        assert data["created_at"] == "2026-03-27T12:00:00Z"

    def test_record_from_dict(self):
        """Record deserializes from dict."""
        data = {
            "kid": "tg-root-1",
            "alg": "Ed25519",
            "public_key": "YWJjZGVmMTIzNDU2",
            "status": "active",
            "created_at": "2026-03-27T12:00:00Z",
        }

        record = PublicKeyRecord.from_dict(data)

        assert record.kid == "tg-root-1"
        assert record.alg == "Ed25519"
        assert record.public_key == "YWJjZGVmMTIzNDU2"

    def test_record_canonical_json_is_deterministic(self):
        """Canonical JSON is deterministic."""
        record1 = PublicKeyRecord(
            kid="tg-root-1",
            alg="Ed25519",
            public_key="YWJjZGVmMTIzNDU2",
            status="active",
            created_at="2026-03-27T12:00:00Z",
        )

        record2 = PublicKeyRecord(
            kid="tg-root-1",
            alg="Ed25519",
            public_key="YWJjZGVmMTIzNDU2",
            status="active",
            created_at="2026-03-27T12:00:00Z",
        )

        assert record1.to_canonical_json() == record2.to_canonical_json()

    def test_record_from_bytes(self):
        """Can create record from raw bytes."""
        public_key_bytes = b"test-key-32-bytes-padding-here!!"

        record = PublicKeyRecord.from_bytes(
            kid="tg-test-1",
            public_key_bytes=public_key_bytes,
            alg="Ed25519",
        )

        assert record.kid == "tg-test-1"
        assert record.get_public_key_bytes() == public_key_bytes

    def test_record_includes_kid_and_alg(self):
        """Record includes kid and alg fields."""
        record = PublicKeyRecord(
            kid="tg-root-1",
            alg="Ed25519",
            public_key="YWJjZGVmMTIzNDU2",
        )

        data = record.to_dict()

        assert "kid" in data
        assert "alg" in data


class TestPublicKeySet:
    """Tests for PublicKeySet."""

    def test_create_key_set(self):
        """Can create a key set."""
        key_set = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                )
            ],
        )

        assert key_set.issuer == "trigguard"
        assert len(key_set.keys) == 1
        assert key_set.updated_at is not None

    def test_key_set_to_dict(self):
        """Key set serializes to dict."""
        key_set = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                    created_at="2026-03-27T12:00:00Z",
                )
            ],
            updated_at="2026-03-27T12:00:00Z",
        )

        data = key_set.to_dict()

        assert data["issuer"] == "trigguard"
        assert len(data["keys"]) == 1
        assert data["keys"][0]["kid"] == "tg-root-1"
        assert data["updated_at"] == "2026-03-27T12:00:00Z"

    def test_key_set_from_dict(self):
        """Key set deserializes from dict."""
        data = {
            "issuer": "trigguard",
            "keys": [
                {
                    "kid": "tg-root-1",
                    "alg": "Ed25519",
                    "public_key": "YWJjZGVmMTIzNDU2",
                    "status": "active",
                    "created_at": "2026-03-27T12:00:00Z",
                }
            ],
            "updated_at": "2026-03-27T12:00:00Z",
        }

        key_set = PublicKeySet.from_dict(data)

        assert key_set.issuer == "trigguard"
        assert len(key_set.keys) == 1
        assert key_set.keys[0].kid == "tg-root-1"

    def test_get_key_by_kid(self):
        """Can lookup key by kid."""
        key_set = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(kid="tg-root-1", alg="Ed25519", public_key="key1"),
                PublicKeyRecord(kid="tg-root-2", alg="Ed25519", public_key="key2"),
            ],
        )

        key1 = key_set.get_key("tg-root-1")
        key2 = key_set.get_key("tg-root-2")
        key3 = key_set.get_key("nonexistent")

        assert key1 is not None
        assert key1.public_key == "key1"
        assert key2 is not None
        assert key2.public_key == "key2"
        assert key3 is None

    def test_get_active_keys(self):
        """Can filter active keys."""
        key_set = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="active-1", alg="Ed25519", public_key="k1", status="active"
                ),
                PublicKeyRecord(
                    kid="rotated-1", alg="Ed25519", public_key="k2", status="rotated"
                ),
                PublicKeyRecord(
                    kid="active-2", alg="Ed25519", public_key="k3", status="active"
                ),
            ],
        )

        active = key_set.get_active_keys()

        assert len(active) == 2
        assert all(k.status == "active" for k in active)

    def test_add_key(self):
        """Can add keys to set."""
        key_set = PublicKeySet(issuer="trigguard")

        assert len(key_set.keys) == 0

        key_set.add_key(PublicKeyRecord(kid="new-key", alg="Ed25519", public_key="k"))

        assert len(key_set.keys) == 1
        assert key_set.get_key("new-key") is not None

    def test_canonical_json_is_deterministic(self):
        """Canonical JSON output is deterministic."""
        key_set1 = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                    status="active",
                    created_at="2026-03-27T12:00:00Z",
                )
            ],
            updated_at="2026-03-27T12:00:00Z",
        )

        key_set2 = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                    status="active",
                    created_at="2026-03-27T12:00:00Z",
                )
            ],
            updated_at="2026-03-27T12:00:00Z",
        )

        assert key_set1.to_canonical_json() == key_set2.to_canonical_json()


class TestBuildPublicKeySet:
    """Tests for build_public_key_set helper."""

    def test_build_key_set(self):
        """Helper builds key set from raw data."""
        keys = [
            ("tg-root-1", b"public-key-1-bytes!", "Ed25519"),
            ("tg-root-2", b"public-key-2-bytes!", "Ed25519"),
        ]

        key_set = build_public_key_set("trigguard", keys)

        assert key_set.issuer == "trigguard"
        assert len(key_set.keys) == 2
        assert key_set.get_key("tg-root-1") is not None
        assert key_set.get_key("tg-root-2") is not None


class TestWellKnownResponseShape:
    """Tests for /.well-known/trigguard-keys response format."""

    def test_response_shape(self):
        """Response has expected shape."""
        key_set = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                    status="active",
                    created_at="2026-03-27T12:00:00Z",
                )
            ],
            updated_at="2026-03-27T12:00:00Z",
        )

        response = key_set.to_dict()

        # Required fields
        assert "issuer" in response
        assert "keys" in response
        assert "updated_at" in response

        # Key record fields
        key = response["keys"][0]
        assert "kid" in key
        assert "alg" in key
        assert "public_key" in key
        assert "status" in key
        assert "created_at" in key

    def test_response_is_valid_json(self):
        """Response is valid JSON."""
        key_set = PublicKeySet(
            issuer="trigguard",
            keys=[
                PublicKeyRecord(
                    kid="tg-root-1",
                    alg="Ed25519",
                    public_key="YWJjZGVmMTIzNDU2",
                )
            ],
        )

        json_str = key_set.to_canonical_json()
        parsed = json.loads(json_str)

        assert parsed["issuer"] == "trigguard"
        assert len(parsed["keys"]) == 1
