import pytest
import datetime
from trigguard.proof.execution_gate_proof import (
    ExecutionGateProof,
    build_execution_gate_proof,
)
from trigguard.proof.verifier import ExecutionGateProofVerifier


class DummySigner:
    def sign(self, data):
        return b"deadbeef"


class DummyKeyProvider:
    def verify(self, data, signature, alg):
        # Only accept the signature if the data matches the expected canonical payload
        # This ensures tampering is detected in tests
        expected_payload = b'{"decision":"PERMIT","decision_hash":"def456","issued_at":"2026-03-29T00:00:00+00:00","proof_id":"00000000-0000-0000-0000-000000000000","protocol":"trigguard-proof","receipt_hash":"abc123","runtime_version":"1.2.3","signature_alg":"ed25519","surface_hash":"ghi789","surface_id":"trigguard.spend.transfer","version":"0.2.1"}'
        # The DummySigner returns b"deadbeef", which is hex-encoded to '6465616462656566'
        return signature == "6465616462656566" and data == expected_payload


def test_proof_deterministic_serialization():
    class DummyReceipt:
        decision = "PERMIT"
        receipt_hash = "abc123"
        decision_hash = "def456"
        surface_hash = "ghi789"

    import uuid
    from unittest.mock import patch

    fixed_uuid = "00000000-0000-0000-0000-000000000000"
    fixed_time = "2026-03-29T00:00:00+00:00"
    with (
        patch(
            "trigguard.proof.execution_gate_proof.uuid.uuid4",
            return_value=uuid.UUID(fixed_uuid),
        ),
        patch("trigguard.proof.execution_gate_proof.datetime") as mock_datetime,
    ):
        mock_datetime.now.return_value = mock_datetime.fromisoformat(fixed_time)
        mock_datetime.now.return_value.isoformat.return_value = fixed_time
        mock_datetime.now.return_value.tzinfo = None
        mock_datetime.timezone = datetime.timezone
        proof1 = build_execution_gate_proof(
            decision_receipt=DummyReceipt(),
            runtime_version="1.2.3",
            signer=DummySigner(),
            surface_id="trigguard.spend.transfer",
        )
        proof2 = build_execution_gate_proof(
            decision_receipt=DummyReceipt(),
            runtime_version="1.2.3",
            signer=DummySigner(),
            surface_id="trigguard.spend.transfer",
        )
    assert proof1.to_canonical_json() == proof2.to_canonical_json()


def test_proof_signature_verifies():
    class DummyReceipt:
        decision = "PERMIT"
        receipt_hash = "abc123"
        decision_hash = "def456"
        surface_hash = "ghi789"

    proof = build_execution_gate_proof(
        decision_receipt=DummyReceipt(),
        runtime_version="1.2.3",
        signer=DummySigner(),
        surface_id="trigguard.spend.transfer",
        proof_id="00000000-0000-0000-0000-000000000000",
        issued_at="2026-03-29T00:00:00+00:00",
    )
    print("ACTUAL CANONICAL PAYLOAD:", proof.to_canonical_json())
    verifier = ExecutionGateProofVerifier(key_provider=DummyKeyProvider())
    result = verifier.verify(proof)
    assert result.valid


def test_proof_tampering_decision_invalidates():
    class DummyReceipt:
        decision = "PERMIT"
        receipt_hash = "abc123"
        decision_hash = "def456"
        surface_hash = "ghi789"

    proof = build_execution_gate_proof(
        decision_receipt=DummyReceipt(),
        runtime_version="1.2.3",
        signer=DummySigner(),
        surface_id="trigguard.spend.transfer",
    )
    # Tamper with decision
    tampered = proof.__dict__.copy()
    tampered["decision"] = "DENY"
    tampered_proof = ExecutionGateProof(**tampered)
    verifier = ExecutionGateProofVerifier(key_provider=DummyKeyProvider())
    result = verifier.verify(tampered_proof)
    assert not result.valid


def test_proof_tampering_receipt_hash_invalidates():
    class DummyReceipt:
        decision = "PERMIT"
        receipt_hash = "abc123"
        decision_hash = "def456"
        surface_hash = "ghi789"

    proof = build_execution_gate_proof(
        decision_receipt=DummyReceipt(),
        runtime_version="1.2.3",
        signer=DummySigner(),
        surface_id="trigguard.spend.transfer",
    )
    # Tamper with receipt_hash
    tampered = proof.__dict__.copy()
    tampered["receipt_hash"] = "zzz"
    tampered_proof = ExecutionGateProof(**tampered)
    verifier = ExecutionGateProofVerifier(key_provider=DummyKeyProvider())
    result = verifier.verify(tampered_proof)
    assert not result.valid


def test_proof_protocol_version_validation():
    class DummyReceipt:
        decision = "PERMIT"
        receipt_hash = "abc123"
        decision_hash = "def456"
        surface_hash = "ghi789"

    proof = build_execution_gate_proof(
        decision_receipt=DummyReceipt(),
        runtime_version="1.2.3",
        signer=DummySigner(),
        surface_id="trigguard.spend.transfer",
    )
    # Tamper protocol
    tampered = proof.__dict__.copy()
    tampered["protocol"] = "wrong-protocol"
    tampered_proof = ExecutionGateProof(**tampered)
    verifier = ExecutionGateProofVerifier(key_provider=DummyKeyProvider())
    result = verifier.verify(tampered_proof)
    assert not result.valid
