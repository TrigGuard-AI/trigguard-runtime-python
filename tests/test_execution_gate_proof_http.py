import pytest
from trigguard.proof.execution_gate_proof import ExecutionGateProof
from trigguard.proof.http import (
    encode_proof_header,
    decode_proof_header,
    build_proof_headers,
)


def make_proof():
    return ExecutionGateProof(
        proof_id="id1",
        protocol="trigguard-proof",
        version="1.0",
        decision="PERMIT",
        surface_id="trigguard.spend.transfer",
        receipt_hash="abc123",
        decision_hash="def456",
        surface_hash="ghi789",
        runtime_version="1.2.3",
        issued_at="2026-03-29T00:00:00Z",
        signature_alg="ed25519",
        signature="deadbeef",
    )


def test_encode_decode_roundtrip():
    proof = make_proof()
    encoded = encode_proof_header(proof)
    decoded = decode_proof_header(encoded)
    # signature is not included in canonical json, so set for comparison
    decoded = decoded.__class__(**{**decoded.__dict__, "signature": proof.signature})
    assert decoded.to_payload_dict() == proof.to_payload_dict()


def test_build_proof_headers():
    proof = make_proof()
    headers = build_proof_headers(proof)
    assert "X-TrigGuard-Proof" in headers
    assert headers["X-TrigGuard-Receipt-Hash"] == proof.receipt_hash
    assert headers["X-TrigGuard-Surface"] == proof.surface_id
    assert headers["X-TrigGuard-Decision"] == proof.decision


def test_invalid_header_decode_fails():
    with pytest.raises(Exception):
        decode_proof_header("not-a-valid-header")
