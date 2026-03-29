import base64
import json
from .execution_gate_proof import ExecutionGateProof


def encode_proof_header(proof: ExecutionGateProof) -> str:
    # URL-safe base64 of canonical json
    canonical = proof.to_canonical_json().encode("utf-8")
    return base64.urlsafe_b64encode(canonical).decode("utf-8").rstrip("=")


def decode_proof_header(value: str) -> ExecutionGateProof:
    # Add padding if needed
    padded = value + "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
    data = json.loads(decoded)
    return ExecutionGateProof(
        **data, signature=""
    )  # signature must be set separately if needed


def build_proof_headers(proof: ExecutionGateProof) -> dict:
    return {
        "X-TrigGuard-Proof": encode_proof_header(proof),
        "X-TrigGuard-Receipt-Hash": proof.receipt_hash,
        "X-TrigGuard-Surface": proof.surface_id,
        "X-TrigGuard-Decision": proof.decision,
    }
