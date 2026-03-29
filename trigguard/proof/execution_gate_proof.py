from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import json
import uuid
from datetime import datetime, timezone


@dataclass(frozen=True)
class ExecutionGateProof:
    proof_id: str
    protocol: str
    version: str
    decision: str
    surface_id: str
    receipt_hash: str
    decision_hash: Optional[str]
    surface_hash: Optional[str]
    runtime_version: str
    issued_at: str
    signature_alg: str
    signature: str

    def to_payload_dict(self) -> Dict[str, Any]:
        # Exclude signature
        d = self.__dict__.copy()
        d.pop("signature")
        return d

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()

    def to_canonical_json(self) -> str:
        # Deterministic, sorted, compact JSON (excluding signature)
        payload = self.to_payload_dict()
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def build_execution_gate_proof(
    *,
    decision_receipt,
    runtime_version: str,
    signer,
    surface_id: str,
    signature_alg: str = "ed25519",
    proof_id: str = None,
    issued_at: str = None,
) -> ExecutionGateProof:
    # Allow deterministic proof_id and issued_at for testing
    proof_id = proof_id or str(uuid.uuid4())
    protocol = "trigguard-proof"
    version = "0.2.1"
    decision = getattr(decision_receipt, "decision", None)
    receipt_hash = getattr(decision_receipt, "receipt_hash", None)
    decision_hash = getattr(decision_receipt, "decision_hash", None)
    surface_hash = getattr(decision_receipt, "surface_hash", None)
    issued_at = issued_at or datetime.now(timezone.utc).isoformat()
    # Build payload (excluding signature)
    payload = dict(
        proof_id=proof_id,
        protocol=protocol,
        version=version,
        decision=decision,
        surface_id=surface_id,
        receipt_hash=receipt_hash,
        decision_hash=decision_hash,
        surface_hash=surface_hash,
        runtime_version=runtime_version,
        issued_at=issued_at,
        signature_alg=signature_alg,
    )
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = signer.sign(canonical_json.encode("utf-8"))
    if isinstance(signature, bytes):
        signature = signature.hex()
    return ExecutionGateProof(
        **payload,
        signature=signature,
    )
