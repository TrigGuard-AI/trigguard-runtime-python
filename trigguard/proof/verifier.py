from typing import Optional
from .execution_gate_proof import ExecutionGateProof


class ExecutionGateProofVerificationResult:
    def __init__(self, valid: bool, reason: str = "", checks: Optional[dict] = None):
        self.valid = valid
        self.reason = reason
        self.checks = checks or {}


class ExecutionGateProofVerifier:
    def __init__(self, key_provider=None):
        self.key_provider = key_provider

    def verify(self, proof: ExecutionGateProof) -> ExecutionGateProofVerificationResult:
        checks = {}
        # Required fields
        required = [
            "proof_id",
            "protocol",
            "version",
            "decision",
            "surface_id",
            "receipt_hash",
            "runtime_version",
            "issued_at",
            "signature_alg",
            "signature",
        ]
        for field in required:
            if not getattr(proof, field, None):
                return ExecutionGateProofVerificationResult(
                    False, f"Missing field: {field}"
                )
        checks["required_fields"] = True
        # Protocol
        if proof.protocol != "trigguard-proof":
            return ExecutionGateProofVerificationResult(
                False, "Invalid protocol", checks
            )
        checks["protocol"] = True
        # Version
        # Accept '0.2.1' (current) and '1.0' series for forward compatibility
        if not (proof.version == "0.2.1" or proof.version.startswith("1.0")):
            return ExecutionGateProofVerificationResult(
                False, "Unrecognized version", checks
            )
        checks["version"] = True
        # Canonical payload
        canonical = proof.to_canonical_json()
        # Signature
        if not self.key_provider:
            return ExecutionGateProofVerificationResult(
                False, "No key provider for signature verification", checks
            )
        try:
            valid_sig = self.key_provider.verify(
                canonical.encode("utf-8"), proof.signature, proof.signature_alg
            )
        except Exception as e:
            return ExecutionGateProofVerificationResult(
                False, f"Signature verification error: {e}", checks
            )
        if not valid_sig:
            return ExecutionGateProofVerificationResult(
                False, "Invalid signature", checks
            )
        checks["signature"] = True
        # Receipt hash
        if not proof.receipt_hash:
            return ExecutionGateProofVerificationResult(
                False, "Missing receipt_hash", checks
            )
        checks["receipt_hash"] = True
        # Decision (artifact validation only)
        allowed = {"PERMIT", "DENY", "SILENCE"}
        if proof.decision not in allowed:
            return ExecutionGateProofVerificationResult(
                False, "Invalid decision value", checks
            )
        checks["decision"] = True
        return ExecutionGateProofVerificationResult(True, "", checks)
