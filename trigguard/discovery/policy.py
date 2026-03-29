from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class TrigGuardPolicy:
    protocol: str
    version: str
    decision_endpoint: str
    receipt_endpoint: str
    surface_registry: str
    attestation_supported: bool
    signature_alg: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "version": self.version,
            "decision_endpoint": self.decision_endpoint,
            "receipt_endpoint": self.receipt_endpoint,
            "surface_registry": self.surface_registry,
            "attestation_supported": self.attestation_supported,
            "signature_alg": self.signature_alg,
        }


def build_policy():
    from trigguard._version import __version__

    return TrigGuardPolicy(
        protocol="trigguard",
        version=__version__,
        decision_endpoint="/v1/decide",
        receipt_endpoint="/v1/receipts",
        surface_registry="/.well-known/trigguard-surfaces",
        attestation_supported=True,
        signature_alg="ed25519",
    )
