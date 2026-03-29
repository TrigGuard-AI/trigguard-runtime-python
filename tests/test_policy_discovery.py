import pytest
from fastapi.testclient import TestClient
from trigguard.server.trigguard_server import app

client = TestClient(app)


def test_policy_discovery_endpoint():
    response = client.get("/.well-known/trigguard-policy")
    assert response.status_code == 200
    data = response.json()
    # Required fields
    for field in [
        "protocol",
        "version",
        "decision_endpoint",
        "receipt_endpoint",
        "surface_registry",
        "attestation_supported",
        "signature_alg",
    ]:
        assert field in data
    assert data["protocol"] == "trigguard"
    # Version matches runtime version
    from trigguard._version import __version__

    assert data["version"] == __version__
