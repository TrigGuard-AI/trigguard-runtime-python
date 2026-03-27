"""
TrigGuard Server

HTTP/gRPC evaluation API for distributed TrigGuard deployment.

Usage:
    python -m server.trigguard_server

    # Or with uvicorn
    uvicorn server.trigguard_server:app --host 0.0.0.0 --port 8080
"""

from trigguard.server.trigguard_server import app, create_app
from trigguard.server.routes import router
from trigguard.server.models import (
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
    PolicyInfoResponse,
    BatchEvaluateRequest,
    BatchEvaluateResponse,
    ReplayRequest,
    ReplayResponse,
    ErrorResponse,
    SignalModel,
)

__all__ = [
    "app",
    "create_app",
    "router",
    "EvaluateRequest",
    "EvaluateResponse",
    "HealthResponse",
    "PolicyInfoResponse",
    "BatchEvaluateRequest",
    "BatchEvaluateResponse",
    "ReplayRequest",
    "ReplayResponse",
    "ErrorResponse",
    "SignalModel",
]
