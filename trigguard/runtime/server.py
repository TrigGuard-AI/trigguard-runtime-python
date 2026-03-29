"""
TrigGuard Runtime Server

FastAPI-based executor runtime service that provides:
- Grant verification endpoint
- Decision execution
- Protocol discovery
- Health checks
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import logging
import uuid

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from trigguard.protocol.decision_contracts import Decision
from trigguard.grants import ActionGrant
from trigguard.verification import TrigGuardVerifierSDK
from trigguard.executor import TrigGuardExecutor
from trigguard.registry import ExecutionSurfaceRegistry

logger = logging.getLogger(__name__)


class ExecuteRequest(BaseModel):
    """Request to execute an action with a grant."""

    grant_token: str = Field(..., description="Signed grant token")
    surface_id: str = Field(..., description="Target execution surface")
    context: dict[str, Any] = Field(
        default_factory=dict, description="Execution context"
    )
    request_id: Optional[str] = Field(
        default=None, description="Client-provided request ID"
    )


class ExecuteResponse(BaseModel):
    """Response from execution request."""

    request_id: str
    decision: str  # PERMIT, DENY, SILENCE
    surface_id: str
    timestamp: str
    reason: Optional[str] = None
    receipt_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    uptime_seconds: float
    surfaces_registered: int


@dataclass
class RuntimeConfig:
    """Configuration for TrigGuard runtime."""

    host: str = "0.0.0.0"
    port: int = 8080
    enable_telemetry: bool = True
    enable_receipts: bool = True
    log_level: str = "INFO"
    max_request_size: int = 1_000_000  # 1MB
    request_timeout: float = 30.0


class TrigGuardRuntime:
    """
    TrigGuard Executor Runtime Service.

    Provides HTTP endpoints for:
    - POST /execute - Execute action with grant verification
    - GET /health - Health check
    - GET /ready - Readiness check
    - GET /.well-known/trigguard-* - Protocol discovery
    """

    def __init__(
        self,
        config: Optional[RuntimeConfig] = None,
        verifier: Optional[TrigGuardVerifierSDK] = None,
        executor: Optional[TrigGuardExecutor] = None,
        registry: Optional[ExecutionSurfaceRegistry] = None,
    ):
        self.config = config or RuntimeConfig()
        self.verifier = verifier or TrigGuardVerifierSDK()
        self.executor = executor or TrigGuardExecutor(self.verifier)
        self.registry = registry or ExecutionSurfaceRegistry.get_default()

        self._start_time = datetime.now(timezone.utc)
        self._request_count = 0
        self._decision_counts: dict[str, int] = {
            "PERMIT": 0,
            "DENY": 0,
            "SILENCE": 0,
        }

        self.app = self._create_app()

    def _create_app(self) -> FastAPI:
        """Create FastAPI application with routes."""
        app = FastAPI(
            title="TrigGuard Runtime",
            description="Execution authorization runtime for AI agents",
            version="0.2.0",
            docs_url="/docs",
            redoc_url="/redoc",
        )

        @app.post("/execute", response_model=ExecuteResponse)
        async def execute(request: ExecuteRequest) -> ExecuteResponse:
            """Execute an action with grant verification."""
            return await self._handle_execute(request)

        @app.get("/health", response_model=HealthResponse)
        async def health() -> HealthResponse:
            """Health check endpoint."""
            return self._get_health()

        @app.get("/ready")
        async def ready() -> dict[str, bool]:
            """Readiness check endpoint."""
            return {"ready": True}

        @app.get("/.well-known/trigguard-runtime")
        async def runtime_info() -> dict[str, Any]:
            """Runtime metadata endpoint."""
            return {
                "runtime": "trigguard-kernel",
                "version": "0.2.0",
                "protocol_version": "1.0",
                "capabilities": [
                    "execute",
                    "verify",
                    "receipts",
                    "telemetry",
                ],
                "endpoints": {
                    "execute": "/execute",
                    "health": "/health",
                    "surfaces": "/.well-known/trigguard-surfaces",
                    "keys": "/.well-known/trigguard-keys",
                },
            }

        return app

    async def _handle_execute(self, request: ExecuteRequest) -> ExecuteResponse:
        """Handle execution request."""
        self._request_count += 1
        request_id = request.request_id or str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            # Verify the grant
            verification_result = self.verifier.verify(request.grant_token)

            if not verification_result.valid:
                self._decision_counts["DENY"] += 1
                return ExecuteResponse(
                    request_id=request_id,
                    decision="DENY",
                    surface_id=request.surface_id,
                    timestamp=timestamp,
                    reason=verification_result.reason or "Grant verification failed",
                )

            # Check surface exists
            if not self.registry.exists(request.surface_id):
                self._decision_counts["DENY"] += 1
                return ExecuteResponse(
                    request_id=request_id,
                    decision="DENY",
                    surface_id=request.surface_id,
                    timestamp=timestamp,
                    reason=f"Unknown surface: {request.surface_id}",
                )

            # Execute through executor boundary
            decision = self.executor.execute(
                grant=verification_result.grant,
                surface_id=request.surface_id,
                context=request.context,
            )

            decision_str = decision.decision_type.name
            self._decision_counts[decision_str] += 1

            return ExecuteResponse(
                request_id=request_id,
                decision=decision_str,
                surface_id=request.surface_id,
                timestamp=timestamp,
                reason=decision.reason,
                receipt_id=str(uuid.uuid4()) if self.config.enable_receipts else None,
                metadata={
                    "risk_tier": (
                        self.registry.get(request.surface_id).risk_tier.name
                        if self.registry.exists(request.surface_id)
                        else None
                    ),
                },
            )

        except Exception as e:
            logger.exception(f"Execution error: {e}")
            self._decision_counts["DENY"] += 1
            return ExecuteResponse(
                request_id=request_id,
                decision="DENY",
                surface_id=request.surface_id,
                timestamp=timestamp,
                reason=f"Internal error: {type(e).__name__}",
            )

    def _get_health(self) -> HealthResponse:
        """Get health status."""
        uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        return HealthResponse(
            status="healthy",
            version="0.2.0",
            uptime_seconds=uptime,
            surfaces_registered=len(self.registry.list_all()),
        )

    def start(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        """Start the runtime server."""
        import uvicorn

        uvicorn.run(
            self.app,
            host=host or self.config.host,
            port=port or self.config.port,
            log_level=self.config.log_level.lower(),
        )

    @property
    def stats(self) -> dict[str, Any]:
        """Get runtime statistics."""
        return {
            "request_count": self._request_count,
            "decisions": self._decision_counts.copy(),
            "uptime_seconds": (
                datetime.now(timezone.utc) - self._start_time
            ).total_seconds(),
        }


def main() -> None:
    """Entry point for runtime server."""
    import argparse

    parser = argparse.ArgumentParser(description="TrigGuard Runtime Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    config = RuntimeConfig(
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )

    runtime = TrigGuardRuntime(config=config)
    logger.info(f"Starting TrigGuard Runtime on {config.host}:{config.port}")
    runtime.start()


if __name__ == "__main__":
    main()
