"""
TrigGuard Server Application

FastAPI application exposing TrigGuard as an HTTP service.

Usage:
    uvicorn server.trigguard_server:app --host 0.0.0.0 --port 8000

    # Development with auto-reload
    uvicorn server.trigguard_server:app --reload

    # Production with gunicorn
    gunicorn server.trigguard_server:app -w 4 -k uvicorn.workers.UvicornWorker
"""

import os
import time
import logging
from contextlib import asynccontextmanager
from typing import Optional

try:
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None

from trigguard.server.routes import router
from trigguard.server.well_known import well_known_router
from trigguard.server.models import ErrorResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("trigguard.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Manages startup and shutdown events.
    """
    # Startup
    logger.info("TrigGuard Server starting...")

    # Initialize telemetry
    from trigguard.telemetry.metrics import get_telemetry

    telemetry = get_telemetry()
    logger.info(f"Telemetry initialized: {telemetry}")

    # Load policy
    from trigguard.policy.policy_registry import get_policy_registry

    policy = get_policy_registry()
    logger.info(f"Policy loaded: version={policy.version}")

    # Initialize gate
    from trigguard.sdk.gate import gate

    logger.info(f"Gate initialized: policy_version={gate.policy_version}")

    app.state.start_time = time.time()
    logger.info("TrigGuard Server ready to accept requests")

    yield

    # Shutdown
    logger.info("TrigGuard Server shutting down...")
    telemetry.flush()
    logger.info("TrigGuard Server shutdown complete")


def create_app(
    cors_origins: Optional[list] = None,
    debug: bool = False,
    title: str = "TrigGuard Server",
) -> FastAPI:
    """
    Create and configure the TrigGuard FastAPI application.

    Args:
        cors_origins: List of allowed CORS origins. Defaults to ["*"].
        debug: Enable debug mode.
        title: API title.

    Returns:
        Configured FastAPI application.
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required. Install with: pip install fastapi[standard]"
        )

    if cors_origins is None:
        cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")

    application = FastAPI(
        title=title,
        description="""
TrigGuard Server - Deterministic Pre-Execution Authorization Layer

## Overview

TrigGuard Server exposes the TrigGuard authorization engine as an HTTP API,
enabling distributed agent systems to enforce consistent execution policies.

## Features

- **Evaluation API**: Real-time authorization decisions for agent actions
- **Batch Processing**: Evaluate multiple requests efficiently
- **Decision Replay**: Verify determinism and audit past decisions
- **Health Monitoring**: Kubernetes-compatible health probes

## Authentication

Configure authentication through environment variables:
- `TRIGGUARD_API_KEY`: Required API key for all requests
- `TRIGGUARD_TENANT_ID`: Optional multi-tenant isolation

## Fail-Closed Guarantee

TrigGuard operates with a fail-closed guarantee. If any error occurs
during evaluation, the decision defaults to DENY for safety.
        """,
        version="0.1.0",
        lifespan=lifespan,
        debug=debug,
        openapi_tags=[
            {
                "name": "trigguard",
                "description": "Core TrigGuard evaluation endpoints",
            },
        ],
    )

    # CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @application.middleware("http")
    async def add_timing_header(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        process_time = (time.perf_counter() - start) * 1000
        response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
        return response

    # Request logging middleware
    @application.middleware("http")
    async def log_requests(request: Request, call_next):
        logger.debug(f"Request: {request.method} {request.url.path}")
        response = await call_next(request)
        logger.debug(f"Response: {response.status_code}")
        return response

    # Global exception handler
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_error",
                message="An internal error occurred",
                details={"type": type(exc).__name__},
            ).model_dump(),
        )

    # Include routers
    application.include_router(router)
    application.include_router(well_known_router)

    # Root endpoint
    @application.get("/")
    async def root():
        return {
            "service": "TrigGuard Server",
            "version": "0.1.0",
            "documentation": "/docs",
            "health": "/api/v1/health",
        }

    return application


# Default application instance
app = create_app()


# CLI entry point
def main():
    """Run the server from command line."""
    import argparse

    parser = argparse.ArgumentParser(description="TrigGuard Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required. Install with: pip install uvicorn")
        return 1

    logger.info(f"Starting TrigGuard Server on {args.host}:{args.port}")

    uvicorn.run(
        "server.trigguard_server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level="debug" if args.debug else "info",
    )

    return 0


if __name__ == "__main__":
    exit(main())
