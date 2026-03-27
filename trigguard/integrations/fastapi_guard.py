"""
TrigGuard FastAPI Middleware

Protects FastAPI endpoints with TrigGuard authorization.

Usage:
    from trigguard.integrations.fastapi_guard import TrigGuardMiddleware

    app = FastAPI()
    app.add_middleware(
        TrigGuardMiddleware,
        surface="DATA_EXPORT"
    )
"""

from typing import Callable, Optional
from uuid import uuid4

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    HAS_STARLETTE = True
except ImportError:
    HAS_STARLETTE = False


from trigguard.sdk.gate import gate, GateResult
from trigguard.protocol.decision_contracts import ExecutionSurface


class TrigGuardMiddleware:
    """
    FastAPI/Starlette middleware for TrigGuard authorization.

    Intercepts requests to protected endpoints and evaluates
    them through TrigGuard before allowing execution.

    Usage:
        app = FastAPI()

        app.add_middleware(
            TrigGuardMiddleware,
            surface="DATA_EXPORT",
            protected_paths=["/api/export", "/api/download"]
        )
    """

    def __init__(
        self,
        app,
        surface: str = "external_api",
        protected_paths: Optional[list] = None,
        exclude_paths: Optional[list] = None,
    ):
        """
        Initialize TrigGuard middleware.

        Args:
            app: ASGI application
            surface: Default execution surface for requests
            protected_paths: List of path prefixes to protect (default: all)
            exclude_paths: List of path prefixes to exclude
        """
        self.app = app
        self.surface = surface
        self.protected_paths = protected_paths
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/docs"]

    async def __call__(self, scope, receive, send):
        """ASGI interface."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Check exclusions
        if self._is_excluded(path):
            await self.app(scope, receive, send)
            return

        # Check if path is protected
        if not self._is_protected(path):
            await self.app(scope, receive, send)
            return

        # Build request for TrigGuard
        method = scope.get("method", "GET")
        request_id = str(uuid4())

        tg_request = {
            "surface": self.surface,
            "action": f"{method} {path}",
            "arguments": {
                "path": path,
                "method": method,
                "query_string": scope.get("query_string", b"").decode(),
            },
            "context": {
                "client": scope.get("client", [None])[0],
                "request_id": request_id,
            },
        }

        # Evaluate through TrigGuard
        decision = gate.check(tg_request)

        if decision.permit:
            # Add decision info to scope for downstream use
            scope["trigguard_decision"] = decision
            scope["trigguard_request_id"] = request_id
            await self.app(scope, receive, send)
        else:
            # Return 403 Forbidden
            response = JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "reason": decision.reason or "TrigGuard denied execution",
                    "request_id": request_id,
                    "receipt_hash": (
                        decision.receipt.receipt_hash if decision.receipt else None
                    ),
                },
                headers={
                    "X-TrigGuard-Decision": "DENY",
                    "X-TrigGuard-Request-ID": request_id,
                },
            )
            await response(scope, receive, send)

    def _is_protected(self, path: str) -> bool:
        """Check if path should be protected."""
        if self.protected_paths is None:
            return True
        return any(path.startswith(p) for p in self.protected_paths)

    def _is_excluded(self, path: str) -> bool:
        """Check if path is excluded from protection."""
        return any(path.startswith(p) for p in self.exclude_paths)


def create_fastapi_dependency(surface: str = "external_api"):
    """
    Create a FastAPI dependency for TrigGuard authorization.

    Usage:
        from fastapi import Depends

        trigguard_check = create_fastapi_dependency(surface="SPEND")

        @app.post("/transfer")
        async def transfer(decision: GateResult = Depends(trigguard_check)):
            if not decision.permit:
                raise HTTPException(403, decision.reason)
            ...
    """

    async def dependency(request: "Request") -> GateResult:
        tg_request = {
            "surface": surface,
            "action": f"{request.method} {request.url.path}",
            "arguments": dict(request.query_params),
            "context": {
                "client": request.client.host if request.client else None,
            },
        }
        return gate.check(tg_request)

    return dependency


__all__ = [
    "TrigGuardMiddleware",
    "create_fastapi_dependency",
]
