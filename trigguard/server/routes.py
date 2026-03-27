"""
TrigGuard Server Routes

API endpoints for TrigGuard evaluation service.
"""

import time
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

try:
    from fastapi import APIRouter, HTTPException, Header, Request
    from fastapi.responses import JSONResponse
except ImportError:
    # Stub for environments without FastAPI
    class APIRouter:
        def __init__(self, **kwargs):
            pass

        def get(self, *args, **kwargs):
            def decorator(f):
                return f

            return decorator

        def post(self, *args, **kwargs):
            def decorator(f):
                return f

            return decorator


from trigguard.server.models import (
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
    PolicyInfoResponse,
    ReplayRequest,
    ReplayResponse,
    ErrorResponse,
    BatchEvaluateRequest,
    BatchEvaluateResponse,
)
from trigguard.sdk.gate import gate, GateResult
from trigguard.policy.policy_registry import get_policy_registry
from trigguard.telemetry.metrics import get_telemetry

router = APIRouter(prefix="/api/v1", tags=["trigguard"])

# Server start time for uptime calculation
_server_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.

    Returns server status, version, and key metrics.
    """
    telemetry = get_telemetry()
    policy = get_policy_registry()

    return HealthResponse(
        status="healthy",
        version="0.1.0",
        policy_version=policy.version,
        uptime_seconds=time.time() - _server_start_time,
        gates_evaluated=telemetry.gates_evaluated.value,
    )


@router.get("/policy", response_model=PolicyInfoResponse)
async def get_policy_info():
    """
    Get current policy information.

    Returns policy version and configuration.
    """
    policy = get_policy_registry()

    irreversible = [
        "spend",
        "export",
        "code_execution",
        "delegation",
        "identity",
    ]

    return PolicyInfoResponse(
        version=policy.version,
        is_external=policy.is_external_policy,
        irreversible_surfaces=irreversible,
        last_updated=datetime.now(timezone.utc),
    )


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(
    request: EvaluateRequest,
    x_request_id: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None),
):
    """
    Evaluate an execution request through TrigGuard.

    This is the primary API endpoint for authorization decisions.

    Returns:
        EvaluateResponse with permit/deny decision and audit trail.
    """
    start_time = time.perf_counter()

    # Use provided request ID or generate one
    request_id = request.request_id or x_request_id or str(uuid4())

    # Build context with headers
    context = dict(request.context)
    if x_tenant_id:
        context["tenant_id"] = x_tenant_id

    # Convert to gate request format
    gate_request = {
        "surface": request.surface,
        "action": request.action,
        "arguments": request.arguments,
        "context": context,
        "signals": [
            {
                "type": s.signal_type,
                "severity": s.severity,
                "confidence": s.confidence,
                "source": s.source,
                "description": s.description,
                "evidence": s.evidence,
            }
            for s in request.signals
        ],
    }

    try:
        # Evaluate through gate
        result = gate.check(gate_request)

        latency_ms = (time.perf_counter() - start_time) * 1000

        return EvaluateResponse(
            permit=result.permit,
            decision=result.decision.value,
            reason=result.reason,
            request_id=request_id,
            surface=request.surface,
            receipt_hash=result.receipt.receipt_hash if result.receipt else None,
            policy_version=gate.policy_version,
            evaluated_at=datetime.now(timezone.utc),
            latency_ms=latency_ms,
            signal_count=len(result.signals),
        )

    except Exception as e:
        # Fail-closed: any error results in DENY
        latency_ms = (time.perf_counter() - start_time) * 1000

        return EvaluateResponse(
            permit=False,
            decision="deny",
            reason=f"FAIL_CLOSED: {str(e)}",
            request_id=request_id,
            surface=request.surface,
            receipt_hash=None,
            policy_version=gate.policy_version,
            evaluated_at=datetime.now(timezone.utc),
            latency_ms=latency_ms,
            signal_count=0,
        )


@router.post("/evaluate/batch", response_model=BatchEvaluateResponse)
async def evaluate_batch(request: BatchEvaluateRequest):
    """
    Evaluate multiple requests in a batch.

    Useful for pre-computing decisions for a set of actions.
    Max 100 requests per batch.
    """
    start_time = time.perf_counter()

    results = []
    permitted = 0
    denied = 0

    for req in request.requests:
        # Build gate request
        gate_request = {
            "surface": req.surface,
            "action": req.action,
            "arguments": req.arguments,
            "context": req.context,
        }

        result = gate.check(gate_request)

        response = EvaluateResponse(
            permit=result.permit,
            decision=result.decision.value,
            reason=result.reason,
            request_id=req.request_id or str(uuid4()),
            surface=req.surface,
            receipt_hash=result.receipt.receipt_hash if result.receipt else None,
            policy_version=gate.policy_version,
            evaluated_at=datetime.now(timezone.utc),
            latency_ms=0,  # Individual latencies not tracked in batch
            signal_count=len(result.signals),
        )

        results.append(response)

        if result.permit:
            permitted += 1
        else:
            denied += 1

    total_latency = (time.perf_counter() - start_time) * 1000

    return BatchEvaluateResponse(
        results=results,
        total=len(results),
        permitted=permitted,
        denied=denied,
        total_latency_ms=total_latency,
    )


@router.get("/metrics")
async def get_metrics():
    """
    Get infrastructure metrics.

    Returns telemetry data for monitoring.
    """
    telemetry = get_telemetry()
    return telemetry.export()


@router.post("/replay", response_model=ReplayResponse)
async def replay_decision(request: ReplayRequest):
    """
    Replay a decision for verification.

    Used for auditing and determinism verification.
    """
    from trigguard.tools.decision_replay import DecisionReplayEngine
    from trigguard.protocol.decision_contracts import SignalFrame, ExecutionSurface
    from uuid import UUID

    try:
        # Reconstruct frame from data
        frame_data = request.frame_data

        frame = SignalFrame(
            request_id=UUID(frame_data.get("request_id", str(uuid4()))),
            surface=ExecutionSurface(frame_data.get("surface", "unknown")),
        )

        # Replay
        engine = DecisionReplayEngine()
        result = engine.replay_decision(frame)

        return ReplayResponse(
            matches=result.matches,
            original_decision=(
                result.original_decision.value
                if result.original_decision
                else "unknown"
            ),
            replayed_decision=result.replayed_decision.value,
            policy_match=result.original_policy == result.replayed_policy,
            differences=result.differences,
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Replay failed: {str(e)}")


# Additional utility endpoints


@router.get("/surfaces")
async def list_surfaces():
    """List available execution surfaces."""
    from trigguard.core.surfaces import (
        TIER1_SURFACES,
        TIER2_SURFACES,
        TIER3_SURFACES,
    )

    return {
        "tier1_irreversible": [s.value for s in TIER1_SURFACES],
        "tier2_medium": [s.value for s in TIER2_SURFACES],
        "tier3_low": [s.value for s in TIER3_SURFACES],
    }


@router.get("/ready")
async def readiness_check():
    """
    Kubernetes-style readiness probe.

    Returns 200 if ready to serve traffic.
    """
    try:
        # Quick sanity check
        policy = get_policy_registry()
        if not policy.version:
            raise Exception("Policy not loaded")

        return {"ready": True}

    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Not ready: {str(e)}")


@router.get("/live")
async def liveness_check():
    """
    Kubernetes-style liveness probe.

    Returns 200 if server is alive.
    """
    return {"alive": True}
