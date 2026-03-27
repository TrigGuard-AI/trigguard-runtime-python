"""
TrigGuard Server Models

Pydantic models for API request/response types.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

try:
    from pydantic import BaseModel, Field
except ImportError:
    # Fallback for environments without pydantic
    from dataclasses import dataclass, field
    
    class BaseModel:
        pass


class SignalModel(BaseModel):
    """Signal in an evaluation request."""
    signal_type: str = Field(..., description="Type of signal (e.g., 'prompt_override')")
    severity: str = Field("medium", description="Signal severity: critical, high, medium, low")
    confidence: float = Field(0.8, ge=0.0, le=1.0, description="Confidence score")
    source: str = Field("api", description="Source of the signal")
    description: str = Field("", description="Human-readable description")
    evidence: Optional[str] = Field(None, description="Supporting evidence")


class EvaluateRequest(BaseModel):
    """
    Request to evaluate an execution through TrigGuard.
    
    This is the primary API input for authorization decisions.
    """
    surface: str = Field(
        ...,
        description="Execution surface: spend, code_execution, export, etc."
    )
    action: str = Field(
        "",
        description="Action being performed"
    )
    request_id: Optional[str] = Field(
        None,
        description="Client-provided request ID for correlation"
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action arguments/payload"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (tenant_id, session_id, etc.)"
    )
    signals: List[SignalModel] = Field(
        default_factory=list,
        description="Pre-computed signals to include"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "surface": "spend",
                "action": "transfer_funds",
                "arguments": {"amount": 1000, "currency": "USD"},
                "context": {"tenant_id": "acme-corp"},
            }
        }


class EvaluateResponse(BaseModel):
    """
    Response from TrigGuard evaluation.
    
    Contains the authorization decision and audit trail.
    """
    permit: bool = Field(..., description="Whether execution is permitted")
    decision: str = Field(..., description="Decision: permit, deny, silence")
    reason: str = Field("", description="Reason for the decision")
    request_id: str = Field(..., description="Request ID for correlation")
    surface: str = Field(..., description="Evaluated surface")
    
    # Audit trail
    receipt_hash: Optional[str] = Field(None, description="Cryptographic receipt hash")
    policy_version: str = Field(..., description="Policy version used")
    evaluated_at: datetime = Field(..., description="Evaluation timestamp")
    latency_ms: float = Field(..., description="Evaluation latency in milliseconds")
    
    # Signals that contributed to decision
    signal_count: int = Field(0, description="Number of signals evaluated")
    
    class Config:
        json_schema_extra = {
            "example": {
                "permit": True,
                "decision": "permit",
                "reason": "",
                "request_id": "req-123",
                "surface": "spend",
                "receipt_hash": "abc123...",
                "policy_version": "v1.0.0",
                "evaluated_at": "2026-03-27T10:00:00Z",
                "latency_ms": 1.5,
                "signal_count": 0,
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Health status: healthy, degraded, unhealthy")
    version: str = Field(..., description="TrigGuard version")
    policy_version: str = Field(..., description="Current policy version")
    uptime_seconds: float = Field(..., description="Server uptime")
    gates_evaluated: int = Field(..., description="Total gates evaluated")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "version": "0.1.0",
                "policy_version": "v1.0.0",
                "uptime_seconds": 3600.0,
                "gates_evaluated": 10000,
            }
        }


class PolicyInfoResponse(BaseModel):
    """Policy information response."""
    version: str = Field(..., description="Policy version")
    is_external: bool = Field(..., description="Whether using external policy")
    irreversible_surfaces: List[str] = Field(..., description="Tier 1 surfaces")
    last_updated: Optional[datetime] = Field(None, description="Last policy update time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "version": "v1.0.0",
                "is_external": False,
                "irreversible_surfaces": ["spend", "export", "code_execution"],
                "last_updated": "2026-03-27T09:00:00Z",
            }
        }


class ReplayRequest(BaseModel):
    """Request to replay a decision."""
    receipt_hash: str = Field(..., description="Receipt hash to replay")
    frame_data: Dict[str, Any] = Field(..., description="Original SignalFrame data")


class ReplayResponse(BaseModel):
    """Response from decision replay."""
    matches: bool = Field(..., description="Whether replay matches original")
    original_decision: str = Field(..., description="Original decision")
    replayed_decision: str = Field(..., description="Replayed decision")
    policy_match: bool = Field(..., description="Whether policy versions match")
    differences: List[str] = Field(default_factory=list, description="List of differences")


class ErrorResponse(BaseModel):
    """Error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    request_id: Optional[str] = Field(None, description="Request ID if available")
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid surface: 'unknown'",
                "request_id": "req-123",
            }
        }


class BatchEvaluateRequest(BaseModel):
    """Batch evaluation request."""
    requests: List[EvaluateRequest] = Field(
        ...,
        max_length=100,
        description="List of evaluation requests (max 100)"
    )


class BatchEvaluateResponse(BaseModel):
    """Batch evaluation response."""
    results: List[EvaluateResponse] = Field(..., description="List of results")
    total: int = Field(..., description="Total requests processed")
    permitted: int = Field(..., description="Number permitted")
    denied: int = Field(..., description="Number denied")
    total_latency_ms: float = Field(..., description="Total processing time")
