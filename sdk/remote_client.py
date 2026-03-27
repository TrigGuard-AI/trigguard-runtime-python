"""
TrigGuard Remote Client

SDK for calling TrigGuard Server from distributed agents.

Usage:
    from sdk.remote_client import TrigGuardClient
    
    client = TrigGuardClient("http://trigguard:8000")
    
    # Evaluate a request
    result = await client.evaluate(
        surface="spend",
        action="transfer",
        arguments={"amount": 100}
    )
    
    if result.permit:
        # Proceed with action
        ...
"""

import asyncio
import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime
from uuid import uuid4


logger = logging.getLogger("trigguard.remote")


class RemoteDecision(Enum):
    """Decision from remote TrigGuard server."""
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    ERROR = "error"


@dataclass
class RemoteEvaluationResult:
    """Result from remote TrigGuard evaluation."""
    permit: bool
    decision: RemoteDecision
    reason: str
    request_id: str
    surface: str
    receipt_hash: Optional[str] = None
    policy_version: str = "unknown"
    latency_ms: float = 0.0
    evaluated_at: Optional[datetime] = None
    signal_count: int = 0
    
    @classmethod
    def from_response(cls, data: Dict[str, Any]) -> "RemoteEvaluationResult":
        """Create from API response."""
        return cls(
            permit=data["permit"],
            decision=RemoteDecision(data["decision"]),
            reason=data.get("reason", ""),
            request_id=data.get("request_id", ""),
            surface=data.get("surface", ""),
            receipt_hash=data.get("receipt_hash"),
            policy_version=data.get("policy_version", "unknown"),
            latency_ms=data.get("latency_ms", 0.0),
            signal_count=data.get("signal_count", 0),
        )
    
    @classmethod
    def fail_closed(cls, reason: str, surface: str = "") -> "RemoteEvaluationResult":
        """Create fail-closed result."""
        return cls(
            permit=False,
            decision=RemoteDecision.ERROR,
            reason=f"FAIL_CLOSED: {reason}",
            request_id=str(uuid4()),
            surface=surface,
        )


@dataclass
class RemoteHealthStatus:
    """Health status from TrigGuard server."""
    healthy: bool
    version: str
    policy_version: str
    uptime_seconds: float
    gates_evaluated: int


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    base_delay_ms: float = 100.0
    max_delay_ms: float = 5000.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.1


@dataclass
class ClientConfig:
    """Configuration for TrigGuard remote client."""
    base_url: str
    api_key: Optional[str] = None
    tenant_id: Optional[str] = None
    timeout_seconds: float = 5.0
    retry_config: RetryConfig = field(default_factory=RetryConfig)
    fail_closed: bool = True
    logger: Optional[logging.Logger] = None


class TrigGuardClient:
    """
    TrigGuard Remote Client.
    
    Provides async/sync interfaces for calling TrigGuard Server.
    
    Features:
        - Automatic retries with exponential backoff
        - Fail-closed error handling
        - Connection pooling
        - Circuit breaker pattern
        - Batch evaluation support
    """
    
    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        timeout: float = 5.0,
        max_retries: int = 3,
        fail_closed: bool = True,
    ):
        """
        Initialize TrigGuard client.
        
        Args:
            base_url: TrigGuard server URL (e.g., "http://trigguard:8000")
            api_key: Optional API key for authentication
            tenant_id: Optional tenant ID for multi-tenant deployments
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            fail_closed: Deny on errors (default: True)
        """
        self.config = ClientConfig(
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            tenant_id=tenant_id,
            timeout_seconds=timeout,
            retry_config=RetryConfig(max_retries=max_retries),
            fail_closed=fail_closed,
            logger=logger,
        )
        
        self._http_client = None
        self._circuit_open = False
        self._consecutive_failures = 0
        self._circuit_threshold = 5
        self._circuit_reset_time = 30.0
        self._last_failure_time = 0.0
    
    @property
    def _headers(self) -> Dict[str, str]:
        """Default headers for requests."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        if self.config.tenant_id:
            headers["X-Tenant-Id"] = self.config.tenant_id
        return headers
    
    async def _get_client(self):
        """Get or create HTTP client."""
        if self._http_client is None:
            try:
                import httpx
                self._http_client = httpx.AsyncClient(
                    base_url=self.config.base_url,
                    timeout=self.config.timeout_seconds,
                    headers=self._headers,
                )
            except ImportError:
                raise RuntimeError(
                    "httpx is required for async client. "
                    "Install with: pip install httpx"
                )
        return self._http_client
    
    def _check_circuit(self) -> bool:
        """Check if circuit breaker allows requests."""
        if not self._circuit_open:
            return True
        
        # Check if it's time to reset
        if time.time() - self._last_failure_time > self._circuit_reset_time:
            self._circuit_open = False
            self._consecutive_failures = 0
            logger.info("Circuit breaker reset")
            return True
        
        return False
    
    def _record_success(self):
        """Record successful request."""
        self._consecutive_failures = 0
        self._circuit_open = False
    
    def _record_failure(self):
        """Record failed request."""
        self._consecutive_failures += 1
        self._last_failure_time = time.time()
        
        if self._consecutive_failures >= self._circuit_threshold:
            self._circuit_open = True
            logger.warning(
                f"Circuit breaker opened after {self._consecutive_failures} failures"
            )
    
    async def _request_with_retry(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic."""
        client = await self._get_client()
        
        if not self._check_circuit():
            raise ConnectionError("Circuit breaker is open")
        
        last_error = None
        retry_config = self.config.retry_config
        
        for attempt in range(retry_config.max_retries + 1):
            try:
                if method == "GET":
                    response = await client.get(path)
                elif method == "POST":
                    response = await client.post(path, json=json_data)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                response.raise_for_status()
                self._record_success()
                return response.json()
                
            except Exception as e:
                last_error = e
                self._record_failure()
                
                if attempt < retry_config.max_retries:
                    # Calculate delay with exponential backoff and jitter
                    delay = min(
                        retry_config.base_delay_ms * (
                            retry_config.exponential_base ** attempt
                        ),
                        retry_config.max_delay_ms,
                    )
                    jitter = delay * retry_config.jitter_factor
                    import random
                    delay += random.uniform(-jitter, jitter)
                    
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}), "
                        f"retrying in {delay:.0f}ms: {e}"
                    )
                    await asyncio.sleep(delay / 1000)
        
        raise last_error or Exception("Request failed")
    
    async def evaluate(
        self,
        surface: str,
        action: str = "",
        *,
        arguments: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        signals: Optional[List[Dict]] = None,
        request_id: Optional[str] = None,
    ) -> RemoteEvaluationResult:
        """
        Evaluate an execution request.
        
        Args:
            surface: Execution surface (e.g., "spend", "code_execution")
            action: Action identifier
            arguments: Action arguments
            context: Execution context
            signals: Risk signals
            request_id: Optional request ID
        
        Returns:
            RemoteEvaluationResult with permit/deny decision.
        """
        try:
            payload = {
                "surface": surface,
                "action": action,
                "arguments": arguments or {},
                "context": context or {},
                "signals": signals or [],
            }
            if request_id:
                payload["request_id"] = request_id
            
            data = await self._request_with_retry(
                "POST",
                "/api/v1/evaluate",
                payload,
            )
            
            return RemoteEvaluationResult.from_response(data)
            
        except Exception as e:
            if self.config.fail_closed:
                logger.error(f"Evaluation failed, returning DENY: {e}")
                return RemoteEvaluationResult.fail_closed(str(e), surface)
            raise
    
    async def evaluate_batch(
        self,
        requests: List[Dict[str, Any]],
    ) -> List[RemoteEvaluationResult]:
        """
        Evaluate multiple requests in batch.
        
        Args:
            requests: List of evaluation requests.
        
        Returns:
            List of evaluation results.
        """
        try:
            data = await self._request_with_retry(
                "POST",
                "/api/v1/evaluate/batch",
                {"requests": requests},
            )
            
            return [
                RemoteEvaluationResult.from_response(r)
                for r in data["results"]
            ]
            
        except Exception as e:
            if self.config.fail_closed:
                logger.error(f"Batch evaluation failed: {e}")
                return [
                    RemoteEvaluationResult.fail_closed(str(e), r.get("surface", ""))
                    for r in requests
                ]
            raise
    
    async def health(self) -> RemoteHealthStatus:
        """Check server health."""
        data = await self._request_with_retry("GET", "/api/v1/health")
        
        return RemoteHealthStatus(
            healthy=data["status"] == "healthy",
            version=data.get("version", "unknown"),
            policy_version=data.get("policy_version", "unknown"),
            uptime_seconds=data.get("uptime_seconds", 0),
            gates_evaluated=data.get("gates_evaluated", 0),
        )
    
    async def ready(self) -> bool:
        """Check if server is ready."""
        try:
            data = await self._request_with_retry("GET", "/api/v1/ready")
            return data.get("ready", False)
        except Exception:
            return False
    
    async def close(self):
        """Close the client and release resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    # Synchronous API
    
    def check(
        self,
        surface: str,
        action: str = "",
        **kwargs,
    ) -> RemoteEvaluationResult:
        """
        Synchronous version of evaluate().
        
        For async code, use evaluate() instead.
        """
        return asyncio.get_event_loop().run_until_complete(
            self.evaluate(surface, action, **kwargs)
        )
    
    def check_health(self) -> RemoteHealthStatus:
        """Synchronous version of health()."""
        return asyncio.get_event_loop().run_until_complete(self.health())


# Convenience function for one-off checks
async def remote_check(
    url: str,
    surface: str,
    action: str = "",
    **kwargs,
) -> RemoteEvaluationResult:
    """
    Quick remote check without maintaining a client.
    
    For repeated checks, use TrigGuardClient directly.
    """
    async with TrigGuardClient(url) as client:
        return await client.evaluate(surface, action, **kwargs)


# Guard decorator for remote evaluation
def remote_guard(
    client: TrigGuardClient,
    surface: str,
    action: str = "",
    *,
    extract_args: Optional[Callable] = None,
):
    """
    Decorator for guarding functions with remote TrigGuard.
    
    Usage:
        client = TrigGuardClient("http://trigguard:8000")
        
        @remote_guard(client, "spend", "transfer")
        async def transfer_funds(amount: float, to: str):
            ...
    """
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract arguments for evaluation
            if extract_args:
                eval_args = extract_args(*args, **kwargs)
            else:
                eval_args = kwargs
            
            # Evaluate
            result = await client.evaluate(
                surface=surface,
                action=action,
                arguments=eval_args,
            )
            
            if not result.permit:
                raise PermissionError(
                    f"TrigGuard denied: {result.reason} "
                    f"(receipt: {result.receipt_hash})"
                )
            
            # Execute function
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator
