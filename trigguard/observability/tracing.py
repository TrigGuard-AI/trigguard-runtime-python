"""
TrigGuard Structured Observability

Production-grade observability with OpenTelemetry, Prometheus, and structured logging.

Features:
    - OpenTelemetry tracing for distributed systems
    - Prometheus metrics for monitoring dashboards
    - Structured JSON logging for log aggregation
    - Decision audit trail spans
    - Auto-instrumentation for server endpoints

Usage:
    from trigguard.observability.tracing import init_tracing, trace_decision
    from trigguard.observability.prometheus import get_metrics_handler

    # Initialize
    init_tracing(service_name="trigguard")

    # Trace a decision
    with trace_decision(request) as span:
        result = evaluate(request)
        span.set_attribute("decision", result.decision)
"""

import os
import time
import logging
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from datetime import datetime, timezone
from functools import wraps

logger = logging.getLogger("trigguard.observability")


# ============================================================================
# Tracing (OpenTelemetry)
# ============================================================================


class TracingBackend(Enum):
    """Supported tracing backends."""

    NONE = "none"
    JAEGER = "jaeger"
    ZIPKIN = "zipkin"
    OTLP = "otlp"
    CONSOLE = "console"


@dataclass
class TracingConfig:
    """Configuration for distributed tracing."""

    enabled: bool = True
    service_name: str = "trigguard"
    backend: TracingBackend = TracingBackend.OTLP

    # OTLP endpoint
    otlp_endpoint: str = "http://localhost:4317"

    # Jaeger config
    jaeger_host: str = "localhost"
    jaeger_port: int = 6831

    # Zipkin config
    zipkin_endpoint: str = "http://localhost:9411/api/v2/spans"

    # Sampling
    sample_rate: float = 1.0  # 1.0 = 100%

    # Resource attributes
    environment: str = "development"
    version: str = "0.1.0"


# Global tracer
_tracer = None


def init_tracing(config: Optional[TracingConfig] = None) -> None:
    """
    Initialize OpenTelemetry tracing.

    Must be called before any traced code.
    """
    global _tracer

    if config is None:
        config = TracingConfig()

    if not config.enabled or config.backend == TracingBackend.NONE:
        logger.info("Tracing disabled")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

        # Create resource
        resource = Resource.create(
            {
                "service.name": config.service_name,
                "service.version": config.version,
                "deployment.environment": config.environment,
            }
        )

        # Create sampler
        sampler = TraceIdRatioBased(config.sample_rate)

        # Create provider
        provider = TracerProvider(resource=resource, sampler=sampler)

        # Configure exporter based on backend
        if config.backend == TracingBackend.OTLP:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            exporter = OTLPSpanExporter(endpoint=config.otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))

        elif config.backend == TracingBackend.JAEGER:
            from opentelemetry.exporter.jaeger.thrift import JaegerExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            exporter = JaegerExporter(
                agent_host_name=config.jaeger_host,
                agent_port=config.jaeger_port,
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))

        elif config.backend == TracingBackend.ZIPKIN:
            from opentelemetry.exporter.zipkin.json import ZipkinExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            exporter = ZipkinExporter(endpoint=config.zipkin_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))

        elif config.backend == TracingBackend.CONSOLE:
            from opentelemetry.sdk.trace.export import (
                ConsoleSpanExporter,
                SimpleSpanProcessor,
            )

            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(config.service_name)

        logger.info(f"Tracing initialized: backend={config.backend.value}")

    except ImportError as e:
        logger.warning(f"OpenTelemetry not available: {e}")
        _tracer = None


def get_tracer():
    """Get the configured tracer."""
    global _tracer

    if _tracer is None:
        try:
            from opentelemetry import trace

            _tracer = trace.get_tracer("trigguard")
        except ImportError:
            pass

    return _tracer


class NoOpSpan:
    """No-op span for when tracing is disabled."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass

    def add_event(self, name: str, attributes: Dict = None) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@contextmanager
def trace_decision(
    request: Dict[str, Any],
    operation_name: str = "trigguard.evaluate",
):
    """
    Create a tracing span for a decision.

    Usage:
        with trace_decision(request) as span:
            result = evaluate(request)
            span.set_attribute("decision", result.decision)
    """
    tracer = get_tracer()

    if tracer is None:
        yield NoOpSpan()
        return

    try:
        from opentelemetry.trace import Status, StatusCode

        with tracer.start_as_current_span(operation_name) as span:
            # Set request attributes
            span.set_attribute("trigguard.surface", request.get("surface", ""))
            span.set_attribute("trigguard.action", request.get("action", ""))
            span.set_attribute("trigguard.request_id", request.get("request_id", ""))

            if request.get("signals"):
                span.set_attribute("trigguard.signal_count", len(request["signals"]))

            try:
                yield span
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise

    except ImportError:
        yield NoOpSpan()


def traced(name: Optional[str] = None):
    """
    Decorator to trace a function.

    Usage:
        @traced("custom.operation")
        def my_function():
            ...
    """

    def decorator(func: Callable):
        operation_name = name or f"trigguard.{func.__name__}"

        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()

            if tracer is None:
                return func(*args, **kwargs)

            with tracer.start_as_current_span(operation_name):
                return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()

            if tracer is None:
                return await func(*args, **kwargs)

            with tracer.start_as_current_span(operation_name):
                return await func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


# ============================================================================
# Prometheus Metrics
# ============================================================================


@dataclass
class PrometheusConfig:
    """Configuration for Prometheus metrics."""

    enabled: bool = True
    prefix: str = "trigguard"
    port: int = 9090
    path: str = "/metrics"


# Metric collectors
class MetricsCollector:
    """
    Prometheus metrics for TrigGuard.

    Provides:
        - Request counters by surface/decision
        - Latency histograms
        - Cache hit/miss ratios
        - Error rates
    """

    def __init__(self, config: Optional[PrometheusConfig] = None):
        self.config = config or PrometheusConfig()
        self._initialized = False

        # Metric references
        self._request_counter = None
        self._decision_counter = None
        self._latency_histogram = None
        self._cache_hits = None
        self._cache_misses = None
        self._error_counter = None
        self._active_requests = None

        if self.config.enabled:
            self._init_metrics()

    def _init_metrics(self):
        """Initialize Prometheus metrics."""
        try:
            from prometheus_client import Counter, Histogram, Gauge

            prefix = self.config.prefix

            self._request_counter = Counter(
                f"{prefix}_requests_total",
                "Total requests by surface",
                ["surface", "action"],
            )

            self._decision_counter = Counter(
                f"{prefix}_decisions_total",
                "Total decisions by type",
                ["decision", "surface"],
            )

            self._latency_histogram = Histogram(
                f"{prefix}_decision_latency_seconds",
                "Decision latency in seconds",
                ["surface"],
                buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            )

            self._cache_hits = Counter(
                f"{prefix}_cache_hits_total",
                "Cache hits",
            )

            self._cache_misses = Counter(
                f"{prefix}_cache_misses_total",
                "Cache misses",
            )

            self._error_counter = Counter(
                f"{prefix}_errors_total",
                "Errors by type",
                ["error_type"],
            )

            self._active_requests = Gauge(
                f"{prefix}_active_requests",
                "Currently active requests",
            )

            self._initialized = True
            logger.info("Prometheus metrics initialized")

        except ImportError:
            logger.warning("prometheus_client not available")

    def record_request(self, surface: str, action: str = "") -> None:
        """Record an incoming request."""
        if self._request_counter:
            self._request_counter.labels(surface=surface, action=action).inc()

    def record_decision(self, decision: str, surface: str) -> None:
        """Record a decision outcome."""
        if self._decision_counter:
            self._decision_counter.labels(decision=decision, surface=surface).inc()

    def record_latency(self, surface: str, latency_seconds: float) -> None:
        """Record decision latency."""
        if self._latency_histogram:
            self._latency_histogram.labels(surface=surface).observe(latency_seconds)

    def record_cache_hit(self) -> None:
        """Record cache hit."""
        if self._cache_hits:
            self._cache_hits.inc()

    def record_cache_miss(self) -> None:
        """Record cache miss."""
        if self._cache_misses:
            self._cache_misses.inc()

    def record_error(self, error_type: str) -> None:
        """Record an error."""
        if self._error_counter:
            self._error_counter.labels(error_type=error_type).inc()

    @contextmanager
    def track_request(self, surface: str, action: str = ""):
        """
        Context manager to track a request lifecycle.

        Records request, latency, and active request gauge.
        """
        self.record_request(surface, action)

        if self._active_requests:
            self._active_requests.inc()

        start = time.perf_counter()

        try:
            yield
        finally:
            latency = time.perf_counter() - start
            self.record_latency(surface, latency)

            if self._active_requests:
                self._active_requests.dec()


# Global metrics instance
_metrics: Optional[MetricsCollector] = None


def get_metrics(config: Optional[PrometheusConfig] = None) -> MetricsCollector:
    """Get or create metrics collector."""
    global _metrics

    if _metrics is None:
        _metrics = MetricsCollector(config)

    return _metrics


def metrics_handler():
    """
    Get Prometheus metrics HTTP handler.

    For use with FastAPI or other frameworks.
    """
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        from fastapi import Response

        async def handler():
            return Response(
                content=generate_latest(),
                media_type=CONTENT_TYPE_LATEST,
            )

        return handler

    except ImportError:

        async def handler():
            return {"error": "prometheus_client not available"}

        return handler


# ============================================================================
# Structured Logging
# ============================================================================


class StructuredLogFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs logs in JSON format for log aggregation systems
    like ELK, Loki, or CloudWatch.
    """

    RESERVED_ATTRS = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
    }

    def __init__(
        self,
        service_name: str = "trigguard",
        include_timestamp: bool = True,
        include_level: bool = True,
    ):
        super().__init__()
        self.service_name = service_name
        self.include_timestamp = include_timestamp
        self.include_level = include_level

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "service": self.service_name,
            "message": record.getMessage(),
        }

        if self.include_timestamp:
            log_data["timestamp"] = datetime.fromtimestamp(
                record.created,
                tz=timezone.utc,
            ).isoformat()

        if self.include_level:
            log_data["level"] = record.levelname.lower()
            log_data["level_num"] = record.levelno

        # Add logger name
        log_data["logger"] = record.name

        # Add location info
        log_data["location"] = {
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
            }

        # Add extra fields (custom context)
        for key, value in record.__dict__.items():
            if key not in self.RESERVED_ATTRS:
                log_data[key] = value

        return json.dumps(log_data, default=str)


def configure_structured_logging(
    service_name: str = "trigguard",
    level: int = logging.INFO,
    json_output: bool = True,
) -> None:
    """
    Configure structured logging for TrigGuard.

    Args:
        service_name: Service name for log entries
        level: Log level
        json_output: Use JSON format (for production)
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setLevel(level)

    if json_output:
        handler.setFormatter(StructuredLogFormatter(service_name))
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )

    root_logger.addHandler(handler)

    logger.info(
        "Structured logging configured",
        extra={"json_output": json_output, "level": logging.getLevelName(level)},
    )


class LogContext:
    """
    Context manager for adding context to logs.

    Usage:
        with LogContext(request_id="123", surface="spend"):
            logger.info("Processing request")
            # Logs will include request_id and surface
    """

    _context: Dict[str, Any] = {}

    def __init__(self, **kwargs):
        self._additions = kwargs
        self._previous = {}

    def __enter__(self):
        for key, value in self._additions.items():
            self._previous[key] = self._context.get(key)
            self._context[key] = value
        return self

    def __exit__(self, *args):
        for key, prev_value in self._previous.items():
            if prev_value is None:
                self._context.pop(key, None)
            else:
                self._context[key] = prev_value

    @classmethod
    def get_context(cls) -> Dict[str, Any]:
        """Get current log context."""
        return cls._context.copy()


class ContextLogger(logging.LoggerAdapter):
    """Logger adapter that includes context in all logs."""

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        extra.update(LogContext.get_context())
        kwargs["extra"] = extra
        return msg, kwargs


def get_context_logger(name: str) -> ContextLogger:
    """Get a context-aware logger."""
    return ContextLogger(logging.getLogger(name), {})


# ============================================================================
# Audit Logger
# ============================================================================


class AuditLogger:
    """
    Specialized logger for audit events.

    Creates structured audit records for compliance and debugging.
    """

    def __init__(self, logger_name: str = "trigguard.audit"):
        self._logger = logging.getLogger(logger_name)

    def log_decision(
        self,
        request_id: str,
        surface: str,
        action: str,
        decision: str,
        reason: str,
        policy_version: str,
        latency_ms: float,
        signals: List[Dict] = None,
        receipt_hash: Optional[str] = None,
    ) -> None:
        """Log a decision audit event."""
        self._logger.info(
            f"Decision: {decision} for {surface}/{action}",
            extra={
                "event_type": "decision",
                "request_id": request_id,
                "surface": surface,
                "action": action,
                "decision": decision,
                "reason": reason,
                "policy_version": policy_version,
                "latency_ms": latency_ms,
                "signal_count": len(signals) if signals else 0,
                "receipt_hash": receipt_hash,
            },
        )

    def log_policy_change(
        self,
        old_version: str,
        new_version: str,
        source: str = "unknown",
    ) -> None:
        """Log a policy change event."""
        self._logger.warning(
            f"Policy changed: {old_version} -> {new_version}",
            extra={
                "event_type": "policy_change",
                "old_version": old_version,
                "new_version": new_version,
                "source": source,
            },
        )

    def log_escalation(
        self,
        request_id: str,
        surface: str,
        reason: str,
    ) -> None:
        """Log an escalation event."""
        self._logger.warning(
            f"Escalation required for {surface}",
            extra={
                "event_type": "escalation",
                "request_id": request_id,
                "surface": surface,
                "reason": reason,
            },
        )

    def log_security_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "medium",
    ) -> None:
        """Log a security-relevant event."""
        log_func = self._logger.warning if severity != "high" else self._logger.error

        log_func(
            f"Security event: {event_type}",
            extra={
                "event_type": "security",
                "security_event": event_type,
                "severity": severity,
                **details,
            },
        )


# Global audit logger
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the audit logger instance."""
    global _audit_logger

    if _audit_logger is None:
        _audit_logger = AuditLogger()

    return _audit_logger
