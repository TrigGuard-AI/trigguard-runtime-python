"""
TrigGuard Observability Module

Production-grade observability stack.
"""

from observability.tracing import (
    # Tracing
    TracingConfig,
    TracingBackend,
    init_tracing,
    get_tracer,
    trace_decision,
    traced,
    
    # Metrics
    PrometheusConfig,
    MetricsCollector,
    get_metrics,
    metrics_handler,
    
    # Logging
    StructuredLogFormatter,
    configure_structured_logging,
    LogContext,
    ContextLogger,
    get_context_logger,
    
    # Audit
    AuditLogger,
    get_audit_logger,
)

__all__ = [
    # Tracing
    "TracingConfig",
    "TracingBackend",
    "init_tracing",
    "get_tracer",
    "trace_decision",
    "traced",
    
    # Metrics
    "PrometheusConfig",
    "MetricsCollector",
    "get_metrics",
    "metrics_handler",
    
    # Logging
    "StructuredLogFormatter",
    "configure_structured_logging",
    "LogContext",
    "ContextLogger",
    "get_context_logger",
    
    # Audit
    "AuditLogger",
    "get_audit_logger",
]
