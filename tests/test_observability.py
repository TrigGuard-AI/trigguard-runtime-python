"""
TrigGuard Observability Tests

Unit tests for tracing, metrics, and logging.
"""

import pytest
import logging
import json
import time
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

from observability.tracing import (
    TracingConfig,
    TracingBackend,
    init_tracing,
    get_tracer,
    trace_decision,
    traced,
    NoOpSpan,
    PrometheusConfig,
    MetricsCollector,
    get_metrics,
    StructuredLogFormatter,
    configure_structured_logging,
    LogContext,
    get_context_logger,
    AuditLogger,
    get_audit_logger,
)


class TestTracingConfig:
    """Test tracing configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = TracingConfig()
        
        assert config.enabled is True
        assert config.service_name == "trigguard"
        assert config.backend == TracingBackend.OTLP
        assert config.sample_rate == 1.0
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = TracingConfig(
            service_name="custom-service",
            backend=TracingBackend.JAEGER,
            sample_rate=0.5,
        )
        
        assert config.service_name == "custom-service"
        assert config.backend == TracingBackend.JAEGER
        assert config.sample_rate == 0.5


class TestNoOpSpan:
    """Test no-op span for disabled tracing."""
    
    def test_noop_methods(self):
        """Test no-op span methods don't raise."""
        span = NoOpSpan()
        
        # These should not raise
        span.set_attribute("key", "value")
        span.set_status(None)
        span.record_exception(Exception("test"))
        span.add_event("event")
    
    def test_noop_context_manager(self):
        """Test no-op span as context manager."""
        span = NoOpSpan()
        
        with span as s:
            assert s is span


class TestTraceDecision:
    """Test trace_decision context manager."""
    
    def test_trace_without_otel(self):
        """Test tracing works without OpenTelemetry."""
        request = {"surface": "read", "action": "get"}
        
        with trace_decision(request) as span:
            # Should get no-op span
            span.set_attribute("test", "value")
    
    @patch("observability.tracing.get_tracer")
    def test_trace_with_mock_tracer(self, mock_get_tracer):
        """Test tracing with mocked tracer."""
        mock_span = Mock()
        mock_span.__enter__ = Mock(return_value=mock_span)
        mock_span.__exit__ = Mock(return_value=None)
        
        mock_tracer = Mock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_get_tracer.return_value = mock_tracer
        
        request = {"surface": "read", "action": "get", "signals": [{}]}
        
        with trace_decision(request) as span:
            pass
        
        # Verify span was created with correct attributes
        mock_tracer.start_as_current_span.assert_called_once()


class TestTracedDecorator:
    """Test @traced decorator."""
    
    def test_traced_sync_function(self):
        """Test tracing sync function."""
        @traced("test.operation")
        def my_function(x):
            return x * 2
        
        result = my_function(5)
        assert result == 10
    
    def test_traced_preserves_function_name(self):
        """Test decorator preserves function metadata."""
        @traced()
        def original_function():
            """Original docstring."""
            pass
        
        assert original_function.__name__ == "original_function"
        assert original_function.__doc__ == "Original docstring."


class TestPrometheusMetrics:
    """Test Prometheus metrics collector."""
    
    def test_metrics_without_prometheus(self):
        """Test metrics work without prometheus_client."""
        # Reset global metrics
        import observability.tracing as module
        module._metrics = None
        
        with patch.dict("sys.modules", {"prometheus_client": None}):
            metrics = MetricsCollector(PrometheusConfig(enabled=True))
            
            # Should not raise
            metrics.record_request("read")
            metrics.record_decision("allow", "read")
            metrics.record_latency("read", 0.01)
            metrics.record_cache_hit()
            metrics.record_error("test")
    
    @patch("observability.tracing.Counter")
    @patch("observability.tracing.Histogram")
    @patch("observability.tracing.Gauge")
    def test_metrics_with_prometheus(self, mock_gauge, mock_histogram, mock_counter):
        """Test metrics with mocked prometheus_client."""
        config = PrometheusConfig(prefix="test")
        metrics = MetricsCollector(config)
        
        # Counters should be created
        assert mock_counter.call_count >= 4
    
    def test_track_request_context_manager(self):
        """Test request tracking context manager."""
        metrics = MetricsCollector(PrometheusConfig(enabled=False))
        
        with metrics.track_request("read", "get_data"):
            time.sleep(0.01)
        
        # Should complete without error


class TestStructuredLogging:
    """Test structured JSON logging."""
    
    def test_json_formatter(self):
        """Test JSON log formatting."""
        formatter = StructuredLogFormatter(service_name="test-service")
        
        # Create a log record
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert data["service"] == "test-service"
        assert data["message"] == "Test message"
        assert data["level"] == "info"
        assert data["logger"] == "test.logger"
        assert data["location"]["line"] == 42
    
    def test_formatter_with_exception(self):
        """Test formatting with exception info."""
        formatter = StructuredLogFormatter()
        
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert "exception" in data
        assert data["exception"]["type"] == "ValueError"
    
    def test_formatter_with_extra(self):
        """Test formatting with extra fields."""
        formatter = StructuredLogFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Message",
            args=(),
            exc_info=None,
        )
        record.request_id = "req-123"
        record.surface = "read"
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert data["request_id"] == "req-123"
        assert data["surface"] == "read"


class TestLogContext:
    """Test log context manager."""
    
    def test_context_nesting(self):
        """Test nested contexts."""
        with LogContext(request_id="outer"):
            assert LogContext.get_context()["request_id"] == "outer"
            
            with LogContext(request_id="inner", surface="read"):
                ctx = LogContext.get_context()
                assert ctx["request_id"] == "inner"
                assert ctx["surface"] == "read"
            
            # Should restore outer
            assert LogContext.get_context()["request_id"] == "outer"
    
    def test_context_cleanup(self):
        """Test context is cleaned up."""
        with LogContext(temp_key="value"):
            assert "temp_key" in LogContext.get_context()
        
        assert "temp_key" not in LogContext.get_context()


class TestContextLogger:
    """Test context-aware logger."""
    
    def test_context_logger_adds_context(self):
        """Test logger includes context."""
        logger = get_context_logger("test")
        
        with LogContext(request_id="test-123"):
            # The logger should include context when logging
            msg, kwargs = logger.process("Test message", {})
            assert kwargs["extra"]["request_id"] == "test-123"


class TestAuditLogger:
    """Test audit logging."""
    
    def test_log_decision(self):
        """Test logging decision events."""
        audit = AuditLogger("test.audit")
        
        with patch.object(audit._logger, "info") as mock_info:
            audit.log_decision(
                request_id="req-123",
                surface="spend",
                action="transfer",
                decision="deny",
                reason="Amount exceeds limit",
                policy_version="v1.0",
                latency_ms=15.5,
            )
            
            mock_info.assert_called_once()
            call_kwargs = mock_info.call_args[1]
            assert call_kwargs["extra"]["event_type"] == "decision"
            assert call_kwargs["extra"]["decision"] == "deny"
    
    def test_log_policy_change(self):
        """Test logging policy changes."""
        audit = AuditLogger("test.audit")
        
        with patch.object(audit._logger, "warning") as mock_warning:
            audit.log_policy_change(
                old_version="v1",
                new_version="v2",
                source="admin-api",
            )
            
            mock_warning.assert_called_once()
            call_kwargs = mock_warning.call_args[1]
            assert call_kwargs["extra"]["event_type"] == "policy_change"
    
    def test_log_security_event(self):
        """Test logging security events."""
        audit = AuditLogger("test.audit")
        
        with patch.object(audit._logger, "error") as mock_error:
            audit.log_security_event(
                event_type="unauthorized_access",
                details={"ip": "192.168.1.1"},
                severity="high",
            )
            
            mock_error.assert_called_once()


class TestGetAuditLogger:
    """Test global audit logger."""
    
    def test_singleton(self):
        """Test audit logger is singleton."""
        # Reset
        import observability.tracing as module
        module._audit_logger = None
        
        logger1 = get_audit_logger()
        logger2 = get_audit_logger()
        
        assert logger1 is logger2


class TestConfigureStructuredLogging:
    """Test logging configuration."""
    
    def test_configure_json_output(self):
        """Test configuring JSON output."""
        # This modifies global state, so just verify it doesn't raise
        configure_structured_logging(
            service_name="test",
            level=logging.DEBUG,
            json_output=True,
        )
    
    def test_configure_standard_output(self):
        """Test configuring standard output."""
        configure_structured_logging(
            service_name="test",
            json_output=False,
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
