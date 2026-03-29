# TrigGuard Runtime Docker Image
#
# Build:   docker build -t trigguard-runtime .
# Run:     docker run -p 8080:8080 trigguard-runtime
# Health:  curl http://localhost:8080/health
#
# Multi-stage build for minimal image size

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir build

# Copy source
COPY pyproject.toml README.md LICENSE ./
COPY trigguard/ trigguard/

# Build wheel
RUN python -m build --wheel

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.11-slim

LABEL org.opencontainers.image.title="TrigGuard Runtime"
LABEL org.opencontainers.image.description="Execution authorization runtime for AI agents"
LABEL org.opencontainers.image.version="0.2.0"
LABEL org.opencontainers.image.vendor="TrigGuard"
LABEL org.opencontainers.image.source="https://gitlab.com/TrigGuardAI/trigguard-kernel"

# Create non-root user
RUN groupadd -r trigguard && useradd -r -g trigguard trigguard

WORKDIR /app

# Copy wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install the package
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Switch to non-root user
USER trigguard

# Expose runtime port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Default command
CMD ["trigguard-runtime", "--host", "0.0.0.0", "--port", "8080"]
