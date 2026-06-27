# =============================================================================
# scau-connect Dockerfile
# Multi-stage build for smaller image size
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev --no-editable

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL maintainer="scau-connect"
LABEL description="SCAU aTrust CAS authentication proxy tool"

# Install Chrome, ChromeDriver, and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Chrome and ChromeDriver
    google-chrome-stable \
    chromium \
    chromium-sandbox \
    # Virtual display for headless Chrome
    xvfb \
    # Fonts for Chinese
    fonts-noto-cjk \
    # OpenSSL and network tools
    libssl3 \
    ca-certificates \
    curl \
    wget \
    # Cleanup
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && find /var/cache -type f -delete

# Download ChromeDriver matching Chrome version
RUN CHROME_VERSION=$(google-chrome --version | awk '{print $3}' | cut -d'.' -f1) && \
    CHROMEDRIVER_VERSION=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROME_VERSION}") && \
    wget -q "https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip" -O /tmp/chromedriver.zip && \
    unzip -o /tmp/chromedriver.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/chromedriver && \
    rm /tmp/chromedriver.zip

# Set Chrome binary path
ENV CHROME_BIN=/usr/bin/google-chrome
ENV CHROMEDRIVER_PATH=/usr/local/bin/chromedriver

# Chrome options for Docker (no sandbox, headless, disable GPU)
ENV CHROME_OPTIONS="--no-sandbox --disable-gpu --disable-dev-shm-usage --disable-software-rasterizer"

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application source
COPY --chown=appuser:appuser src/ /app/src/

# Set up Python path
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:$PYTHONPATH"
ENV PYTHONUNBUFFERED=1

# Create directories for runtime artifacts
RUN mkdir -p /app/.proxy-ca /app/.session && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose proxy ports
EXPOSE 1080 1081

# Health check (check if proxy is responding)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import socket; socket.create_connection(('localhost', 1081), timeout=5).close()" || exit 1

# Default command
ENTRYPOINT ["scau-connect"]
CMD ["--help"]
