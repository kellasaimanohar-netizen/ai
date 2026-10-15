FROM python:3.12-slim

LABEL org.opencontainers.image.title="certifyai-backend" \
      org.opencontainers.image.description="CertifyAI Backend API & Agent Audit Engine" \
      org.opencontainers.image.version="10.3.0" \
      org.opencontainers.image.vendor="CertifyAI" \
      org.opencontainers.image.url="https://certifyai.in"

WORKDIR /app

# Install system dependencies (git for repository scanning, curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md requirements.txt ./
COPY src/ src/
RUN pip install --no-cache-dir ".[all]" && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pytest pytest-asyncio

COPY . /app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000"]
