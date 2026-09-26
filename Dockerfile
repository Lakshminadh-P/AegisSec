# AegisSec Dockerfile
# Security Best Practices:
# 1. Use specific base image version (not :latest)
# 2. Run as non-root user
# 3. Minimal base image
# 4. No hardcoded secrets
# 5. Health check included

FROM python:3.11-slim

# Security: Set metadata
LABEL maintainer="AegisSec" \
      description="DevSecOps Security Platform" \
      version="1.0.0"

# Security: Don't run as root
RUN groupadd -r aegissec && useradd -r -g aegissec -m aegissec

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker layer caching optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY frontend/ ./frontend/

# Security: Switch to non-root user
USER aegissec

# Environment variables (no secrets here — use .env or Docker secrets)
ENV APP_ENV=production
ENV DEBUG=false
ENV HOST=0.0.0.0
ENV PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
