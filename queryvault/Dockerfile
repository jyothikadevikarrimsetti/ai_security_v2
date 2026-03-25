# ── Stage 1: Build ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ───────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="QueryVault Team"
LABEL description="QueryVault - AI Security Framework"

# Security: run as non-root
RUN groupadd -r queryvault && useradd -r -g queryvault queryvault

WORKDIR /srv

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code into queryvault/ package directory
COPY app/ ./queryvault/app/
COPY data/ ./queryvault/data/
COPY scripts/ ./queryvault/scripts/

# Ensure data directory is readable
RUN chown -R queryvault:queryvault /srv

USER queryvault

EXPOSE 8950

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8950/health')" || exit 1

CMD ["uvicorn", "queryvault.app.main:app", "--host", "0.0.0.0", "--port", "8950", "--workers", "1"]
