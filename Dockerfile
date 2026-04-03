# ── Build stage ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --prefix=/install build
RUN python -m build

# ── Runtime stage ────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/cortexc0de/netmcp"
LABEL org.opencontainers.image.description="Professional-grade network analysis MCP server"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    nmap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    # Allow non-root packet capture
    && setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap 2>/dev/null || true

# Create non-root user
RUN groupadd -r netmcp && useradd -r -g netmcp -d /home/netmcp -s /sbin/nologin netmcp \
    && mkdir -p /home/netmcp && chown netmcp:netmcp /home/netmcp

# Install netmcp package
COPY --from=builder /install /usr/local
RUN pip install --no-cache-dir netmcp 2>/dev/null || \
    pip install --no-cache-dir /build/dist/*.whl 2>/dev/null || true

WORKDIR /home/netmcp
USER netmcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import netmcp; print('ok')" || exit 1

ENTRYPOINT ["netmcp"]
