# ── Build stage ──────────────────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir build && python -m build

# ── Runtime stage ────────────────────────────────────────────────────
FROM python:3.14-slim

LABEL org.opencontainers.image.source="https://github.com/cortexc0de/netmcp"
LABEL org.opencontainers.image.description="Professional-grade network analysis MCP server"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    nmap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap 2>/dev/null || true

RUN groupadd -r netmcp && useradd -r -g netmcp -d /home/netmcp -s /sbin/nologin netmcp \
    && mkdir -p /home/netmcp && chown netmcp:netmcp /home/netmcp

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

WORKDIR /home/netmcp
USER netmcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import netmcp; print('ok')" || exit 1

ENTRYPOINT ["netmcp"]
CMD ["--transport", "stdio"]
