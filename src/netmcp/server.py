"""NetMCP Server — Main entry point.

Professional-grade network analysis MCP server combining Wireshark/TShark,
Nmap scanning, and threat intelligence into a single MCP-compliant service.
"""

import argparse
import os
import sys

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.history import CaptureHistory
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.nmap import NmapInterface
from netmcp.interfaces.threat_intel import ThreatIntelInterface
from netmcp.interfaces.tshark import TsharkInterface, TsharkNotFoundError
from netmcp.prompts.workflows import register_prompts

# Resources and prompts
from netmcp.resources import register_resources
from netmcp.tools.advanced import register_advanced_tools
from netmcp.tools.analysis import register_analysis_tools

# Tool registrations
from netmcp.tools.capture import register_capture_tools
from netmcp.tools.credentials import register_credential_tools
from netmcp.tools.export_tools import register_export_tools
from netmcp.tools.flow_tls import register_flow_tls_tools
from netmcp.tools.nmap_scan import register_nmap_tools
from netmcp.tools.pcap_tools import register_pcap_tools
from netmcp.tools.profiles import register_profile_tools
from netmcp.tools.streaming import register_streaming_tools
from netmcp.tools.streams import register_stream_tools
from netmcp.tools.threat_intel import register_threat_tools


def create_server(host: str = "0.0.0.0", port: int = 8080) -> FastMCP:
    """Create and configure the NetMCP server with all tools, resources, and prompts.

    Args:
        host: Host to bind for HTTP/SSE transports.
        port: Port to bind for HTTP/SSE transports.
    """

    mcp = FastMCP(
        "NetMCP",
        instructions=(
            "NetMCP provides professional-grade network analysis capabilities. "
            "Use tools for packet capture, PCAP analysis, Nmap scanning, "
            "threat intelligence, and credential extraction. "
            "Always validate inputs and follow security best practices."
        ),
        host=host,
        port=port,
    )

    # ── Initialize core components ──────────────────────────────────────
    sec = SecurityValidator()
    fmt = OutputFormatter()
    history = CaptureHistory()

    # ── Initialize interfaces ───────────────────────────────────────────
    # Tshark
    tshark_path = os.environ.get("NETMCP_TSHARK_PATH") or None
    try:
        tshark = TsharkInterface(tshark_path)
    except TsharkNotFoundError as e:
        print(f"WARNING: {e}", file=sys.stderr)
        tshark = None  # type: ignore

    # Nmap
    nmap = NmapInterface(security=sec)

    # Threat Intelligence
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY") or None
    threat = ThreatIntelInterface(abuseipdb_key=abuseipdb_key)

    # ── Register Resources ──────────────────────────────────────────────
    register_resources(mcp, tshark, nmap, fmt, history)

    # ── Register Prompts ───────────────────────────────────────────────
    register_prompts(mcp)

    # ── Register Tools (only if interfaces are available) ───────────────
    if tshark:
        register_capture_tools(mcp, tshark, fmt, sec)
        register_analysis_tools(mcp, tshark, fmt, sec)
        register_stream_tools(mcp, tshark, fmt, sec)
        register_export_tools(mcp, tshark, fmt, sec)
        register_credential_tools(mcp, tshark, fmt, sec)
        register_threat_tools(mcp, tshark, threat, fmt, sec)
        register_streaming_tools(mcp, tshark, fmt, sec)
        register_profile_tools(mcp, tshark, fmt, sec)
        register_pcap_tools(mcp, tshark, fmt, sec)
        register_flow_tls_tools(mcp, tshark, fmt, sec)
        register_advanced_tools(mcp, tshark, fmt, sec)

    if nmap.available:
        register_nmap_tools(mcp, nmap, fmt, sec)

    return mcp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the NetMCP server."""
    parser = argparse.ArgumentParser(description="NetMCP - Network Analysis MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for HTTP/SSE transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP/SSE transport (default: 8080)",
    )
    return parser.parse_args(argv)


def main() -> None:
    """Entry point for the netmcp CLI."""
    args = parse_args()
    server = create_server(host=args.host, port=args.port)
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
