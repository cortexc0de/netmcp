"""NetMCP Server — Main entry point.

Professional-grade network analysis MCP server combining Wireshark/TShark,
Nmap scanning, and threat intelligence into a single MCP-compliant service.
"""

import os
import sys

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.nmap import NmapInterface
from netmcp.interfaces.threat_intel import ThreatIntelInterface
from netmcp.interfaces.tshark import TsharkInterface, TsharkNotFoundError
from netmcp.prompts.workflows import register_prompts

# Resources and prompts
from netmcp.resources import register_resources
from netmcp.tools.analysis import register_analysis_tools

# Tool registrations
from netmcp.tools.capture import register_capture_tools
from netmcp.tools.credentials import register_credential_tools
from netmcp.tools.export_tools import register_export_tools
from netmcp.tools.nmap_scan import register_nmap_tools
from netmcp.tools.streams import register_stream_tools
from netmcp.tools.threat_intel import register_threat_tools


def create_server() -> FastMCP:
    """Create and configure the NetMCP server with all tools, resources, and prompts."""

    mcp = FastMCP(
        "NetMCP",
        instructions=(
            "NetMCP provides professional-grade network analysis capabilities. "
            "Use tools for packet capture, PCAP analysis, Nmap scanning, "
            "threat intelligence, and credential extraction. "
            "Always validate inputs and follow security best practices."
        ),
    )

    # ── Initialize core components ──────────────────────────────────────
    sec = SecurityValidator()
    fmt = OutputFormatter()

    # ── Initialize interfaces ───────────────────────────────────────────
    # Tshark
    tshark_path = os.environ.get("NETMCP_TSHARK_PATH") or None
    try:
        tshark = TsharkInterface(tshark_path)
    except TsharkNotFoundError as e:
        print(f"WARNING: {e}", file=sys.stderr)
        tshark = None  # type: ignore

    # Nmap
    nmap = NmapInterface()

    # Threat Intelligence
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY") or None
    threat = ThreatIntelInterface(abuseipdb_key=abuseipdb_key)

    # ── Register Resources ──────────────────────────────────────────────
    register_resources(mcp, tshark, nmap, fmt)

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

    if nmap.available:
        register_nmap_tools(mcp, nmap, fmt, sec)

    return mcp


def main() -> None:
    """Entry point for the netmcp CLI."""
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
