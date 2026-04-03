"""MCP Resources for NetMCP."""

import subprocess
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.history import CaptureHistory
from netmcp.interfaces.nmap import NmapInterface
from netmcp.interfaces.tshark import TsharkInterface


def register_resources(
    mcp: FastMCP,
    tshark: TsharkInterface,
    nmap: NmapInterface,
    fmt: OutputFormatter,
    history: CaptureHistory | None = None,
) -> None:
    """Register MCP resources."""

    @mcp.resource("netmcp://interfaces")
    def get_interfaces() -> str:
        """Dynamic list of available network interfaces."""
        try:
            result = subprocess.run(
                [tshark.tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            if result.returncode != 0:
                return f"Error listing interfaces: {result.stderr}"

            interfaces = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if ". " in line:
                    line = line.split(". ", 1)[1]
                if " (" in line:
                    line = line.split(" (", 1)[0]
                interfaces.append(line.strip())

            return fmt.format_json({"count": len(interfaces), "interfaces": interfaces})
        except FileNotFoundError:
            return f"Error: tshark not found at {tshark.tshark_path}"
        except subprocess.TimeoutExpired:
            return "Error: interface listing timed out"
        except Exception as e:
            return f"Error: {e}"

    @mcp.resource("netmcp://captures")
    def get_captures() -> str:
        """List available PCAP files in common directories."""
        search_dirs = [
            Path.home() / "captures",
            Path.home() / "pcaps",
            Path.cwd(),
        ]

        captures = []
        for d in search_dirs:
            if d.exists():
                for f in d.glob("*.pcap"):
                    captures.append(
                        {"path": str(f), "size_mb": round(f.stat().st_size / 1024 / 1024, 2)}
                    )
                for f in d.glob("*.pcapng"):
                    captures.append(
                        {"path": str(f), "size_mb": round(f.stat().st_size / 1024 / 1024, 2)}
                    )

        return fmt.format_json({"count": len(captures), "files": captures})

    @mcp.resource("netmcp://system/info")
    def get_system_info() -> str:
        """System capabilities and tool availability."""
        import platform
        import sys

        info = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "tshark_available": tshark.tshark_path is not None,
            "tshark_path": tshark.tshark_path,
            "nmap_available": nmap.available,
            "tools": (
                list(mcp._tool_manager._tools.keys())
                if hasattr(mcp, "_tool_manager")
                and hasattr(mcp._tool_manager, "_tools")
                else []
            ),
        }
        return fmt.format_json(info)

    @mcp.resource("analysis://history")
    async def get_analysis_history() -> str:
        """Recent analysis history."""
        if history is None:
            return "History tracking not enabled."

        entries = history.get_recent(20)
        if not entries:
            return "No analysis history yet."

        lines = ["# Analysis History\n"]
        for e in entries:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.timestamp))
            lines.append(f"- [{ts}] {e.tool_name}: {e.file_path}")
            if e.summary:
                lines.append(f"  {e.summary}")
            if e.duration > 0:
                lines.append(f"  Duration: {e.duration:.1f}s")
        return "\n".join(lines)

    @mcp.resource("network://help")
    async def get_help() -> str:
        """Comprehensive help and usage guide."""
        return """# NetMCP — Network Analysis MCP Server

## Quick Start
- Analyze PCAP: `analyze_pcap(file_path="/path/to/capture.pcap")`
- Live capture: `quick_capture(interface="eth0", duration=10)`
- Scan network: `scan_network(target="192.168.1.0/24")`

## Tool Categories

### Capture & Analysis
- `analyze_pcap` — Full PCAP analysis
- `quick_capture` — Quick packet capture
- `capture_targeted_traffic` — Filtered capture
- `analyze_large_pcap` — Streaming analysis for large files

### Protocol Analysis
- `analyze_http_traffic` — HTTP request/response analysis
- `analyze_dns_traffic` — DNS query/response analysis
- `get_protocol_hierarchy` — Protocol distribution
- `get_expert_info` — Wireshark expert warnings

### Network Flows
- `visualize_network_flows` — ASCII/Mermaid flow diagrams
- `get_flow_statistics` — Flow statistics
- `follow_stream` — TCP/UDP stream following

### Security
- `extract_credentials` — Credential extraction
- `decrypt_tls_traffic` — TLS decryption
- `analyze_tls_handshake` — TLS handshake analysis
- `check_threat_intelligence` — Threat intel lookup

### PCAP Tools
- `diff_pcap_files` — Compare PCAPs
- `merge_pcap_files` — Merge PCAPs
- `slice_pcap` — Slice/filter PCAPs
- `decode_packet` — Decode single packet

### Network Scanning
- `scan_network` — Nmap scan
- `quick_scan` — Fast port scan
- `scan_vulnerabilities` — Vulnerability scan

### Export
- `export_packets_json` — JSON export
- `export_specific_fields` — Field extraction

### Wireshark Profiles
- `list_wireshark_profiles` — List profiles
- `apply_profile_capture` — Analyze with profile
- `get_color_filters` — Color filter rules

## Resources
- `system://info` — System status
- `analysis://history` — Recent analysis history
- `network://help` — This help text

## Tips
- Use display filters: `ip.addr == 10.0.0.1 && tcp.port == 443`
- For large files, use `analyze_large_pcap` with chunking
- Check `get_expert_info` for Wireshark warnings
"""
