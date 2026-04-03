"""MCP Resources for NetMCP."""

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.interfaces.nmap import NmapInterface
from netmcp.interfaces.tshark import TsharkInterface


def register_resources(
    mcp: FastMCP,
    tshark: TsharkInterface,
    nmap: NmapInterface,
    fmt: OutputFormatter,
) -> None:
    """Register MCP resources."""

    @mcp.resource("netmcp://interfaces")
    def get_interfaces() -> str:
        """Dynamic list of available network interfaces."""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Can't await directly, use run_until_complete
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as pool:
                    interfaces = loop.run_in_executor(
                        pool, lambda: asyncio.run(tshark.list_interfaces())
                    )
                    # For sync context, we need a different approach
                    return "Use get_network_interfaces tool for interface list"
            else:
                interfaces = loop.run_until_complete(tshark.list_interfaces())
                return fmt.format_json({"count": len(interfaces), "interfaces": interfaces})
        except Exception as e:
            return f"Error: {e}"

    @mcp.resource("netmcp://captures")
    def get_captures() -> str:
        """List available PCAP files in common directories."""
        from pathlib import Path

        search_dirs = [
            Path.home() / "captures",
            Path.home() / "pcaps",
            Path("/tmp"),
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
            "tools": [
                "get_network_interfaces",
                "capture_live_packets",
                "analyze_pcap_file",
                "get_protocol_statistics",
                "get_capture_file_info",
                "capture_targeted_traffic",
                "analyze_http_traffic",
                "detect_network_protocols",
                "follow_tcp_stream",
                "follow_udp_stream",
                "list_tcp_streams",
                "export_packets_json",
                "export_packets_csv",
                "convert_pcap_format",
                "nmap_port_scan",
                "nmap_service_detection",
                "nmap_os_detection",
                "nmap_vulnerability_scan",
                "nmap_quick_scan",
                "nmap_comprehensive_scan",
                "check_ip_threat_intel",
                "scan_capture_for_threats",
                "extract_credentials",
            ],
        }
        return fmt.format_json(info)
