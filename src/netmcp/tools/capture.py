"""Capture and network interface tools."""

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_capture_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register capture-related MCP tools."""

    @mcp.tool()
    async def get_network_interfaces() -> dict:
        """List all available network interfaces for packet capture."""
        try:
            interfaces = await tshark.list_interfaces()
            return fmt.format_success(
                {"count": len(interfaces), "interfaces": interfaces}, title="Network Interfaces"
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool()
    async def capture_live_packets(
        interface: str,
        duration: int = 5,
        packet_count: int = 100,
        bpf_filter: str = "",
    ) -> dict:
        """
        Capture live network packets from a specified interface.

        Args:
            interface: Network interface name (e.g., eth0, en0, Wi-Fi)
            duration: Maximum capture duration in seconds
            packet_count: Maximum number of packets to capture
            bpf_filter: BPF capture filter (e.g., 'tcp port 80')
        """
        try:
            sec.validate_interface(interface)
            sec.validate_capture_filter(bpf_filter)

            pcap_path = await tshark.capture_live(
                interface=interface,
                bpf_filter=bpf_filter,
                packet_count=packet_count,
                timeout=float(duration),
            )

            packets = await tshark.read_pcap(str(pcap_path))
            summary = {
                "interface": interface,
                "duration": duration,
                "filter": bpf_filter,
                "packets_captured": len(packets),
                "pcap_file": str(pcap_path),
                "packets": packets[:100],  # Limit output
            }
            return fmt.format_success(summary, title="Live Capture")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")
