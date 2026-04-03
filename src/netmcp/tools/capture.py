"""Capture and network interface tools."""

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_capture_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register capture-related MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="List Network Interfaces",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def get_network_interfaces() -> dict:
        """List all available network interfaces for packet capture."""
        try:
            interfaces = await tshark.list_interfaces()
            return fmt.format_success(
                {"count": len(interfaces), "interfaces": interfaces}, title="Network Interfaces"
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Capture Live Packets",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
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

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Quick Capture",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def quick_capture(
        interface: str = "eth0",
        packet_count: int = 10,
    ) -> dict:
        """
        Perform a quick packet capture (3 seconds, default interface).

        A fast way to see what's happening on the network without configuration.

        Args:
            interface: Network interface name (default: eth0)
            packet_count: Maximum packets to capture (default: 10)
        """
        try:
            sec.validate_interface(interface)

            pcap_path = await tshark.capture_live(
                interface=interface,
                bpf_filter="",
                packet_count=packet_count,
                timeout=3.0,
            )

            packets = await tshark.read_pcap(str(pcap_path))

            # Quick summary
            protocols = set()
            ips = set()
            for pkt in packets:
                layers = pkt.get("_source", {}).get("layers", {})
                if "frame.protocols" in layers:
                    protos = (
                        layers["frame.protocols"][0]
                        if isinstance(layers["frame.protocols"], list)
                        else layers["frame.protocols"]
                    )
                    protocols.update(protos.split(":"))
                for ip_field in ("ip.src", "ip.dst"):
                    if ip_field in layers:
                        val = layers[ip_field]
                        ips.add(val[0] if isinstance(val, list) else val)

            return fmt.format_success(
                {
                    "interface": interface,
                    "duration_seconds": 3,
                    "packets_captured": len(packets),
                    "unique_ips": sorted(ips),
                    "protocols_seen": sorted(protocols),
                    "pcap_file": str(pcap_path),
                    "packets": packets[:20],
                },
                title="Quick Capture",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Save Capture to File",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def save_capture_to_file(
        interface: str,
        output_file: str,
        duration: int = 10,
        packet_count: int = 500,
        bpf_filter: str = "",
    ) -> dict:
        """
        Capture network traffic and save to a PCAP file.

        Useful when you want to keep a capture for later analysis.

        Args:
            interface: Network interface name
            output_file: Path where to save the PCAP file
            duration: Max capture duration in seconds
            packet_count: Max packets to capture
            bpf_filter: BPF capture filter (optional)
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

            # Copy to user-specified path
            import shutil
            from pathlib import Path

            dest = Path(output_file)
            if not dest.is_absolute():
                dest = Path.cwd() / dest
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(pcap_path), str(dest))

            return fmt.format_success(
                {
                    "interface": interface,
                    "duration": duration,
                    "filter": bpf_filter,
                    "packets_captured": packet_count,
                    "output_file": str(dest),
                    "file_size_bytes": dest.stat().st_size,
                },
                title="Capture Saved",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")
