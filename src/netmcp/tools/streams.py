"""Stream following tools (TCP/UDP conversation reconstruction)."""

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_stream_tools(mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator) -> None:
    """Register stream-related MCP tools."""

    @mcp.tool()
    async def follow_tcp_stream(
        filepath: str,
        stream_index: int = 0,
        format: str = "ascii",
    ) -> dict:
        """
        Reconstruct a TCP conversation from a PCAP file.

        Args:
            filepath: Path to PCAP/PCAPNG file
            stream_index: Index of the TCP stream to follow (0-based)
            format: Output format: ascii, hex, or raw
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            stream = await tshark.follow_stream(str(validated_path), stream_index, "tcp", format)
            return fmt.format_success(
                {"filepath": str(validated_path), "stream_index": stream_index, "content": stream},
                title=f"TCP Stream #{stream_index}",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool()
    async def follow_udp_stream(
        filepath: str,
        stream_index: int = 0,
        format: str = "ascii",
    ) -> dict:
        """
        Reconstruct a UDP conversation from a PCAP file.

        Args:
            filepath: Path to PCAP/PCAPNG file
            stream_index: Index of the UDP stream to follow (0-based)
            format: Output format: ascii, hex, or raw
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            stream = await tshark.follow_stream(str(validated_path), stream_index, "udp", format)
            return fmt.format_success(
                {"filepath": str(validated_path), "stream_index": stream_index, "content": stream},
                title=f"UDP Stream #{stream_index}",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool()
    async def list_tcp_streams(filepath: str) -> dict:
        """
        List all TCP conversations found in a PCAP file.

        Args:
            filepath: Path to PCAP/PCAPNG file
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            streams = await tshark.list_streams(str(validated_path), "tcp")
            return fmt.format_success(
                {"filepath": str(validated_path), "stream_count": len(streams), "streams": streams},
                title="TCP Streams",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")
