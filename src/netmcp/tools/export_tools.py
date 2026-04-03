"""Data export tools (JSON, CSV, format conversion)."""

import csv
import io
import re

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface

_TSHARK_FIELD_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{0,127}$")

_DEFAULT_EXPORT_FIELDS = [
    "frame.number",
    "frame.time",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.protocols",
    "frame.len",
]


def register_export_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register export-related MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Export Packets Json",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def export_packets_json(
        filepath: str,
        display_filter: str = "",
        max_packets: int = 10000,
    ) -> dict:
        """
        Export packets from a PCAP file as structured JSON.

        Args:
            filepath: Path to PCAP/PCAPNG file
            display_filter: Wireshark display filter
            max_packets: Maximum packets to export
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            if display_filter:
                sec.validate_display_filter(display_filter)
            packets = await tshark.export_json(str(validated_path), display_filter, max_packets)
            return fmt.format_success(
                {
                    "filepath": str(validated_path),
                    "packet_count": len(packets),
                    "packets": packets[:500],
                },
                title="JSON Export",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Export Packets Csv",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def export_packets_csv(
        filepath: str,
        fields: str = "",
        display_filter: str = "",
    ) -> dict:
        """
        Export specific packet fields from a PCAP as CSV.

        Args:
            filepath: Path to PCAP/PCAPNG file
            fields: Comma-separated field names (default: standard fields)
            display_filter: Wireshark display filter
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            if display_filter:
                sec.validate_display_filter(display_filter)
            field_list = (
                [f.strip() for f in fields.split(",")] if fields else _DEFAULT_EXPORT_FIELDS
            )
            for field_name in field_list:
                if not _TSHARK_FIELD_RE.match(field_name):
                    raise ValueError(f"Invalid tshark field name: {field_name!r}")
            rows = await tshark.export_fields(str(validated_path), field_list, display_filter)

            # Convert to CSV string
            output = io.StringIO()
            if rows:
                writer = csv.DictWriter(output, fieldnames=field_list)
                writer.writeheader()
                writer.writerows(rows)
            csv_text = output.getvalue()

            return fmt.format_success(
                {"filepath": str(validated_path), "row_count": len(rows), "csv": csv_text[:50000]},
                title="CSV Export",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Convert Pcap Format",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def convert_pcap_format(
        filepath: str,
        output_format: str = "pcapng",
    ) -> dict:
        """
        Convert a PCAP file between pcap and pcapng formats.

        Args:
            filepath: Path to source PCAP file
            output_format: Target format: pcap or pcapng
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            if output_format not in ("pcap", "pcapng"):
                raise ValueError("output_format must be 'pcap' or 'pcapng'")

            output_path = str(validated_path.with_suffix(f".{output_format}"))

            result = await tshark.convert_format(
                str(validated_path), output_path, timeout=60.0
            )
            if result.returncode != 0:
                raise RuntimeError(f"Format conversion failed: {result.stderr}")

            return fmt.format_success(
                {"input": str(validated_path), "output": output_path, "format": output_format},
                title="Format Conversion",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")
