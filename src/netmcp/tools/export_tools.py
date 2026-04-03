"""Data export tools (JSON, CSV, format conversion)."""

import re

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface

_TSHARK_FIELD_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]{0,127}$")

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

_CSV_DEFAULT_FIELDS = [
    "frame.number",
    "frame.time",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "frame.len",
    "_ws.col.Info",
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
            return fmt.truncate_output(fmt.format_success(
                {
                    "filepath": str(validated_path),
                    "packet_count": len(packets),
                    "packets": packets[:500],
                },
                title="JSON Export",
            ))
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
        separator: str = ",",
    ) -> dict:
        """
        Export packet fields from a PCAP as CSV with proper headers using tshark -E flags.

        Args:
            filepath: Path to PCAP/PCAPNG file
            fields: Comma-separated field names (default: standard fields including column fields)
            display_filter: Wireshark display filter
            separator: CSV field separator character (default: comma)
        """
        try:
            if not sec.check_rate_limit("export_packets_csv"):
                raise ValueError("Rate limit exceeded for export_packets_csv")

            validated_path = sec.sanitize_filepath(filepath)
            if display_filter:
                sec.validate_display_filter(display_filter)

            field_list = (
                [f.strip() for f in fields.split(",") if f.strip()]
                if fields
                else list(_CSV_DEFAULT_FIELDS)
            )
            for field_name in field_list:
                if not _TSHARK_FIELD_RE.match(field_name):
                    raise ValueError(f"Invalid tshark field name: {field_name!r}")

            args = ["-r", str(validated_path), "-T", "fields"]
            for f in field_list:
                args.extend(["-e", f])
            args.extend([
                "-E", f"separator={separator}",
                "-E", "header=y",
                "-E", "quote=d",
            ])
            if display_filter:
                args.extend(["-Y", display_filter])

            result = await tshark._run(args, timeout=60.0)
            if result.returncode != 0:
                raise RuntimeError(f"tshark CSV export failed: {result.stderr}")

            csv_text = result.stdout

            sec.audit_log("export_packets_csv", {
                "filepath": str(validated_path),
                "fields": field_list,
                "display_filter": display_filter or "(none)",
            })

            return fmt.truncate_output(fmt.format_success(
                {
                    "filepath": str(validated_path),
                    "csv": csv_text[:50000],
                    "fields": field_list,
                },
                title="CSV Export",
            ))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    # ── get_packet_summary ──────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get Packet Summary",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def get_packet_summary(
        file_path: str,
        count: int = 20,
        display_filter: str = "",
    ) -> dict:
        """
        Get a quick packet summary similar to Wireshark's packet list view.

        Uses column fields (_ws.col.*) for human-readable output.

        Args:
            file_path: Path to PCAP/PCAPNG file
            count: Maximum number of packets to show (default: 20)
            display_filter: Optional Wireshark display filter
        """
        try:
            if not sec.check_rate_limit("get_packet_summary"):
                raise ValueError("Rate limit exceeded for get_packet_summary")

            validated_path = sec.sanitize_filepath(file_path)
            if display_filter:
                sec.validate_display_filter(display_filter)

            summary_fields = [
                "frame.number",
                "frame.time_relative",
                "ip.src",
                "ip.dst",
                "_ws.col.Protocol",
                "frame.len",
                "_ws.col.Info",
            ]

            args = ["-r", str(validated_path), "-c", str(count), "-T", "fields"]
            for f in summary_fields:
                args.extend(["-e", f])
            args.extend(["-E", "header=y", "-E", "separator=\t"])
            if display_filter:
                args.extend(["-Y", display_filter])

            result = await tshark._run(args, timeout=60.0)
            if result.returncode != 0:
                raise RuntimeError(f"tshark packet summary failed: {result.stderr}")

            # Format output as a table
            lines = result.stdout.strip().splitlines()
            table_lines = []
            for line in lines:
                table_lines.append(line)

            sec.audit_log("get_packet_summary", {
                "filepath": str(validated_path),
                "count": count,
                "display_filter": display_filter or "(none)",
            })

            output = {
                "filepath": str(validated_path),
                "count": count,
                "display_filter": display_filter or "(none)",
                "summary": "\n".join(table_lines),
                "raw_output": result.stdout,
            }
            return fmt.truncate_output(fmt.format_success(output, title="Packet Summary"))
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
