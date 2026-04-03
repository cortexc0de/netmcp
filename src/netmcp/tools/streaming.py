"""PCAP streaming analysis tools for large files."""

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_streaming_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register streaming analysis MCP tools for large PCAP files."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Analyze Large PCAP",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def analyze_large_pcap(
        filepath: str,
        chunk_size: int = 10000,
        display_filter: str = "",
        ctx: Context | None = None,
    ) -> dict:
        """Analyze a large PCAP file in chunks for memory efficiency.

        Processes packets in batches, accumulating statistics.

        Args:
            filepath: Path to PCAP/PCAPNG file
            chunk_size: Number of packets per processing chunk
            display_filter: Optional Wireshark display filter
            ctx: Optional MCP context for progress reporting
        """
        try:
            validated = sec.sanitize_filepath(filepath)
            if display_filter:
                sec.validate_display_filter(display_filter)

            total_packets = 0
            protocols: dict[str, int] = {}
            ips_src: dict[str, int] = {}
            ips_dst: dict[str, int] = {}
            offset = 0
            chunk_index = 0

            while True:
                chunk_filter = (
                    f"frame.number >= {offset + 1} and frame.number <= {offset + chunk_size}"
                )
                if display_filter:
                    chunk_filter = f"{chunk_filter} and {display_filter}"

                if ctx:
                    await ctx.report_progress(chunk_index, chunk_index + 1)

                packets = await tshark.read_pcap(
                    str(validated),
                    max_packets=chunk_size,
                    display_filter=chunk_filter,
                )

                if not packets:
                    break

                for pkt in packets:
                    layers = pkt.get("_source", {}).get("layers", {})
                    # Count protocols
                    if "frame.protocols" in layers:
                        p = layers["frame.protocols"]
                        p = p[0] if isinstance(p, list) else p
                        for proto in p.split(":"):
                            protocols[proto] = protocols.get(proto, 0) + 1
                    # Count IPs
                    for field, counter in [("ip.src", ips_src), ("ip.dst", ips_dst)]:
                        if field in layers:
                            v = layers[field]
                            v = v[0] if isinstance(v, list) else v
                            counter[v] = counter.get(v, 0) + 1

                total_packets += len(packets)
                offset += chunk_size
                chunk_index += 1

                if len(packets) < chunk_size:
                    break

            if ctx:
                await ctx.report_progress(chunk_index, chunk_index)

            top_protos = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:20]
            top_src = sorted(ips_src.items(), key=lambda x: x[1], reverse=True)[:20]
            top_dst = sorted(ips_dst.items(), key=lambda x: x[1], reverse=True)[:20]

            return fmt.format_success(
                {
                    "total_packets": total_packets,
                    "chunks_processed": (offset // chunk_size) + (1 if offset % chunk_size else 0),
                    "top_protocols": [{"protocol": p, "count": c} for p, c in top_protos],
                    "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_src],
                    "top_dest_ips": [{"ip": ip, "count": c} for ip, c in top_dst],
                },
                title="Large PCAP Analysis",
            )
        except Exception as e:
            return fmt.format_error(e)
