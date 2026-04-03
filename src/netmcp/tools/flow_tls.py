"""Flow visualization and TLS decryption tools."""

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface

# Allowed output formats for flow visualization
_FLOW_OUTPUT_FORMATS = {"text", "mermaid"}
_FLOW_TYPES = {"tcp", "udp"}
_MAX_FLOWS_LIMIT = 200
_PCAPNG_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def _build_flow_diagram_text(flows: list[dict]) -> str:
    """Build an ASCII art flow diagram from parsed packet data.

    Args:
        flows: List of packet dicts with src, dst, and summary info.

    Returns:
        ASCII art string showing directional arrows between endpoints.
    """
    if not flows:
        return "(no flows to display)"

    # Identify unique endpoints (ordered by first appearance)
    endpoints: list[str] = []
    for f in flows:
        for ep in (f["src"], f["dst"]):
            if ep not in endpoints:
                endpoints.append(ep)

    if len(endpoints) < 2:
        endpoints.append("(unknown)")

    ep_a, ep_b = endpoints[0], endpoints[1]

    # Header boxes
    max_label = max(len(ep_a), len(ep_b), 12)
    box_w = max_label + 4
    pad_a = (box_w - len(ep_a)) // 2
    pad_b = (box_w - len(ep_b)) // 2

    lines = []
    top = "┌" + "─" * (box_w) + "┐"
    mid_a = "│" + " " * pad_a + ep_a + " " * (box_w - pad_a - len(ep_a)) + "│"
    mid_b = "│" + " " * pad_b + ep_b + " " * (box_w - pad_b - len(ep_b)) + "│"
    bot_l = "└" + "─" * ((box_w - 1) // 2) + "┬" + "─" * (box_w - 1 - (box_w - 1) // 2) + "┘"
    bot_r = "└" + "─" * ((box_w - 1) // 2) + "┬" + "─" * (box_w - 1 - (box_w - 1) // 2) + "┘"

    gap = 20
    lines.append(top + " " * gap + top)
    lines.append(mid_a + " " * gap + mid_b)
    lines.append(bot_l + " " * gap + bot_r)

    col_a = box_w // 2
    col_b = box_w + gap + box_w // 2
    arrow_len = col_b - col_a - 1

    for f in flows:
        label = f.get("summary", "")
        if f["src"] == ep_a:
            arrow = (
                " " * col_a
                + "│"
                + "── "
                + label
                + " "
                + "─" * max(1, arrow_len - len(label) - 5)
                + ">│"
            )
        else:
            arrow = (
                " " * col_a
                + "│<"
                + "─" * max(1, arrow_len - len(label) - 5)
                + " "
                + label
                + " ──"
                + "│"
            )
        lines.append(arrow)

    return "\n".join(lines)


def _build_flow_diagram_mermaid(flows: list[dict]) -> str:
    """Build a Mermaid sequence diagram from parsed packet data.

    Args:
        flows: List of packet dicts with src, dst, and summary info.

    Returns:
        Mermaid sequenceDiagram string.
    """
    if not flows:
        return "sequenceDiagram\n    Note over A: No flows found"

    endpoints: list[str] = []
    for f in flows:
        for ep in (f["src"], f["dst"]):
            if ep not in endpoints:
                endpoints.append(ep)

    lines = ["sequenceDiagram"]
    alias_map: dict[str, str] = {}
    for i, ep in enumerate(endpoints):
        alias = chr(ord("A") + i) if i < 26 else f"P{i}"
        alias_map[ep] = alias
        lines.append(f"    participant {alias} as {ep}")

    for f in flows:
        src_alias = alias_map.get(f["src"], "A")
        dst_alias = alias_map.get(f["dst"], "B")
        label = f.get("summary", "data")
        lines.append(f"    {src_alias}->>{dst_alias}: {label}")

    return "\n".join(lines)


def _parse_packet_rows(rows: list[dict]) -> list[dict]:
    """Parse tshark field-export rows into flow entries.

    Each row is expected to have ip.src, ip.dst, tcp/udp ports,
    tcp.flags.str, http fields, etc.
    """
    flows: list[dict] = []
    for row in rows:
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        src_port = row.get("tcp.srcport", "") or row.get("udp.srcport", "")
        dst_port = row.get("tcp.dstport", "") or row.get("udp.dstport", "")
        flags = row.get("tcp.flags.str", "")
        method = row.get("http.request.method", "")
        uri = row.get("http.request.uri", "")
        resp_code = row.get("http.response.code", "")
        frame_len = row.get("frame.len", "")

        if not src_ip or not dst_ip:
            continue

        src = f"{src_ip}:{src_port}" if src_port else src_ip
        dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

        # Build summary
        if method and uri:
            summary = f"HTTP {method} {uri}"
        elif resp_code:
            size_info = f" ({frame_len} bytes)" if frame_len else ""
            summary = f"HTTP {resp_code}{size_info}"
        elif flags:
            flag_parts = []
            clean = flags.replace("·", "").replace(".", "").strip()
            flag_map = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH"}
            for ch in clean:
                if ch in flag_map:
                    flag_parts.append(flag_map[ch])
            summary = "TCP " + ",".join(flag_parts) if flag_parts else f"TCP [{flags.strip()}]"
        else:
            summary = f"data ({frame_len} bytes)" if frame_len else "data"

        flows.append(
            {
                "src": src,
                "dst": dst,
                "summary": summary,
                "frame_len": int(frame_len) if frame_len and frame_len.isdigit() else 0,
            }
        )

    return flows


def _summarize_conversations(flows: list[dict]) -> list[dict]:
    """Group flows by (src, dst) pairs and compute summary stats."""
    conv: dict[tuple[str, str], dict] = {}
    for f in flows:
        key_fwd = (f["src"], f["dst"])
        key_rev = (f["dst"], f["src"])
        key = key_fwd if key_fwd in conv else key_rev if key_rev in conv else key_fwd
        if key not in conv:
            conv[key] = {"src": key[0], "dst": key[1], "packets": 0, "bytes": 0}
        conv[key]["packets"] += 1
        conv[key]["bytes"] += f.get("frame_len", 0)
    return list(conv.values())


def register_flow_tls_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register flow visualization and TLS decryption MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Visualize Network Flows",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def visualize_network_flows(
        filepath: str,
        flow_type: str = "tcp",
        max_flows: int = 20,
        output_format: str = "text",
    ) -> dict:
        """
        Generate visual diagrams of network flows from a PCAP file.

        Produces ASCII art or Mermaid sequence diagrams showing packet
        exchanges between endpoints.

        Args:
            filepath: Path to PCAP/PCAPNG file
            flow_type: Protocol type: tcp or udp
            max_flows: Maximum number of packet arrows to include (1-200)
            output_format: Diagram format: text or mermaid
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)

            if flow_type not in _FLOW_TYPES:
                raise ValueError(
                    f"Invalid flow_type: {flow_type!r}. Allowed: {', '.join(sorted(_FLOW_TYPES))}"
                )
            if output_format not in _FLOW_OUTPUT_FORMATS:
                raise ValueError(
                    f"Invalid output_format: {output_format!r}. "
                    f"Allowed: {', '.join(sorted(_FLOW_OUTPUT_FORMATS))}"
                )
            max_flows = max(1, min(max_flows, _MAX_FLOWS_LIMIT))

            sec.audit_log(
                "visualize_network_flows",
                {
                    "filepath": str(validated_path),
                    "flow_type": flow_type,
                    "output_format": output_format,
                },
            )

            # Extract packet-level data for the diagram
            fields = [
                "ip.src",
                "ip.dst",
                "tcp.srcport",
                "tcp.dstport",
                "udp.srcport",
                "udp.dstport",
                "tcp.flags.str",
                "http.request.method",
                "http.request.uri",
                "http.response.code",
                "frame.number",
                "frame.len",
            ]
            display_filter = flow_type

            rows = await tshark.export_fields(
                str(validated_path),
                fields,
                display_filter=display_filter,
            )

            parsed = _parse_packet_rows(rows)
            # Limit to max_flows entries for the diagram
            diagram_flows = parsed[:max_flows]
            conversations = _summarize_conversations(parsed)

            if output_format == "mermaid":
                diagram = _build_flow_diagram_mermaid(diagram_flows)
            else:
                diagram = _build_flow_diagram_text(diagram_flows)

            result = {
                "filepath": str(validated_path),
                "flow_type": flow_type,
                "flow_count": len(conversations),
                "diagram": diagram,
                "flows": conversations,
            }
            return fmt.format_success(result, title="Network Flow Visualization")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004" if isinstance(e, ValueError) else "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Decrypt TLS Traffic",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def decrypt_tls_traffic(
        filepath: str,
        keylog_file: str = "",
        output_file: str = "",
    ) -> dict:
        """
        Decrypt TLS/HTTPS traffic using an SSLKEYLOGFILE.

        Requires a TLS key log file (NSS Key Log Format) captured alongside
        the traffic. Set SSLKEYLOGFILE env var or pass keylog_file explicitly.

        Args:
            filepath: Path to PCAP/PCAPNG file containing TLS traffic
            keylog_file: Path to TLS key log file (NSS format)
            output_file: Optional path to write decrypted pcapng
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)

            # Resolve keylog file
            keylog_path = keylog_file or os.environ.get("SSLKEYLOGFILE", "")
            if not keylog_path:
                raise ValueError(
                    "No TLS key log file provided. Either pass keylog_file or set the "
                    "SSLKEYLOGFILE environment variable.\n"
                    "To capture TLS keys, run your browser/client with:\n"
                    "  export SSLKEYLOGFILE=/path/to/keylog.txt\n"
                    "Then replay or capture traffic."
                )

            # Validate keylog file path
            keylog_resolved = Path(keylog_path).resolve()
            if ".." in str(Path(keylog_path)).split(os.sep):
                raise ValueError(f"Path traversal not allowed: {keylog_path!r}")
            if not keylog_resolved.exists():
                raise ValueError(f"Key log file does not exist: {keylog_resolved}")
            if not keylog_resolved.is_file():
                raise ValueError(f"Key log path is not a file: {keylog_resolved}")

            # Validate output file if provided
            validated_output = ""
            if output_file:
                out_path = Path(output_file).resolve()
                if ".." in str(Path(output_file)).split(os.sep):
                    raise ValueError(f"Path traversal not allowed: {output_file!r}")
                if out_path.suffix.lower() not in _PCAPNG_EXTENSIONS:
                    raise ValueError(
                        f"Invalid output extension: {out_path.suffix!r}. "
                        f"Allowed: {', '.join(sorted(_PCAPNG_EXTENSIONS))}"
                    )
                validated_output = str(out_path)

            sec.audit_log(
                "decrypt_tls_traffic",
                {
                    "filepath": str(validated_path),
                    "keylog_file": str(keylog_resolved),
                    "output_file": validated_output or "(none)",
                },
            )

            # Decrypt and extract HTTP layer
            tls_option = f"tls.keylog_file:{keylog_resolved}"
            result = await tshark._run(
                [
                    "-r",
                    str(validated_path),
                    "-o",
                    tls_option,
                    "-T",
                    "fields",
                    "-e",
                    "http.request.method",
                    "-e",
                    "http.host",
                    "-e",
                    "http.request.uri",
                    "-e",
                    "http.response.code",
                    "-e",
                    "http.content_type",
                    "-e",
                    "frame.number",
                    "-Y",
                    "http",
                ],
                timeout=60.0,
            )

            # Parse decrypted HTTP data
            http_requests: list[dict] = []
            http_responses: list[dict] = []
            field_names = [
                "http.request.method",
                "http.host",
                "http.request.uri",
                "http.response.code",
                "http.content_type",
                "frame.number",
            ]

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                values = line.split("\t")
                row = dict(zip(field_names, values, strict=False))
                method = row.get("http.request.method", "")
                resp_code = row.get("http.response.code", "")
                if method:
                    http_requests.append(
                        {
                            "method": method,
                            "host": row.get("http.host", ""),
                            "uri": row.get("http.request.uri", ""),
                            "frame": row.get("frame.number", ""),
                        }
                    )
                if resp_code:
                    http_responses.append(
                        {
                            "code": resp_code,
                            "content_type": row.get("http.content_type", ""),
                            "frame": row.get("frame.number", ""),
                        }
                    )

            decrypted_packets = len(http_requests) + len(http_responses)

            # Optionally write decrypted pcapng
            if validated_output:
                write_result = await tshark._run(
                    [
                        "-r",
                        str(validated_path),
                        "-o",
                        tls_option,
                        "-w",
                        validated_output,
                        "-F",
                        "pcapng",
                    ],
                    timeout=60.0,
                )
                if write_result.returncode != 0:
                    raise RuntimeError(f"Failed to write decrypted capture: {write_result.stderr}")

            output = {
                "filepath": str(validated_path),
                "keylog_file": str(keylog_resolved),
                "decrypted_packets": decrypted_packets,
                "http_requests": http_requests,
                "http_responses": http_responses,
            }
            if validated_output:
                output["output_file"] = validated_output

            return fmt.truncate_output(fmt.format_success(output, title="TLS Decryption Results"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004" if isinstance(e, ValueError) else "NETMCP_003")
