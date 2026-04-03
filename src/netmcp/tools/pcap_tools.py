"""PCAP manipulation tools (diff, merge, slice, decode)."""

import asyncio
import shutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface

_ALLOWED_OUTPUT_EXTENSIONS = {".pcap", ".pcapng"}


def _validate_output_path(output_file: str) -> Path:
    """Validate and resolve an output file path.

    Raises ValueError on traversal attempts or disallowed extensions.
    """
    p = Path(output_file)
    if ".." in p.parts:
        raise ValueError(f"Path traversal not allowed in output: {output_file!r}")

    try:
        resolved = p.resolve(strict=False)
    except (OSError, ValueError):
        raise ValueError(f"Invalid output path: {output_file!r}") from None

    if resolved.suffix.lower() not in _ALLOWED_OUTPUT_EXTENSIONS:
        raise ValueError(
            f"Invalid output extension: {resolved.suffix!r}. "
            f"Allowed: {', '.join(sorted(_ALLOWED_OUTPUT_EXTENSIONS))}"
        )
    return resolved


def _extract_ips(packets: list[dict]) -> set[str]:
    """Extract unique IP addresses from tshark JSON packets."""
    ips: set[str] = set()
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        for ip_field in ("ip.src", "ip.dst"):
            if ip_field in layers:
                val = layers[ip_field]
                ips.add(val[0] if isinstance(val, list) else val)
    return ips


def register_pcap_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register PCAP manipulation MCP tools."""

    # ── diff_pcap_files ─────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Diff Pcap Files",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def diff_pcap_files(
        filepath1: str,
        filepath2: str,
        display_filter: str = "",
    ) -> dict:
        """
        Compare two PCAP files and report differences.

        Args:
            filepath1: Path to first PCAP file
            filepath2: Path to second PCAP file
            display_filter: Optional Wireshark display filter applied to both
        """
        try:
            path1 = sec.sanitize_filepath(filepath1)
            path2 = sec.sanitize_filepath(filepath2)
            if display_filter:
                sec.validate_display_filter(display_filter)

            packets1 = await tshark.read_pcap(str(path1), display_filter)
            packets2 = await tshark.read_pcap(str(path2), display_filter)

            stats1 = await tshark.protocol_stats(str(path1))
            stats2 = await tshark.protocol_stats(str(path2))

            ips1 = _extract_ips(packets1)
            ips2 = _extract_ips(packets2)

            # Protocol distribution differences
            all_protos = set(stats1.keys()) | set(stats2.keys())
            protocol_diff = {}
            for proto in sorted(all_protos):
                f1 = stats1.get(proto, {}).get("frames", 0)
                f2 = stats2.get(proto, {}).get("frames", 0)
                if f1 != f2:
                    protocol_diff[proto] = {"file1_frames": f1, "file2_frames": f2}

            result = {
                "file1_packets": len(packets1),
                "file2_packets": len(packets2),
                "only_in_file1_ips": sorted(ips1 - ips2),
                "only_in_file2_ips": sorted(ips2 - ips1),
                "protocol_diff": protocol_diff,
                "summary": (
                    f"File1: {len(packets1)} packets, File2: {len(packets2)} packets. "
                    f"{len(ips1 - ips2)} IPs only in file1, "
                    f"{len(ips2 - ips1)} IPs only in file2, "
                    f"{len(protocol_diff)} protocol differences."
                ),
            }
            return fmt.truncate_output(fmt.format_success(result, title="PCAP Diff"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    # ── merge_pcap_files ────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Merge Pcap Files",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def merge_pcap_files(
        filepaths: list[str],
        output_file: str,
        chronological: bool = True,
    ) -> dict:
        """
        Merge multiple PCAP files into one using mergecap.

        Args:
            filepaths: List of PCAP file paths to merge
            output_file: Output file path (.pcap or .pcapng)
            chronological: Merge by timestamp (True) or append in order (False)
        """
        try:
            if not filepaths:
                raise ValueError("At least one input file is required")

            validated_paths = [str(sec.sanitize_filepath(fp)) for fp in filepaths]
            output_path = _validate_output_path(output_file)

            mergecap_bin = shutil.which("mergecap")
            if not mergecap_bin:
                raise FileNotFoundError(
                    "mergecap not found. Install Wireshark to get mergecap."
                )

            cmd = [mergecap_bin, "-w", str(output_path)]
            if not chronological:
                cmd.append("-a")
            cmd.extend(validated_paths)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)

            if proc.returncode != 0:
                raise RuntimeError(
                    f"mergecap failed (rc={proc.returncode}): {stderr.decode().strip()}"
                )

            result = {
                "output_file": str(output_path),
                "files_merged": len(validated_paths),
                "file_size_bytes": output_path.stat().st_size,
            }
            return fmt.format_success(result, title="PCAP Merge")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    # ── slice_pcap ──────────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Slice Pcap",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def slice_pcap(
        filepath: str,
        output_file: str,
        start_packet: int = 0,
        end_packet: int = 0,
        start_time: str = "",
        end_time: str = "",
        remove_duplicates: bool = False,
    ) -> dict:
        """
        Slice or filter a PCAP file using editcap.

        Args:
            filepath: Path to input PCAP file
            output_file: Output file path (.pcap or .pcapng)
            start_packet: First packet number to keep (1-based)
            end_packet: Last packet number to keep
            start_time: Keep packets after this time (editcap -A format)
            end_time: Keep packets before this time (editcap -B format)
            remove_duplicates: Remove duplicate packets
        """
        try:
            validated_input = str(sec.sanitize_filepath(filepath))
            output_path = _validate_output_path(output_file)

            editcap_bin = shutil.which("editcap")
            if not editcap_bin:
                raise FileNotFoundError(
                    "editcap not found. Install Wireshark to get editcap."
                )

            cmd = [editcap_bin]

            if start_packet and end_packet:
                cmd.extend(["-r", f"{start_packet}-{end_packet}"])
            if start_time:
                cmd.extend(["-A", start_time])
            if end_time:
                cmd.extend(["-B", end_time])
            if remove_duplicates:
                cmd.append("-d")

            cmd.extend([validated_input, str(output_path)])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)

            if proc.returncode != 0:
                raise RuntimeError(
                    f"editcap failed (rc={proc.returncode}): {stderr.decode().strip()}"
                )

            operations = []
            if start_packet and end_packet:
                operations.append(f"packets {start_packet}-{end_packet}")
            if start_time:
                operations.append(f"after {start_time}")
            if end_time:
                operations.append(f"before {end_time}")
            if remove_duplicates:
                operations.append("dedup")

            result = {
                "input_file": validated_input,
                "output_file": str(output_path),
                "operation": ", ".join(operations) if operations else "copy",
                "file_size_bytes": output_path.stat().st_size,
            }
            return fmt.format_success(result, title="PCAP Slice")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    # ── decode_packet ───────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Decode Packet",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def decode_packet(
        filepath: str,
        packet_number: int,
        verbose: bool = True,
    ) -> dict:
        """
        Decode a single packet in full detail.

        Args:
            filepath: Path to PCAP file
            packet_number: Packet number to decode (1-based)
            verbose: If True, return verbose text decode; if False, return JSON layers
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            if packet_number < 1:
                raise ValueError("packet_number must be greater than 0")

            frame_filter = f"frame.number == {packet_number}"

            if verbose:
                result = await tshark._run(
                    ["-r", str(validated_path), "-Y", frame_filter, "-V"],
                    timeout=30.0,
                )
            else:
                result = await tshark._run(
                    ["-r", str(validated_path), "-Y", frame_filter, "-T", "json"],
                    timeout=30.0,
                )

            if result.returncode != 0:
                raise RuntimeError(f"tshark decode failed: {result.stderr}")

            if not result.stdout.strip():
                raise ValueError(
                    f"Packet {packet_number} not found in {validated_path}"
                )

            layers: list[str] = []
            raw_output = result.stdout

            if verbose:
                # Extract layer names from verbose output section headers
                for line in result.stdout.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("0x") and ":" not in stripped:
                        continue
                    # Layer headers look like "Frame 1: ..." or "Internet Protocol Version 4, ..."
                for line in result.stdout.splitlines():
                    if line and not line.startswith(" ") and not line.startswith("\t"):
                        layers.append(line.strip())
            else:
                import json

                try:
                    parsed = json.loads(result.stdout)
                    if isinstance(parsed, list) and parsed:
                        pkt_layers = parsed[0].get("_source", {}).get("layers", {})
                        layers = list(pkt_layers.keys())
                        raw_output = json.dumps(parsed, indent=2)
                except json.JSONDecodeError:
                    pass

            data = {
                "filepath": str(validated_path),
                "packet_number": packet_number,
                "layers": layers,
                "raw_output": raw_output,
            }
            return fmt.truncate_output(fmt.format_success(data, title="Packet Decode"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")
