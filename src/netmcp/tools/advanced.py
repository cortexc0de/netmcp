"""Advanced tshark analysis tools (object extraction, I/O stats, conversations)."""

import asyncio
import os
import shutil
import tempfile

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface

_EXPORT_PROTOCOLS = {"http", "smb", "dicom", "imf", "tftp"}
_CONV_TYPES = {"eth", "ip", "ipv6", "tcp", "udp"}


def register_advanced_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register advanced tshark analysis MCP tools."""

    # ── extract_objects ──────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Extract Objects",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def extract_objects(
        file_path: str,
        protocol: str = "http",
        output_dir: str = "",
    ) -> dict:
        """
        Extract files from HTTP/SMB/DICOM/IMF/TFTP streams using tshark.

        Args:
            file_path: Path to PCAP/PCAPNG file
            protocol: Protocol to extract objects from (http, smb, dicom, imf, tftp)
            output_dir: Directory to write extracted files (created if empty)
        """
        try:
            if not sec.check_rate_limit("extract_objects"):
                raise ValueError("Rate limit exceeded for extract_objects")

            validated_path = sec.sanitize_filepath(file_path)

            if protocol not in _EXPORT_PROTOCOLS:
                raise ValueError(
                    f"Invalid protocol: {protocol!r}. "
                    f"Allowed: {', '.join(sorted(_EXPORT_PROTOCOLS))}"
                )

            if output_dir:
                out_path = os.path.abspath(output_dir)
                if ".." in output_dir.split(os.sep):
                    raise ValueError(f"Path traversal not allowed: {output_dir!r}")
                os.makedirs(out_path, exist_ok=True)
            else:
                out_path = tempfile.mkdtemp(prefix="netmcp_export_")

            tshark_bin = shutil.which("tshark")
            if not tshark_bin:
                raise FileNotFoundError("tshark not found on PATH")

            cmd = [
                tshark_bin,
                "-r", str(validated_path),
                "--export-objects", f"{protocol},{out_path}",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)

            if proc.returncode != 0:
                raise RuntimeError(
                    f"tshark export-objects failed (rc={proc.returncode}): "
                    f"{stderr.decode().strip()}"
                )

            extracted_files = []
            for entry in os.listdir(out_path):
                full = os.path.join(out_path, entry)
                if os.path.isfile(full):
                    extracted_files.append({
                        "filename": entry,
                        "size_bytes": os.path.getsize(full),
                    })

            sec.audit_log("extract_objects", {
                "filepath": str(validated_path),
                "protocol": protocol,
                "output_dir": out_path,
                "files_extracted": len(extracted_files),
            })

            result = {
                "filepath": str(validated_path),
                "protocol": protocol,
                "output_dir": out_path,
                "files_extracted": len(extracted_files),
                "files": extracted_files,
            }
            return fmt.truncate_output(fmt.format_success(result, title="Object Extraction"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    # ── get_io_statistics ────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get IO Statistics",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def get_io_statistics(
        file_path: str,
        interval: str = "1",
        display_filter: str = "",
    ) -> dict:
        """
        Time-binned I/O statistics from a PCAP file.

        Args:
            file_path: Path to PCAP/PCAPNG file
            interval: Time interval in seconds for binning (positive number)
            display_filter: Optional Wireshark display filter
        """
        try:
            if not sec.check_rate_limit("get_io_statistics"):
                raise ValueError("Rate limit exceeded for get_io_statistics")

            validated_path = sec.sanitize_filepath(file_path)

            try:
                interval_val = float(interval)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid interval: {interval!r}. Must be a positive number.") from None

            if interval_val <= 0:
                raise ValueError(f"Invalid interval: {interval!r}. Must be a positive number.")

            if display_filter:
                sec.validate_display_filter(display_filter)

            stat_arg = f"io,stat,{interval}"
            if display_filter:
                stat_arg = f"io,stat,{interval},{display_filter}"

            result = await tshark._run(
                ["-r", str(validated_path), "-z", stat_arg, "-q"],
                timeout=60.0,
            )

            if result.returncode != 0:
                raise RuntimeError(f"tshark io,stat failed: {result.stderr}")

            lines = result.stdout.strip().splitlines()
            intervals = []
            for line in lines:
                line = line.strip()
                if line.startswith("|") and "<>" in line:
                    parts = line.strip("|").split("|")
                    if len(parts) >= 2:
                        time_part = parts[0].strip()
                        count_part = parts[1].strip()
                        intervals.append({
                            "time_range": time_part,
                            "frames": count_part,
                        })

            sec.audit_log("get_io_statistics", {
                "filepath": str(validated_path),
                "interval": interval,
                "display_filter": display_filter or "(none)",
            })

            output = {
                "filepath": str(validated_path),
                "interval": interval,
                "display_filter": display_filter or "(none)",
                "intervals": intervals,
                "raw_output": result.stdout,
            }
            return fmt.truncate_output(fmt.format_success(output, title="I/O Statistics"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    # ── get_conversation_stats ───────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get Conversation Stats",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def get_conversation_stats(
        file_path: str,
        conv_type: str = "ip",
        display_filter: str = "",
    ) -> dict:
        """
        IP/TCP/UDP/Ethernet conversation statistics from a PCAP file.

        Args:
            file_path: Path to PCAP/PCAPNG file
            conv_type: Conversation type (eth, ip, ipv6, tcp, udp)
            display_filter: Optional Wireshark display filter
        """
        try:
            if not sec.check_rate_limit("get_conversation_stats"):
                raise ValueError("Rate limit exceeded for get_conversation_stats")

            validated_path = sec.sanitize_filepath(file_path)

            if conv_type not in _CONV_TYPES:
                raise ValueError(
                    f"Invalid conv_type: {conv_type!r}. "
                    f"Allowed: {', '.join(sorted(_CONV_TYPES))}"
                )

            if display_filter:
                sec.validate_display_filter(display_filter)

            conv_arg = f"conv,{conv_type}"
            if display_filter:
                conv_arg = f"conv,{conv_type},{display_filter}"

            result = await tshark._run(
                ["-r", str(validated_path), "-z", conv_arg, "-q"],
                timeout=60.0,
            )

            if result.returncode != 0:
                raise RuntimeError(f"tshark conv failed: {result.stderr}")

            lines = result.stdout.strip().splitlines()
            conversations = []
            header_found = False
            for line in lines:
                if not header_found:
                    if line.strip().startswith("Filter:") or line.strip().startswith("|"):
                        continue
                    # Look for header separator line with dashes
                    if "=" * 5 in line or "-" * 5 in line:
                        header_found = True
                        continue
                    # Also detect data lines by checking structure
                    parts = line.split()
                    if len(parts) >= 5 and "<->" in line:
                        header_found = True
                    else:
                        continue

                line = line.strip()
                if not line or line.startswith("="):
                    continue
                if "<->" in line:
                    parts = line.split()
                    try:
                        arrow_idx = parts.index("<->")
                        addr_a = parts[arrow_idx - 1] if arrow_idx > 0 else ""
                        addr_b = parts[arrow_idx + 1] if arrow_idx + 1 < len(parts) else ""
                        remaining = parts[arrow_idx + 2:]
                        conversations.append({
                            "address_a": addr_a,
                            "address_b": addr_b,
                            "details": " ".join(remaining),
                        })
                    except (ValueError, IndexError):
                        continue

            sec.audit_log("get_conversation_stats", {
                "filepath": str(validated_path),
                "conv_type": conv_type,
                "display_filter": display_filter or "(none)",
            })

            output = {
                "filepath": str(validated_path),
                "conv_type": conv_type,
                "display_filter": display_filter or "(none)",
                "conversation_count": len(conversations),
                "conversations": conversations,
                "raw_output": result.stdout,
            }
            return fmt.truncate_output(
                fmt.format_success(output, title="Conversation Statistics")
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")
