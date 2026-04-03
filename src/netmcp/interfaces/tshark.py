"""TShark CLI interface for packet capture and analysis."""

import asyncio
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class TsharkNotFoundError(Exception):
    """Raised when tshark binary cannot be found."""


@dataclass
class TsharkResult:
    """Result from a tshark operation."""
    returncode: int
    stdout: str
    stderr: str
    data: Any = None


# Default fields for JSON export
_DEFAULT_FIELDS = [
    "frame.number",
    "frame.time",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "http.request.method",
    "http.response.code",
    "http.host",
    "http.request.uri",
    "frame.protocols",
    "frame.len",
]

# Fallback tshark paths by platform
_FALLBACK_PATHS = {
    "darwin": [
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
    ],
    "linux": [
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/bin/tshark",
    ],
    "win32": [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ],
}


def find_tshark() -> str:
    """Find tshark binary on the system."""
    # Try PATH first
    path = shutil.which("tshark")
    if path:
        return path

    # Try fallback paths
    import platform
    system = platform.system().lower()
    fallbacks = _FALLBACK_PATHS.get(system, [])

    for fallback in fallbacks:
        if Path(fallback).exists():
            return fallback

    raise TsharkNotFoundError(
        "tshark not found. Please install Wireshark and ensure tshark is in your PATH.\n"
        "  Ubuntu/Debian: sudo apt install tshark\n"
        "  macOS: brew install wireshark\n"
        "  Windows: https://www.wireshark.org/download.html"
    )


class TsharkInterface:
    """Wraps tshark CLI for packet capture and analysis.

    All subprocess calls use shell=False with list-based arguments.
    """

    def __init__(self, tshark_path: str | None = None) -> None:
        self.tshark_path = tshark_path or find_tshark()
        self._version: str | None = None

    def __repr__(self) -> str:
        return f"TsharkInterface(path={self.tshark_path!r})"

    # ── Internal helpers ────────────────────────────────────────────────

    async def _run(
        self,
        args: list[str],
        timeout: float = 30.0,
        capture_output: bool = True,
    ) -> TsharkResult:
        """Run tshark with given arguments asynchronously."""
        cmd = [self.tshark_path, *args]

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd,
                        capture_output=capture_output,
                        text=True,
                        timeout=timeout,
                        shell=False,  # Security: never use shell
                    ),
                ),
                timeout=timeout + 5,  # Extra buffer for asyncio
            )
            return TsharkResult(
                returncode=result.returncode,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
            )
        except subprocess.TimeoutExpired as e:
            raise TimeoutError(f"TShark command timed out after {timeout}s: {e}")
        except FileNotFoundError as e:
            raise TsharkNotFoundError(f"TShark binary not found at {self.tshark_path}: {e}")

    # ── Network interfaces ──────────────────────────────────────────────

    async def list_interfaces(self) -> list[str]:
        """List available network interfaces."""
        result = await self._run(["-D"], timeout=10.0)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, "tshark -D", stderr=result.stderr)

        interfaces = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Remove number prefix: "1. eth0" -> "eth0"
            if ". " in line:
                line = line.split(". ", 1)[1]
            # Extract device name
            if " (" in line:
                line = line.split(" (", 1)[0]
            interfaces.append(line.strip())
        return interfaces

    # ── Live capture ────────────────────────────────────────────────────

    async def capture_live(
        self,
        interface: str,
        bpf_filter: str = "",
        packet_count: int = 100,
        timeout: float = 30.0,
        output_file: str | None = None,
    ) -> Path:
        """Capture live packets from a network interface.

        Args:
            interface: Network interface name
            bpf_filter: BPF capture filter
            packet_count: Max packets to capture
            timeout: Max capture time in seconds
            output_file: Save to pcap file (optional)

        Returns:
            Path to the capture file
        """
        import os
        import tempfile

        if output_file:
            out_path = Path(output_file)
        else:
            fd, out_path = tempfile.mkstemp(suffix=".pcap")
            os.close(fd)
            out_path = Path(out_path)

        args = ["-i", interface, "-w", str(out_path)]

        if bpf_filter:
            args.extend(["-f", bpf_filter])
        if packet_count:
            args.extend(["-c", str(packet_count)])

        # Use -a duration for timeout
        args.extend(["-a", f"duration:{timeout}"])

        result = await self._run(args, timeout=timeout + 10)
        if result.returncode != 0 and not out_path.exists():
            raise subprocess.CalledProcessError(
                result.returncode, "tshark capture", stderr=result.stderr
            )

        return out_path

    # ── Read PCAP ───────────────────────────────────────────────────────

    async def read_pcap(
        self,
        filepath: str,
        display_filter: str = "",
        max_packets: int = 10000,
    ) -> list[dict]:
        """Read and parse packets from a PCAP file.

        Args:
            filepath: Path to PCAP file
            display_filter: Wireshark display filter
            max_packets: Max packets to read

        Returns:
            List of packet dicts
        """
        args = ["-r", filepath, "-T", "json"]

        if display_filter:
            args.extend(["-Y", display_filter])
        if max_packets:
            args.extend(["-c", str(max_packets)])

        # Export key fields for structured output
        for f in _DEFAULT_FIELDS:
            args.extend(["-e", f])

        result = await self._run(args, timeout=60.0)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, "tshark read", stderr=result.stderr
            )

        try:
            packets = json.loads(result.stdout)
            return packets if isinstance(packets, list) else []
        except json.JSONDecodeError:
            return []

    # ── Protocol statistics ─────────────────────────────────────────────

    async def protocol_stats(self, filepath: str) -> dict[str, dict]:
        """Get protocol hierarchy statistics from a PCAP file.

        Returns:
            Dict with protocol names as keys and stats as values.
        """
        result = await self._run(
            ["-r", filepath, "-q", "-z", "io,phs"],
            timeout=30.0,
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, "tshark stats", stderr=result.stderr
            )

        # Parse the text output into structured data
        return self._parse_protocol_stats(result.stdout)

    @staticmethod
    def _parse_protocol_stats(text: str) -> dict[str, dict]:
        """Parse tshark -z io,phs output into a dict."""
        stats = {}
        for line in text.split("\n"):
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("Filter"):
                continue

            # Match lines like: "eth                                    frames:100 bytes:12000"
            match = re.match(
                r"^(\S+)\s+frames:(\d+)\s+bytes:(\d+(?:\.\d+\s*\w+)?)",
                line,
            )
            if match:
                proto, frames, bytes_str = match.groups()
                # Parse bytes (handle "12000", "12.5 kB", etc.)
                try:
                    bytes_val = int(bytes_str.split()[0])
                except (ValueError, IndexError):
                    bytes_val = 0

                stats[proto] = {
                    "frames": int(frames),
                    "bytes": bytes_val,
                }
        return stats

    # ── Stream following ────────────────────────────────────────────────

    async def follow_stream(
        self,
        filepath: str,
        stream_idx: int,
        proto: str = "tcp",
        fmt: str = "ascii",
    ) -> str:
        """Follow a TCP/UDP stream.

        Args:
            filepath: Path to PCAP file
            stream_idx: Stream index to follow
            proto: Protocol (tcp, udp)
            fmt: Output format (ascii, hex, raw)

        Returns:
            Stream content as string
        """
        result = await self._run(
            [
                "-r", filepath,
                "-q",
                "-z", f"follow,{proto},{fmt},{stream_idx}",
            ],
            timeout=30.0,
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, "tshark follow stream", stderr=result.stderr
            )
        return result.stdout.strip()

    # ── List streams ────────────────────────────────────────────────────

    async def list_streams(
        self,
        filepath: str,
        proto: str = "tcp",
    ) -> list[dict]:
        """List all conversations of a given protocol.

        Returns:
            List of stream/conversation dicts
        """
        result = await self._run(
            ["-r", filepath, "-q", "-z", f"conv,{proto}"],
            timeout=30.0,
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, f"tshark conv {proto}", stderr=result.stderr
            )

        # Parse conversation table
        streams = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if "<->" in line:
                # Parse: "192.168.1.1:443  <->  10.0.0.1:54321  100  120 kB  ..."
                parts = line.split("<->")
                if len(parts) == 2:
                    left = parts[0].strip()
                    right_and_stats = parts[1].strip()
                    tokens = right_and_stats.split()
                    streams.append({
                        "endpoint_a": left,
                        "endpoint_b": tokens[0] if tokens else "",
                        "raw_output": line,
                    })
        return streams

    # ── File info (capinfos) ────────────────────────────────────────────

    async def file_info(self, filepath: str) -> dict[str, str]:
        """Get capture file metadata using capinfos or tshark."""
        # Try capinfos first
        capinfos = shutil.which("capinfos")
        if capinfos:
            cmd = [capinfos, "-T", filepath]
            asyncio.get_event_loop()
            result = await self._run_cmd(cmd, timeout=10.0)
            if result.returncode == 0:
                return self._parse_capinfos(result.stdout)

        # Fallback: use tshark to get basic info
        stats = await self.protocol_stats(filepath)
        total_frames = sum(s.get("frames", 0) for s in stats.values())
        return {
            "filepath": filepath,
            "total_frames": str(total_frames),
            "protocols": ", ".join(stats.keys()),
        }

    async def _run_cmd(
        self, cmd: list[str], timeout: float = 30.0
    ) -> TsharkResult:
        """Run arbitrary command (for capinfos etc)."""
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False),
                ),
                timeout=timeout + 5,
            )
            return TsharkResult(
                returncode=result.returncode,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out: {cmd}")

    @staticmethod
    def _parse_capinfos(text: str) -> dict[str, str]:
        """Parse capinfos -T output into a dict."""
        info = {}
        for line in text.split("\n"):
            if ":" in line:
                key, _, val = line.partition(":")
                info[key.strip()] = val.strip()
        return info

    # ── Export helpers ──────────────────────────────────────────────────

    async def export_json(
        self,
        filepath: str,
        display_filter: str = "",
        max_packets: int = 10000,
    ) -> list[dict]:
        """Export packets from PCAP as JSON."""
        return await self.read_pcap(filepath, display_filter, max_packets)

    async def export_fields(
        self,
        filepath: str,
        fields: list[str],
        display_filter: str = "",
    ) -> list[dict]:
        """Export specific fields from PCAP as list of dicts."""
        args = ["-r", filepath, "-T", "fields"]

        for f in fields:
            args.extend(["-e", f])

        if display_filter:
            args.extend(["-Y", display_filter])

        result = await self._run(args, timeout=60.0)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, "tshark export fields", stderr=result.stderr
            )

        rows = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            values = line.split("\t")
            row = dict(zip(fields, values, strict=False))
            rows.append(row)
        return rows
