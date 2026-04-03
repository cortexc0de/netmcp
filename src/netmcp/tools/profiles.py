"""Wireshark profile integration tools."""

import os
import platform
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def _profile_search_dirs() -> list[Path]:
    """Return candidate Wireshark profile directories for the current platform."""
    home = Path.home()
    dirs: list[Path] = []
    system = platform.system()
    if system == "Darwin":
        dirs.append(home / "Library" / "Application Support" / "Wireshark" / "profiles")
    else:
        dirs.append(home / ".config" / "wireshark" / "profiles")
    # Older Wireshark versions (all platforms)
    dirs.append(home / ".wireshark" / "profiles")
    return dirs


def _find_profile_dir(profile_name: str) -> Path:
    """Locate the directory for a named profile.

    Raises ValueError if not found.
    """
    if not profile_name or not isinstance(profile_name, str):
        raise ValueError("Profile name must be a non-empty string")
    # Reject path traversal / shell meta-characters
    if re.search(r"[/\\;|&`$<>]", profile_name) or ".." in profile_name:
        raise ValueError(f"Invalid characters in profile name: {profile_name!r}")

    for base in _profile_search_dirs():
        candidate = base / profile_name
        if candidate.is_dir():
            return candidate
    raise ValueError(
        f"Wireshark profile {profile_name!r} not found in: "
        + ", ".join(str(d) for d in _profile_search_dirs())
    )


def _default_config_dir() -> Path | None:
    """Return the default (non-profile) Wireshark config directory, if it exists."""
    home = Path.home()
    system = platform.system()
    candidates: list[Path] = []
    if system == "Darwin":
        candidates.append(home / "Library" / "Application Support" / "Wireshark")
    else:
        candidates.append(home / ".config" / "wireshark")
    candidates.append(home / ".wireshark")
    for d in candidates:
        if d.is_dir():
            return d
    return None


_CONFIG_FILES = ("colorfilters", "preferences", "decode_as_entries")


def _parse_colorfilters(text: str) -> list[dict]:
    """Parse Wireshark colorfilters file content into structured dicts.

    Format: @<name>@<filter>@[r,g,b][r,g,b]
    Lines starting with '!' are disabled.
    """
    filters: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        enabled = True
        if line.startswith("!"):
            enabled = False
            line = line[1:]
        if not line.startswith("@"):
            continue
        parts = line.split("@")
        # Expected: ['', name, filter, '[r,g,b][r,g,b]']
        if len(parts) < 4:
            continue
        name = parts[1]
        display_filter = parts[2]
        colors_raw = parts[3]
        # Parse colour pairs: [r,g,b][r,g,b]
        rgb_matches = re.findall(r"\[(\d+),(\d+),(\d+)\]", colors_raw)
        fg_rgb = [int(c) for c in rgb_matches[0]] if len(rgb_matches) >= 1 else []
        bg_rgb = [int(c) for c in rgb_matches[1]] if len(rgb_matches) >= 2 else []
        filters.append(
            {
                "name": name,
                "display_filter": display_filter,
                "foreground_rgb": fg_rgb,
                "background_rgb": bg_rgb,
                "enabled": enabled,
            }
        )
    return filters


def register_profile_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register Wireshark profile MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="List Wireshark Profiles",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    async def list_wireshark_profiles() -> dict:
        """List available Wireshark profiles and their configuration files."""
        try:
            profiles: list[dict] = []
            for base in _profile_search_dirs():
                if not base.is_dir():
                    continue
                for entry in sorted(base.iterdir()):
                    if not entry.is_dir():
                        continue
                    profiles.append(
                        {
                            "name": entry.name,
                            "path": str(entry),
                            "has_colorfilters": (entry / "colorfilters").is_file(),
                            "has_preferences": (entry / "preferences").is_file(),
                            "has_decode_as": (entry / "decode_as_entries").is_file(),
                        }
                    )

            default_path = _default_config_dir()
            return fmt.format_success(
                {
                    "profiles": profiles,
                    "default_profile_path": str(default_path) if default_path else None,
                },
                title="Wireshark Profiles",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Analyze PCAP With Profile",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def apply_profile_capture(
        filepath: str,
        profile_name: str,
        display_filter: str = "",
        max_packets: int = 10000,
    ) -> dict:
        """Analyze a PCAP file using a specific Wireshark profile.

        Args:
            filepath: Path to PCAP/PCAPNG file
            profile_name: Wireshark profile name to apply
            display_filter: Optional Wireshark display filter
            max_packets: Maximum packets to return
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            sec.validate_display_filter(display_filter)
            _find_profile_dir(profile_name)

            args = ["-C", profile_name, "-r", str(validated_path), "-T", "json"]
            if display_filter:
                args.extend(["-Y", display_filter])
            args.extend(["-c", str(max_packets)])

            result = await tshark._run(args, timeout=60.0)
            if result.returncode != 0:
                raise RuntimeError(f"tshark failed: {result.stderr.strip()}")

            import json

            packets = json.loads(result.stdout) if result.stdout.strip() else []

            return fmt.format_success(
                {
                    "filepath": str(validated_path),
                    "profile": profile_name,
                    "packets_analyzed": len(packets),
                    "packets": packets[:50],
                },
                title="Profile Analysis",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get Color Filters",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    async def get_color_filters(profile_name: str = "") -> dict:
        """Read Wireshark color filter rules from a profile or the default config.

        Args:
            profile_name: Profile name (empty string uses default config)
        """
        try:
            if profile_name:
                profile_dir = _find_profile_dir(profile_name)
                colorfilters_path = profile_dir / "colorfilters"
            else:
                default_dir = _default_config_dir()
                if default_dir is None:
                    raise FileNotFoundError("No default Wireshark configuration directory found")
                colorfilters_path = default_dir / "colorfilters"

            if not colorfilters_path.is_file():
                raise FileNotFoundError(
                    f"colorfilters file not found at {colorfilters_path}"
                )

            text = colorfilters_path.read_text(encoding="utf-8", errors="replace")
            filters = _parse_colorfilters(text)

            return fmt.format_success(
                {
                    "profile": profile_name or "default",
                    "filter_count": len(filters),
                    "filters": filters,
                },
                title="Color Filters",
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Capture With Profile",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def capture_with_profile(
        interface: str,
        profile_name: str,
        duration: int = 10,
        packet_count: int = 500,
    ) -> dict:
        """Live capture using a Wireshark profile's configuration.

        Args:
            interface: Network interface name (e.g., eth0, en0)
            profile_name: Wireshark profile name to apply
            duration: Capture duration in seconds
            packet_count: Maximum number of packets
        """
        try:
            sec.validate_interface(interface)
            if not sec.check_rate_limit("profile_capture", max_ops=30, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 30 profile captures per hour")
            sec.audit_log(
                "capture_with_profile",
                {"interface": interface, "profile": profile_name},
            )
            _find_profile_dir(profile_name)  # validate profile exists

            import tempfile

            tmp_fd, tmp_name = tempfile.mkstemp(suffix=".pcap", prefix="netmcp_profile_")
            os.close(tmp_fd)
            pcap_path = Path(tmp_name)

            try:
                # Capture
                capture_args = [
                    "-C",
                    profile_name,
                    "-i",
                    interface,
                    "-w",
                    str(pcap_path),
                    "-a",
                    f"duration:{duration}",
                    "-c",
                    str(packet_count),
                ]
                cap_result = await tshark._run(capture_args, timeout=float(duration) + 10.0)
                if cap_result.returncode != 0:
                    raise RuntimeError(f"tshark capture failed: {cap_result.stderr.strip()}")

                # Read back with profile
                read_args = [
                    "-C",
                    profile_name,
                    "-r",
                    str(pcap_path),
                    "-T",
                    "json",
                ]
                read_result = await tshark._run(read_args, timeout=60.0)

                import json

                packets = (
                    json.loads(read_result.stdout) if read_result.stdout.strip() else []
                )

                return fmt.format_success(
                    {
                        "interface": interface,
                        "profile": profile_name,
                        "packets_captured": len(packets),
                        "packets": packets[:50],
                    },
                    title="Profile Capture",
                )
            finally:
                try:
                    os.unlink(str(pcap_path))
                except OSError:
                    pass
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")
