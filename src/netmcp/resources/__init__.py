"""MCP Resources for NetMCP."""

import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.interfaces.nmap import NmapInterface
from netmcp.interfaces.tshark import TsharkInterface


def register_resources(
    mcp: FastMCP,
    tshark: TsharkInterface,
    nmap: NmapInterface,
    fmt: OutputFormatter,
) -> None:
    """Register MCP resources."""

    @mcp.resource("netmcp://interfaces")
    def get_interfaces() -> str:
        """Dynamic list of available network interfaces."""
        try:
            result = subprocess.run(
                [tshark.tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            if result.returncode != 0:
                return f"Error listing interfaces: {result.stderr}"

            interfaces = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if ". " in line:
                    line = line.split(". ", 1)[1]
                if " (" in line:
                    line = line.split(" (", 1)[0]
                interfaces.append(line.strip())

            return fmt.format_json({"count": len(interfaces), "interfaces": interfaces})
        except FileNotFoundError:
            return f"Error: tshark not found at {tshark.tshark_path}"
        except subprocess.TimeoutExpired:
            return "Error: interface listing timed out"
        except Exception as e:
            return f"Error: {e}"

    @mcp.resource("netmcp://captures")
    def get_captures() -> str:
        """List available PCAP files in common directories."""
        search_dirs = [
            Path.home() / "captures",
            Path.home() / "pcaps",
            Path.cwd(),
        ]

        captures = []
        for d in search_dirs:
            if d.exists():
                for f in d.glob("*.pcap"):
                    captures.append(
                        {"path": str(f), "size_mb": round(f.stat().st_size / 1024 / 1024, 2)}
                    )
                for f in d.glob("*.pcapng"):
                    captures.append(
                        {"path": str(f), "size_mb": round(f.stat().st_size / 1024 / 1024, 2)}
                    )

        return fmt.format_json({"count": len(captures), "files": captures})

    @mcp.resource("netmcp://system/info")
    def get_system_info() -> str:
        """System capabilities and tool availability."""
        import platform
        import sys

        info = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "tshark_available": tshark.tshark_path is not None,
            "tshark_path": tshark.tshark_path,
            "nmap_available": nmap.available,
            "tools": (
                list(mcp._tool_manager._tools.keys())
                if hasattr(mcp, "_tool_manager")
                and hasattr(mcp._tool_manager, "_tools")
                else []
            ),
        }
        return fmt.format_json(info)
