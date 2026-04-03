"""Response formatting utilities for NetMCP."""

import json
import subprocess
from typing import Any


class OutputFormatter:
    """Standardized output formatting for MCP responses."""

    # Error code mapping
    _ERROR_CODES = {
        ValueError: "NETMCP_002",
        FileNotFoundError: "NETMCP_004",
        TimeoutError: "NETMCP_005",
        PermissionError: "NETMCP_007",
        subprocess.CalledProcessError: "NETMCP_003",
    }

    def format_json(self, data: Any) -> str:
        """Pretty-print data as JSON."""
        # Explicitly reject non-serializable types before json.dumps swallows them
        if isinstance(data, (set, frozenset)):
            raise ValueError(f"Data is not JSON serializable: {type(data).__name__}")
        try:
            return json.dumps(data, indent=2, default=str)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Data is not JSON serializable: {e}")

    def format_text(self, data: Any, title: str = "") -> str:
        """Format data as human-readable text."""
        lines = []
        if title:
            lines.append(f"=== {title} ===")

        if isinstance(data, str):
            lines.append(data)
        elif isinstance(data, dict):
            for key in ("error", "message", "result", "status"):
                if key in data:
                    lines.append(f"{key}: {data[key]}")
            # Include any other keys not yet shown
            shown = {"error", "message", "result", "status"}
            for key, val in data.items():
                if key not in shown:
                    lines.append(f"{key}: {val}")
        elif isinstance(data, (list, tuple)):
            if data and isinstance(data[0], dict):
                # List of dicts — table-like
                for item in data:
                    lines.append(json.dumps(item, default=str))
            else:
                for item in data:
                    lines.append(f"- {item}")
        else:
            lines.append(str(data))

        return "\n".join(lines)

    def format_error(self, error: Exception, code: str = "") -> dict:
        """Return standardized MCP error response."""
        if not code:
            code = self._ERROR_CODES.get(type(error), "NETMCP_001")

        msg = f"[{code}] {error}"
        return {
            "content": [{"type": "text", "text": msg}],
            "isError": True,
        }

    def format_table(self, rows: list[dict], headers: list[str]) -> str:
        """Format rows as aligned ASCII table."""
        if not headers:
            return ""

        # Calculate column widths
        widths = {h: len(h) for h in headers}
        for row in rows:
            for h in headers:
                val = str(row.get(h, "-"))
                widths[h] = max(widths[h], len(val))

        # Build format string
        fmt = "  ".join(f"{{:<{widths[h]}}}" for h in headers)

        lines = []
        # Header
        lines.append(fmt.format(*[h for h in headers]))
        # Separator
        lines.append("  ".join("-" * widths[h] for h in headers))
        # Rows
        for row in rows:
            vals = [str(row.get(h, "-")) for h in headers]
            lines.append(fmt.format(*vals))

        return "\n".join(lines)

    def truncate(self, text: str, max_chars: int = 720000) -> str:
        """Truncate text to max_chars with indicator."""
        if not text:
            return ""
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + f"\n\n... [truncated to {max_chars} chars]"

    def format_success(self, result: Any, title: str = "") -> dict:
        """Return standardized MCP success response."""
        if isinstance(result, (dict, list)):
            text = self.format_json(result)
        else:
            text = str(result)

        if title:
            text = f"=== {title} ===\n{text}"

        return {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
