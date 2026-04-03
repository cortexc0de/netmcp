"""Response formatting utilities for NetMCP."""

import json
import subprocess
from typing import Any, ClassVar


# Standardized error codes
class ErrorCode:
    """NetMCP error code constants."""
    INTERNAL = "NETMCP_001"          # Unexpected internal error
    VALIDATION = "NETMCP_002"        # Input validation failure
    TOOL_EXECUTION = "NETMCP_003"    # External tool execution error (tshark, nmap)
    FILE_ERROR = "NETMCP_004"        # File not found, permission, or format error
    TIMEOUT = "NETMCP_005"           # Operation timed out
    RATE_LIMITED = "NETMCP_006"      # Rate limit exceeded
    PERMISSION = "NETMCP_007"        # Insufficient permissions
    NOT_AVAILABLE = "NETMCP_008"     # Required tool not installed


class OutputFormatter:
    """Standardized output formatting for MCP responses."""

    # Error code mapping
    _ERROR_CODES: ClassVar[dict[type[Exception], str]] = {
        ValueError: ErrorCode.VALIDATION,
        FileNotFoundError: ErrorCode.FILE_ERROR,
        TimeoutError: ErrorCode.TIMEOUT,
        PermissionError: ErrorCode.PERMISSION,
        subprocess.CalledProcessError: ErrorCode.TOOL_EXECUTION,
        RuntimeError: ErrorCode.INTERNAL,
    }

    def format_json(self, data: Any) -> str:
        """Pretty-print data as JSON."""
        # Explicitly reject non-serializable types before json.dumps swallows them
        if isinstance(data, (set, frozenset)):
            raise ValueError(f"Data is not JSON serializable: {type(data).__name__}")
        try:
            return json.dumps(data, indent=2, default=str)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Data is not JSON serializable: {e}") from e

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
            # Use isinstance to catch subclasses
            for exc_type, code_val in self._ERROR_CODES.items():
                if isinstance(error, exc_type):
                    code = code_val
                    break
            else:
                code = "NETMCP_001"

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
        lines.append(fmt.format(*list(headers)))
        # Separator
        lines.append("  ".join("-" * widths[h] for h in headers))
        # Rows
        for row in rows:
            vals = [str(row.get(h, "-")) for h in headers]
            lines.append(fmt.format(*vals))

        return "\n".join(lines)

    MAX_OUTPUT_CHARS = 500_000  # 500K chars to prevent LLM context overflow

    def truncate_output(self, result: dict, max_chars: int = 0) -> dict:
        """Truncate output to prevent LLM context overflow."""
        limit = max_chars or self.MAX_OUTPUT_CHARS
        text = result.get("content", [{}])[0].get("text", "")
        if len(text) <= limit:
            return result
        truncated = text[:limit]
        remaining = len(text) - limit
        new_text = (
            f"{truncated}\n\n⚠️ Вывод обрезан ({remaining:,} символов пропущено). "
            f"Используйте фильтры для сужения результатов."
        )
        return {
            "content": [{"type": "text", "text": new_text}],
            "isError": result.get("isError", False),
        }

    def truncate(self, text: str, max_chars: int = 720000) -> str:
        """Truncate text to max_chars with indicator."""
        if not text:
            return ""
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + f"\n\n... [truncated to {max_chars} chars]"

    def format_success(self, result: Any, title: str = "") -> dict:
        """Return standardized MCP success response."""
        text = self.format_json(result) if isinstance(result, (dict, list)) else str(result)

        if title:
            text = f"=== {title} ===\n{text}"

        return {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
