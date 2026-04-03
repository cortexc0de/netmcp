"""Security validation, sanitization, and rate limiting for NetMCP."""

import os
import re
import threading
import time
from ipaddress import AddressValueError, NetmaskValueError, ip_address, ip_network
from pathlib import Path

# Patterns for input validation
_SHELL_META = re.compile(r"[;|&$`{}!]")
_INTERFACE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9:_\-\.]{0,255}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$"
)

# File constraints
_ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Rate limiting defaults
_DEFAULT_RATE_LIMIT = 10  # max operations
_DEFAULT_RATE_WINDOW = 3600  # seconds (1 hour)


class SecurityValidator:
    """Multi-layer input validation and sanitization for NetMCP."""

    def __init__(self) -> None:
        self._rate_limit_history: dict[str, list[float]] = {}
        self._rate_limit_lock = threading.Lock()

    # ── Interface validation ──────────────────────────────────────────

    def validate_interface(self, name: str) -> str:
        """Validate a network interface name."""
        if not name or not name.strip():
            raise ValueError("Interface name cannot be empty")
        if _SHELL_META.search(name):
            raise ValueError(f"Interface name contains shell metacharacters: {name!r}")
        if " " in name:
            raise ValueError("Interface name cannot contain spaces")
        if len(name) > 256:
            raise ValueError(f"Interface name too long ({len(name)} > 256)")
        if not _INTERFACE_RE.match(name):
            raise ValueError(f"Invalid interface name format: {name!r}")
        return name.strip()

    # ── Target validation (IP / CIDR / hostname) ──────────────────────

    def validate_target(self, target: str) -> str:
        """Validate an IP address, CIDR range, or hostname."""
        if not target or not target.strip():
            raise ValueError("Target cannot be empty")
        if _SHELL_META.search(target):
            raise ValueError(f"Target contains dangerous characters: {target!r}")

        # Try IP address (v4/v6)
        try:
            ip_address(target)
            return target.strip()
        except (ValueError, AddressValueError):
            pass

        # Try CIDR range
        if "/" in target:
            try:
                ip_network(target, strict=False)
                return target.strip()
            except (ValueError, AddressValueError, NetmaskValueError):
                pass

        # Try hostname
        if _HOSTNAME_RE.match(target):
            return target.strip()

        raise ValueError(f"Invalid target (not a valid IP, CIDR, or hostname): {target!r}")

    # ── Port range validation ─────────────────────────────────────────

    def validate_port_range(self, ports: str) -> str:
        """Validate a port specification: '80', '1-1024', '80,443,8080'."""
        if not ports or not ports.strip():
            raise ValueError("Port specification cannot be empty")

        parts = ports.strip().split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                tokens = part.split("-", 1)
                if len(tokens) != 2:
                    raise ValueError(f"Invalid port range: {part!r}")
                try:
                    lo, hi = int(tokens[0]), int(tokens[1])
                except ValueError:
                    raise ValueError(f"Invalid port range (non-numeric): {part!r}") from None
                if lo < 1 or hi > 65535 or lo > hi:
                    raise ValueError(f"Invalid port range: {part!r}")
            else:
                try:
                    port = int(part)
                except ValueError:
                    raise ValueError(f"Invalid port (non-numeric): {part!r}") from None
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port number: {port}")

        return ports.strip()

    # ── Capture filter (BPF) validation ───────────────────────────────

    def validate_capture_filter(self, bpf: str) -> str:
        """Validate a BPF capture filter string."""
        if bpf == "":
            return ""
        if _SHELL_META.search(bpf):
            raise ValueError(f"Capture filter contains shell metacharacters: {bpf!r}")
        if len(bpf) > 256:
            raise ValueError(f"Capture filter too long ({len(bpf)} > 256 chars)")
        return bpf

    # ── Display filter validation ─────────────────────────────────────

    def validate_display_filter(self, dfilter: str) -> str:
        """Validate a Wireshark display filter string."""
        if dfilter == "":
            return ""
        if _SHELL_META.search(dfilter):
            raise ValueError(f"Display filter contains shell metacharacters: {dfilter!r}")
        if len(dfilter) > 512:
            raise ValueError(f"Display filter too long ({len(dfilter)} > 512 chars)")
        return dfilter

    # ── File path sanitization ────────────────────────────────────────

    def sanitize_filepath(self, path: str) -> Path:
        """Sanitize and validate a file path."""
        p = Path(path)

        # Reject path traversal
        try:
            resolved = p.resolve(strict=False)
        except (OSError, ValueError):
            raise ValueError(f"Invalid file path: {path!r}") from None

        # Check for path traversal attempts in original string
        if ".." in str(p).split(os.sep):
            raise ValueError(f"Path traversal not allowed: {path!r}")

        # Check extension
        ext = resolved.suffix.lower()
        if ext not in _ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Invalid file extension: {ext!r}. "
                f"Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}"
            )

        # Check file exists
        if not resolved.exists():
            raise ValueError(f"File does not exist: {resolved}")

        # Check file size
        size = resolved.stat().st_size
        if size > _MAX_FILE_SIZE:
            raise ValueError(
                f"File too large ({size / 1024 / 1024:.1f} MB > {_MAX_FILE_SIZE / 1024 / 1024:.0f} MB)"
            )

        return resolved

    # ── Rate limiting ─────────────────────────────────────────────────

    def check_rate_limit(
        self,
        operation: str,
        max_ops: int = _DEFAULT_RATE_LIMIT,
        window_seconds: int = _DEFAULT_RATE_WINDOW,
    ) -> bool:
        """Check if an operation is allowed under rate limiting.

        Returns True if allowed, False if rate limit exceeded.
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._rate_limit_lock:
            if operation not in self._rate_limit_history:
                self._rate_limit_history[operation] = []

            # Remove expired entries
            self._rate_limit_history[operation] = [
                t for t in self._rate_limit_history[operation] if t > cutoff
            ]

            # Check limit
            if len(self._rate_limit_history[operation]) >= max_ops:
                return False

            # Record this operation
            self._rate_limit_history[operation].append(now)
            return True

    # ── Privilege detection ───────────────────────────────────────────

    def is_privileged(self) -> bool:
        """Check if the process is running with elevated privileges."""
        if os.name == "nt":
            import ctypes

            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        else:
            try:
                return os.getuid() == 0
            except AttributeError:
                return False
