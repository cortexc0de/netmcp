"""Nmap interface for network scanning and service detection."""

import asyncio
import shutil
import subprocess
from dataclasses import dataclass

try:
    import nmap
    _NMAP_AVAILABLE = True
except ImportError:
    _NMAP_AVAILABLE = False


class NmapNotFoundError(Exception):
    """Raised when nmap is not available."""


@dataclass
class NmapResult:
    """Result from an nmap operation."""
    scan_type: str
    target: str
    data: dict
    returncode: int = 0
    error: str = ""


class NmapInterface:
    """Wraps python-nmap for network scanning.

    Never auto-escalates privileges. Detects when root is required.
    """

    def __init__(self) -> None:
        self.available = shutil.which("nmap") is not None and _NMAP_AVAILABLE
        self._scanner: nmap.PortScanner | None = None

    def __repr__(self) -> str:
        return f"NmapInterface(available={self.available})"

    def _get_scanner(self) -> "nmap.PortScanner":
        """Get or create nmap PortScanner instance."""
        if not self.available:
            raise NmapNotFoundError(
                "nmap not found. Please install nmap:\n"
                "  Ubuntu/Debian: sudo apt install nmap\n"
                "  macOS: brew install nmap\n"
                "  Windows: https://nmap.org/download.html"
            )
        if self._scanner is None:
            self._scanner = nmap.PortScanner()
        return self._scanner

    # ── Internal helpers ────────────────────────────────────────────────

    async def _run_scan(
        self,
        target: str,
        arguments: str,
        timeout: float = 300.0,
    ) -> dict:
        """Run an nmap scan asynchronously."""
        scanner = self._get_scanner()

        loop = asyncio.get_event_loop()

        def _scan() -> dict:
            try:
                scanner.scan(hosts=target, arguments=arguments)
                return dict(scanner.scaninfo()) if hasattr(scanner, "scaninfo") else scanner.all_hosts()
            except nmap.PortScannerError as e:
                raise RuntimeError(f"Nmap scan error: {e}")
            except subprocess.SubprocessError as e:
                raise RuntimeError(f"Nmap subprocess error: {e}")

        try:
            await asyncio.wait_for(loop.run_in_executor(None, _scan), timeout=timeout)
            # Return the full scan result
            return scanner.scan() if hasattr(scanner, "scan") else {}
        except TimeoutError:
            raise TimeoutError(f"Nmap scan timed out after {timeout}s for {target}")

    # ── Port scanning ───────────────────────────────────────────────────

    async def port_scan(
        self,
        target: str,
        ports: str = "",
        scan_type: str = "connect",
        timeout: float = 120.0,
    ) -> dict:
        """Scan for open ports.

        Args:
            target: IP, hostname, or CIDR
            ports: Port specification (e.g., "80,443", "1-1024")
            scan_type: "connect", "syn", or "udp"
            timeout: Max scan time

        Returns:
            Nmap scan result dict
        """
        args_map = {
            "connect": "-sT",
            "syn": "-sS",
            "udp": "-sU",
        }
        flag = args_map.get(scan_type, "-sT")
        args = f"{flag} -T4"
        if ports:
            args += f" -p {ports}"

        return await self._run_scan(target, args, timeout=timeout)

    # ── Service detection ───────────────────────────────────────────────

    async def service_detect(
        self,
        target: str,
        ports: str = "",
        timeout: float = 120.0,
    ) -> dict:
        """Detect service versions on open ports."""
        args = "-sV -T4"
        if ports:
            args += f" -p {ports}"
        return await self._run_scan(target, args, timeout=timeout)

    # ── OS detection ────────────────────────────────────────────────────

    async def os_detect(
        self,
        target: str,
        timeout: float = 120.0,
    ) -> dict:
        """Detect operating system (requires root/admin)."""
        args = "-O -T4 --osscan-guess"
        result = await self._run_scan(target, args, timeout=timeout)
        return result

    # ── Vulnerability scanning ──────────────────────────────────────────

    async def vuln_scan(
        self,
        target: str,
        ports: str = "",
        timeout: float = 600.0,
    ) -> dict:
        """Run NSE vulnerability scripts."""
        args = "--script vuln -T4"
        if ports:
            args += f" -p {ports}"
        return await self._run_scan(target, args, timeout=timeout)

    # ── Quick scan ──────────────────────────────────────────────────────

    async def quick_scan(
        self,
        target: str,
        timeout: float = 60.0,
    ) -> dict:
        """Fast scan of top 100 ports."""
        return await self._run_scan(target, "-F -T4", timeout=timeout)

    # ── Comprehensive scan ──────────────────────────────────────────────

    async def comprehensive_scan(
        self,
        target: str,
        timeout: float = 600.0,
    ) -> dict:
        """Full scan with OS detection, service versions, and default scripts."""
        args = "-sS -sV -O -sC -T4 --version-all"
        return await self._run_scan(target, args, timeout=timeout)
