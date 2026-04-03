"""Nmap scanning tools."""

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.nmap import NmapInterface


def register_nmap_tools(
    mcp: FastMCP, nmap: NmapInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register nmap-related MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Nmap Port Scan",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def nmap_port_scan(
        target: str,
        ports: str = "",
        scan_type: str = "connect",
    ) -> dict:
        """
        Scan a target for open ports.

        Args:
            target: IP address, hostname, or CIDR range
            ports: Port specification (e.g., '80,443', '1-1024'). Default: all common ports
            scan_type: Scan type: 'syn' (stealth, needs root), 'connect' (TCP), or 'udp'
        """
        try:
            if not nmap.available:
                return fmt.format_error(RuntimeError("Nmap not installed"), "NETMCP_003")

            sec.validate_target(target)
            if not sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 10 nmap scans per hour")
            sec.audit_log("nmap_port_scan", {"target": target, "ports": ports, "scan_type": scan_type})
            if ports:
                sec.validate_port_range(ports)
            if scan_type not in ("syn", "connect", "udp"):
                raise ValueError("scan_type must be 'syn', 'connect', or 'udp'")

            result = await nmap.port_scan(target, ports, scan_type)
            return fmt.format_success(
                {"target": target, "scan_type": scan_type, "result": result}, title="Port Scan"
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_002")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Nmap Service Detection",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def nmap_service_detection(target: str, ports: str = "") -> dict:
        """
        Detect service versions on open ports of a target.

        Args:
            target: IP address or hostname
            ports: Port specification (optional)
        """
        try:
            if not nmap.available:
                return fmt.format_error(RuntimeError("Nmap not installed"), "NETMCP_003")

            sec.validate_target(target)
            if not sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 10 nmap scans per hour")
            if ports:
                sec.validate_port_range(ports)

            result = await nmap.service_detect(target, ports)
            return fmt.format_success(
                {"target": target, "result": result}, title="Service Detection"
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Nmap Os Detection",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def nmap_os_detection(target: str) -> dict:
        """
        Detect the operating system of a target (requires root/admin).

        Args:
            target: IP address or hostname
        """
        try:
            if not nmap.available:
                return fmt.format_error(RuntimeError("Nmap not installed"), "NETMCP_003")

            sec.validate_target(target)
            if not sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 10 nmap scans per hour")
            result = await nmap.os_detect(target)
            return fmt.format_success({"target": target, "result": result}, title="OS Detection")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Nmap Vulnerability Scan",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def nmap_vulnerability_scan(target: str, ports: str = "") -> dict:
        """
        Run NSE vulnerability scripts against a target.

        Args:
            target: IP address or hostname
            ports: Port specification (optional)
        """
        try:
            if not nmap.available:
                return fmt.format_error(RuntimeError("Nmap not installed"), "NETMCP_003")

            sec.validate_target(target)
            if not sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 10 nmap scans per hour")
            sec.audit_log("nmap_vuln_scan", {"target": target, "ports": ports})
            if ports:
                sec.validate_port_range(ports)

            result = await nmap.vuln_scan(target, ports)
            return fmt.format_success(
                {"target": target, "result": result}, title="Vulnerability Scan"
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Nmap Quick Scan",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def nmap_quick_scan(target: str) -> dict:
        """
        Quick scan of top 100 ports on a target.

        Args:
            target: IP address or hostname
        """
        try:
            if not nmap.available:
                return fmt.format_error(RuntimeError("Nmap not installed"), "NETMCP_003")

            sec.validate_target(target)
            if not sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 10 nmap scans per hour")
            result = await nmap.quick_scan(target)
            return fmt.format_success({"target": target, "result": result}, title="Quick Scan")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Nmap Comprehensive Scan",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def nmap_comprehensive_scan(target: str) -> dict:
        """
        Full scan: SYN scan, service detection, OS detection, default scripts.

        Args:
            target: IP address or hostname
        """
        try:
            if not nmap.available:
                return fmt.format_error(RuntimeError("Nmap not installed"), "NETMCP_003")

            sec.validate_target(target)
            if not sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 10 nmap scans per hour")
            sec.audit_log("nmap_comprehensive_scan", {"target": target})
            result = await nmap.comprehensive_scan(target)
            return fmt.format_success(
                {"target": target, "result": result}, title="Comprehensive Scan"
            )
        except Exception as e:
            return fmt.format_error(e, "NETMCP_003")
