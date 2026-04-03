"""Threat intelligence tools."""

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.threat_intel import ThreatIntelInterface
from netmcp.interfaces.tshark import TsharkInterface


def register_threat_tools(
    mcp: FastMCP,
    tshark: TsharkInterface,
    threat: ThreatIntelInterface,
    fmt: OutputFormatter,
    sec: SecurityValidator,
) -> None:
    """Register threat-related MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Check Ip Threat Intel",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    @mcp.tool()
    async def check_ip_threat_intel(
        ip_address: str,
        providers: str = "urlhaus,abuseipdb",
    ) -> dict:
        """
        Check an IP address against threat intelligence feeds.

        Args:
            ip_address: IP address to check
            providers: Comma-separated providers (urlhaus, abuseipdb)
        """
        try:
            sec.validate_target(ip_address)
            provider_list = [p.strip() for p in providers.split(",") if p.strip()]

            result = await threat.check_ip(ip_address, provider_list or None)
            return fmt.format_success(result, title=f"Threat Intel: {ip_address}")
        except Exception as e:
            return fmt.format_error(e)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Scan Capture For Threats",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    @mcp.tool()
    async def scan_capture_for_threats(
        filepath: str,
        providers: str = "urlhaus,abuseipdb",
    ) -> dict:
        """
        Extract all IPs from a PCAP file and check against threat feeds.

        Args:
            filepath: Path to PCAP/PCAPNG file
            providers: Comma-separated providers (urlhaus, abuseipdb)
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            provider_list = [p.strip() for p in providers.split(",") if p.strip()]

            result = await threat.scan_pcap(str(validated_path), tshark, provider_list or None)
            return fmt.format_success(result, title="PCAP Threat Scan")
        except Exception as e:
            return fmt.format_error(e)
