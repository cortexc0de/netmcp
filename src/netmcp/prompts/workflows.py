"""MCP Prompts for NetMCP — guided workflows."""

from mcp.server.fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:
    """Register MCP prompts."""

    @mcp.prompt()
    def security_audit(filepath: str) -> str:
        """
        Perform a comprehensive security audit of a PCAP file.

        Guided workflow:
        1. Analyze the PCAP file for protocol distribution
        2. Extract all credentials (HTTP, FTP, Telnet, Kerberos)
        3. Scan for malicious IPs using threat intelligence
        4. Identify suspicious patterns (unusual ports, data exfiltration)
        5. Generate a security report with findings and recommendations
        """
        return f"""Perform a comprehensive security audit of the PCAP file: {filepath}

Step 1: Run get_protocol_statistics to understand the traffic composition
Step 2: Run extract_credentials to find any exposed credentials
Step 3: Run scan_capture_for_threats to check for malicious IPs
Step 4: Run analyze_http_traffic to identify suspicious HTTP activity
Step 5: Run list_tcp_streams to find unusual connections

Provide a detailed security report with:
- Summary of findings
- Risk level assessment
- Specific recommendations for each issue found
- Indicators of Compromise (IOCs) if any"""

    @mcp.prompt()
    def network_troubleshooting(interface: str = "eth0", duration: int = 10) -> str:
        """
        Diagnose network issues through traffic analysis.

        Guided workflow:
        1. Capture live traffic on the specified interface
        2. Analyze protocol distribution
        3. Identify top talkers and conversations
        4. Check for packet loss, retransmissions, or anomalies
        """
        return f"""Diagnose network issues by analyzing traffic on interface '{interface}' for {duration} seconds.

Step 1: Run capture_live_packets to capture baseline traffic
Step 2: Run get_protocol_statistics to see protocol breakdown
Step 3: Identify the most active connections and protocols
Step 4: Check for anomalies: excessive DNS, retransmissions, unexpected protocols

Provide a troubleshooting report with:
- Current network state summary
- Potential issues detected
- Recommendations for improvement"""

    @mcp.prompt()
    def incident_response(target: str) -> str:
        """
        Investigate a potential security incident.

        Guided workflow:
        1. Run nmap scans against the target to identify open ports and services
        2. Check the target's IP against threat intelligence feeds
        3. Capture and analyze traffic to/from the target
        4. Generate an incident report
        """
        return f"""Investigate a potential security incident involving: {target}

Step 1: Run nmap_quick_scan to identify exposed services
Step 2: Run check_ip_threat_intel to check threat feeds
Step 3: If the target is local, run nmap_vulnerability_scan
Step 4: Run nmap_comprehensive_scan for detailed analysis
Step 5: Capture traffic with capture_live_packets (filter: 'host {target}')

Provide an incident response report with:
- Target profile (open ports, services, OS)
- Threat intelligence findings
- Vulnerability assessment
- Immediate containment recommendations
- Long-term remediation steps"""
