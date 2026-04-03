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

    @mcp.prompt()
    def traffic_analysis(filepath: str) -> str:
        """
        Perform deep traffic analysis with protocol breakdown and GeoIP mapping.

        Guided workflow:
        1. Get protocol statistics from the PCAP
        2. Analyze HTTP traffic for patterns and anomalies
        3. Extract and analyze HTTP headers (cookies, tokens, auth)
        4. Look up GeoIP data for all IPs
        5. Identify unusual patterns or suspicious activity
        """
        return f"""Perform a comprehensive traffic analysis of: {filepath}

Step 1: Run get_protocol_statistics for protocol breakdown
Step 2: Run analyze_http_traffic to understand web activity
Step 3: Run analyze_http_headers to find cookies, tokens, auth headers
Step 4: Run geoip_lookup to map all IPs to geographic locations
Step 5: Run extract_credentials to find any exposed credentials

Provide a traffic analysis report with:
- Protocol distribution summary
- Top communicating endpoints with GeoIP data
- HTTP activity summary (methods, hosts, status codes)
- Suspicious patterns or indicators
- Cookie and token inventory"""

    @mcp.prompt()
    def network_baseline(interface: str = "eth0", duration: int = 30) -> str:
        """
        Establish a network baseline to understand normal traffic patterns.

        Guided workflow:
        1. Quick capture to see immediate activity
        2. Extended capture for baseline
        3. Protocol distribution analysis
        4. Conversation analysis
        """
        return f"""Establish a network baseline on interface '{interface}' for {duration} seconds.

Step 1: Run quick_capture to see immediate activity (3 seconds)
Step 2: Run capture_live_packets with extended duration
Step 3: Run get_protocol_statistics for protocol breakdown
Step 4: Run list_tcp_streams to understand active conversations

Provide a baseline report with:
- Normal traffic volume and protocol mix
- Expected communication pairs
- Baseline for future anomaly detection
- Any deviations from expected patterns"""
