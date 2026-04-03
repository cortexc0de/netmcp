"""PCAP analysis tools."""

from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_analysis_tools(mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator) -> None:
    """Register analysis-related MCP tools."""

    @mcp.tool()
    async def analyze_pcap_file(
        filepath: str,
        display_filter: str = "",
        max_packets: int = 10000,
    ) -> dict:
        """
        Analyze a PCAP file with optional display filters.

        Args:
            filepath: Path to PCAP/PCAPNG file
            display_filter: Wireshark display filter (e.g., 'http', 'ip.addr == 10.0.0.1')
            max_packets: Maximum number of packets to analyze
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            sec.validate_display_filter(display_filter)

            packets = await tshark.read_pcap(str(validated_path), display_filter, max_packets)
            stats = await tshark.protocol_stats(str(validated_path))

            # Extract unique IPs
            ips = set()
            for pkt in packets:
                layers = pkt.get("_source", {}).get("layers", {})
                for ip_field in ("ip.src", "ip.dst"):
                    if ip_field in layers:
                        ips.add(layers[ip_field][0] if isinstance(layers[ip_field], list) else layers[ip_field])

            result = {
                "filepath": str(validated_path),
                "total_packets": len(packets),
                "unique_ips": sorted(ips),
                "protocol_stats": stats,
                "packets": packets[:50],
            }
            return fmt.format_success(result, title="PCAP Analysis")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004" if isinstance(e, ValueError) else "NETMCP_003")

    @mcp.tool()
    async def get_protocol_statistics(filepath: str) -> dict:
        """
        Get protocol hierarchy statistics from a PCAP file.

        Args:
            filepath: Path to PCAP/PCAPNG file
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            stats = await tshark.protocol_stats(str(validated_path))

            total_frames = sum(s.get("frames", 0) for s in stats.values())
            result = {
                "filepath": str(validated_path),
                "total_frames": total_frames,
                "protocols": stats,
            }
            return fmt.format_success(result, title="Protocol Statistics")
        except Exception as e:
            return fmt.format_error(e)

    @mcp.tool()
    async def get_capture_file_info(filepath: str) -> dict:
        """
        Get metadata about a PCAP capture file.

        Args:
            filepath: Path to PCAP/PCAPNG file
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            info = await tshark.file_info(str(validated_path))
            return fmt.format_success(info, title="Capture File Info")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool()
    async def capture_targeted_traffic(
        interface: str,
        target_host: str = "",
        target_port: int = 0,
        protocol: str = "",
        duration: int = 10,
        packet_limit: int = 500,
    ) -> dict:
        """
        Capture traffic targeted to specific host, port, or protocol.

        Args:
            interface: Network interface name
            target_host: Filter by host IP (optional)
            target_port: Filter by port number (optional)
            protocol: Filter by protocol (tcp, udp, icmp, http)
            duration: Max capture duration in seconds
            packet_limit: Maximum packets to capture
        """
        try:
            sec.validate_interface(interface)

            # Build BPF filter
            filter_parts = []
            if target_host:
                sec.validate_target(target_host)
                filter_parts.append(f"host {target_host}")
            if target_port:
                sec.validate_port_range(str(target_port))
                filter_parts.append(f"port {target_port}")
            if protocol:
                if protocol.lower() in ("http", "https"):
                    filter_parts.append(f"tcp port {80 if protocol.lower() == 'http' else 443}")
                else:
                    filter_parts.append(protocol.lower())

            bpf = " and ".join(filter_parts) if filter_parts else ""

            pcap_path = await tshark.capture_live(
                interface=interface,
                bpf_filter=bpf,
                packet_count=packet_limit,
                timeout=float(duration),
            )

            packets = await tshark.read_pcap(str(pcap_path))
            result = {
                "interface": interface,
                "filter": bpf,
                "duration": duration,
                "packets_captured": len(packets),
                "pcap_file": str(pcap_path),
                "packets": packets[:50],
            }
            return fmt.format_success(result, title="Targeted Capture")
        except Exception as e:
            return fmt.format_error(e)

    @mcp.tool()
    async def analyze_http_traffic(filepath: str) -> dict:
        """
        Analyze HTTP traffic from a PCAP file.

        Extracts HTTP methods, hosts, URIs, user agents, and response codes.

        Args:
            filepath: Path to PCAP/PCAPNG file
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            packets = await tshark.export_fields(
                str(validated_path),
                fields=["http.request.method", "http.host", "http.request.uri",
                        "http.response.code", "http.user_agent"],
                display_filter="http",
            )

            methods = {}
            hosts = {}
            status_codes = {}
            requests = []

            for row in packets:
                method = row.get("http.request.method", "")
                host = row.get("http.host", "")
                uri = row.get("http.request.uri", "")
                status = row.get("http.response.code", "")
                ua = row.get("http.user_agent", "")

                if method:
                    methods[method] = methods.get(method, 0) + 1
                if host:
                    hosts[host] = hosts.get(host, 0) + 1
                if status:
                    status_codes[status] = status_codes.get(status, 0) + 1
                if method or uri:
                    requests.append({"method": method, "host": host, "uri": uri, "user_agent": ua})

            result = {
                "filepath": str(validated_path),
                "total_http_requests": len(requests),
                "methods": methods,
                "hosts": dict(sorted(hosts.items(), key=lambda x: -x[1])[:20]),
                "status_codes": status_codes,
                "sample_requests": requests[:20],
            }
            return fmt.format_success(result, title="HTTP Traffic Analysis")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool()
    async def detect_network_protocols(
        filepath: str = "",
        interface: str = "",
        duration: int = 10,
    ) -> dict:
        """
        Detect and report network protocols in use.

        Args:
            filepath: Path to existing PCAP file (optional)
            interface: Network interface for live capture (if no file)
            duration: Duration in seconds for live capture
        """
        try:
            if filepath:
                validated_path = sec.sanitize_filepath(filepath)
                stats = await tshark.protocol_stats(str(validated_path))
                source = str(validated_path)
            elif interface:
                sec.validate_interface(interface)
                pcap_path = await tshark.capture_live(
                    interface=interface,
                    packet_count=200,
                    timeout=float(duration),
                )
                stats = await tshark.protocol_stats(str(pcap_path))
                source = f"live capture on {interface}"
            else:
                return fmt.format_error(ValueError("Either filepath or interface required"), "NETMCP_002")

            insights = []
            proto_names = list(stats.keys())
            for p in ["http", "HTTP", "tls", "TLS", "ssl", "SSL", "dns", "DNS"]:
                if any(p in pn for pn in proto_names):
                    insights.append(f"Protocol detected: {p}")

            result = {
                "source": source,
                "total_protocols": len(stats),
                "protocols": stats,
                "insights": insights,
            }
            return fmt.format_success(result, title="Protocol Detection")
        except Exception as e:
            return fmt.format_error(e)
