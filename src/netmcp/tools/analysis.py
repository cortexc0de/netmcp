"""PCAP analysis tools."""

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_analysis_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register analysis-related MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Analyze Pcap File",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
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
                        ips.add(
                            layers[ip_field][0]
                            if isinstance(layers[ip_field], list)
                            else layers[ip_field]
                        )

            result = {
                "filepath": str(validated_path),
                "total_packets": len(packets),
                "unique_ips": sorted(ips),
                "protocol_stats": stats,
                "packets": packets[:50],
            }
            return fmt.truncate_output(fmt.format_success(result, title="PCAP Analysis"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004" if isinstance(e, ValueError) else "NETMCP_003")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get Protocol Statistics",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
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
            return fmt.truncate_output(fmt.format_success(result, title="Protocol Statistics"))
        except Exception as e:
            return fmt.format_error(e)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Get Capture File Info",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
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

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Capture Targeted Traffic",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def capture_targeted_traffic(
        interface: str,
        target_host: str = "",
        target_port: int = 0,
        protocol: str = "",
        duration: int = 10,
        packet_limit: int = 500,
        ctx: Context | None = None,
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
            ctx: Optional MCP context for progress reporting
        """
        try:
            sec.validate_interface(interface)
            if not sec.check_rate_limit("live_capture", max_ops=30, window_seconds=3600):
                raise RuntimeError("Rate limit exceeded: max 30 live captures per hour")
            sec.audit_log("capture_targeted_traffic", {
                "interface": interface, "target_host": target_host,
                "target_port": target_port, "protocol": protocol,
            })

            # Build BPF filter
            filter_parts = []
            if target_host:
                sec.validate_target(target_host)
                filter_parts.append(f"host {target_host}")
            if target_port:
                sec.validate_port_range(str(target_port))
                filter_parts.append(f"port {target_port}")
            if protocol:
                allowed_protocols = {"tcp", "udp", "icmp", "arp", "ip", "ip6", "http", "https"}
                if protocol.lower() not in allowed_protocols:
                    raise ValueError(
                        f"Invalid protocol: {protocol!r}. "
                        f"Allowed: {', '.join(sorted(allowed_protocols))}"
                    )
                if protocol.lower() in ("http", "https"):
                    filter_parts.append(f"tcp port {80 if protocol.lower() == 'http' else 443}")
                else:
                    filter_parts.append(protocol.lower())

            bpf = " and ".join(filter_parts) if filter_parts else ""

            if ctx:
                await ctx.report_progress(0, 2)

            pcap_path = await tshark.capture_live(
                interface=interface,
                bpf_filter=bpf,
                packet_count=packet_limit,
                timeout=float(duration),
            )

            try:
                if ctx:
                    await ctx.report_progress(1, 2)

                packets = await tshark.read_pcap(str(pcap_path))
                result = {
                    "interface": interface,
                    "filter": bpf,
                    "duration": duration,
                    "packets_captured": len(packets),
                    "pcap_file": str(pcap_path),
                    "packets": packets[:50],
                }

                if ctx:
                    await ctx.report_progress(2, 2)

                return fmt.format_success(result, title="Targeted Capture")
            finally:
                import os
                try:
                    os.unlink(str(pcap_path))
                except OSError:
                    pass
        except Exception as e:
            return fmt.format_error(e)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Analyze Http Traffic",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
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
                fields=[
                    "http.request.method",
                    "http.host",
                    "http.request.uri",
                    "http.response.code",
                    "http.user_agent",
                ],
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
            return fmt.truncate_output(fmt.format_success(result, title="HTTP Traffic Analysis"))
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Detect Network Protocols",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
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
                try:
                    stats = await tshark.protocol_stats(str(pcap_path))
                finally:
                    import os
                    try:
                        os.unlink(str(pcap_path))
                    except OSError:
                        pass
                source = f"live capture on {interface}"
            else:
                return fmt.format_error(
                    ValueError("Either filepath or interface required"), "NETMCP_002"
                )

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

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Analyze Http Headers",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def analyze_http_headers(
        filepath: str,
        include_cookies: bool = True,
    ) -> dict:
        """
        Analyze HTTP headers from a PCAP file — tokens, cookies, auth headers.

        Extracts:
        - Cookies and session tokens
        - Authorization headers (Bearer, API keys)
        - Custom security headers
        - Suspicious headers (X-Forwarded-For spoofing)

        Args:
            filepath: Path to PCAP/PCAPNG file
            include_cookies: Whether to include cookie analysis
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)

            # Extract HTTP header fields
            header_fields = [
                "http.request.method",
                "http.host",
                "http.request.uri",
                "http.authorization",
                "http.cookie",
                "http.set_cookie",
                "http.user_agent",
                "http.referer",
                "http.x_forwarded_for",
                "http.response.code",
                "frame.number",
            ]
            rows = await tshark.export_fields(
                str(validated_path), header_fields, display_filter="http"
            )

            auth_tokens = []
            cookies = []
            suspicious = []
            user_agents = set()

            for row in rows:
                auth = row.get("http.authorization", "")
                cookie = row.get("http.cookie", "") if include_cookies else ""
                xff = row.get("http.x_forwarded_for", "")
                ua = row.get("http.user_agent", "")
                frame = row.get("frame.number", "")

                # Auth tokens
                if auth:
                    auth_tokens.append(
                        {
                            "type": "Bearer"
                            if auth.startswith("Bearer")
                            else "Basic"
                            if auth.startswith("Basic")
                            else "Other",
                            "value_preview": auth[:50] + "...",
                            "frame": frame,
                        }
                    )

                # Cookies
                if cookie:
                    cookie_parts = cookie.split("; ")
                    for part in cookie_parts:
                        if "=" in part:
                            name, _, val = part.partition("=")
                            cookies.append(
                                {
                                    "name": name.strip(),
                                    "value_preview": val[:30] + "..." if len(val) > 30 else val,
                                    "frame": frame,
                                }
                            )

                # Suspicious headers
                if xff:
                    suspicious.append(
                        {
                            "type": "X-Forwarded-For",
                            "value": xff,
                            "frame": frame,
                        }
                    )

                # User agents
                if ua:
                    user_agents.add(ua)

            result = {
                "filepath": str(validated_path),
                "auth_tokens_found": len(auth_tokens),
                "cookies_found": len(cookies),
                "suspicious_headers": len(suspicious),
                "unique_user_agents": len(user_agents),
                "auth_tokens": auth_tokens[:50],
                "cookies": cookies[:100],
                "suspicious": suspicious[:20],
                "user_agents": list(user_agents)[:20],
            }
            return fmt.format_success(result, title="HTTP Header Analysis")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Geoip Lookup",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def geoip_lookup(
        ip_addresses: str,
        filepath: str = "",
    ) -> dict:
        """
        Look up geographic information for IP addresses.

        Can check specific IPs or extract all from a PCAP file.

        Args:
            ip_addresses: Comma-separated IP addresses (e.g., '1.1.1.1,8.8.8.8')
            filepath: PCAP file to extract IPs from (optional, overrides ip_addresses if provided)
        """
        try:
            from netmcp.utils.geoip import enrich_ips

            ips_to_check = []

            if filepath:
                validated_path = sec.sanitize_filepath(filepath)
                # Extract IPs from PCAP
                packets = await tshark.export_fields(str(validated_path), ["ip.src", "ip.dst"])
                for row in packets:
                    for val in row.values():
                        val = val.strip()
                        if val and val not in ("", "unknown"):
                            ips_to_check.append(val)
                ips_to_check = list(set(ips_to_check))[:100]  # Limit to 100
            elif ip_addresses:
                ips_to_check = [ip.strip() for ip in ip_addresses.split(",") if ip.strip()]

            if not ips_to_check:
                return fmt.format_error(ValueError("No IP addresses provided"), "NETMCP_002")

            geo_results = await enrich_ips(ips_to_check)

            # Summary
            countries = {}
            for r in geo_results:
                c = r.get("country", "Unknown")
                countries[c] = countries.get(c, 0) + 1

            result = {
                "total_ips": len(geo_results),
                "countries": dict(sorted(countries.items(), key=lambda x: -x[1])),
                "results": geo_results[:100],
            }
            return fmt.format_success(result, title="GeoIP Lookup")
        except Exception as e:
            return fmt.format_error(e)

    # ── DNS Analysis ────────────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Analyze DNS Traffic",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def analyze_dns_traffic(filepath: str, max_queries: int = 1000) -> dict:
        """Analyze DNS queries and responses from a PCAP file.

        Extracts DNS query names, types, response codes, and identifies
        potential DNS tunneling or suspicious patterns.

        Args:
            filepath: Path to PCAP/PCAPNG file
            max_queries: Maximum number of DNS rows to process
        """
        try:
            validated = sec.sanitize_filepath(filepath)

            dns_fields = [
                "dns.qry.name",
                "dns.qry.type",
                "dns.flags.rcode",
                "dns.resp.name",
                "dns.a",
                "dns.aaaa",
                "ip.src",
                "ip.dst",
            ]
            rows = await tshark.export_fields(str(validated), dns_fields, "dns")

            queries: dict[str, int] = {}
            nxdomains: list[str] = []
            for row in rows[:max_queries]:
                qname = row.get("dns.qry.name", "")
                rcode = row.get("dns.flags.rcode", "")
                if qname:
                    queries[qname] = queries.get(qname, 0) + 1
                if rcode == "3":  # NXDOMAIN
                    nxdomains.append(qname)

            top_domains = sorted(queries.items(), key=lambda x: x[1], reverse=True)[:20]
            unique_nxdomains = list(set(nxdomains))[:50]

            # Detect potential DNS tunneling (unusually long subdomain names)
            suspicious = [q for q in queries if len(q) > 60 or q.count(".") > 6]

            return fmt.format_success(
                {
                    "total_dns_packets": len(rows),
                    "unique_queries": len(queries),
                    "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
                    "nxdomain_count": len(nxdomains),
                    "nxdomains": unique_nxdomains,
                    "suspicious_domains": suspicious[:20],
                    "potential_tunneling": len(suspicious) > 0,
                },
                title="DNS Analysis",
            )
        except Exception as e:
            return fmt.format_error(e)

    # ── Expert Information ──────────────────────────────────────────────

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Expert Information",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def get_expert_info(filepath: str) -> dict:
        """Extract Wireshark expert information from a PCAP file.

        Returns warnings, errors, and notes from Wireshark's expert system.
        Useful for identifying protocol violations, malformed packets, etc.

        Args:
            filepath: Path to PCAP/PCAPNG file
        """
        try:
            validated = sec.sanitize_filepath(filepath)

            result = await tshark._run(
                ["-r", str(validated), "-z", "expert", "-q"],
                timeout=60.0,
            )

            entries: dict[str, list[str]] = {
                "error": [],
                "warning": [],
                "note": [],
                "chat": [],
            }
            current_severity: str | None = None
            for line in result.stdout.split("\n"):
                line = line.strip()
                if not line or line.startswith("="):
                    continue
                lower = line.lower()
                if "errors" in lower and "(" in lower:
                    current_severity = "error"
                    continue
                elif "warnings" in lower and "(" in lower:
                    current_severity = "warning"
                    continue
                elif "notes" in lower and "(" in lower:
                    current_severity = "note"
                    continue
                elif "chats" in lower and "(" in lower:
                    current_severity = "chat"
                    continue
                if current_severity and line:
                    entries[current_severity].append(line)

            return fmt.format_success(
                {
                    "errors": entries["error"][:50],
                    "warnings": entries["warning"][:50],
                    "notes": entries["note"][:50],
                    "chats": entries["chat"][:20],
                    "summary": {
                        "error_count": len(entries["error"]),
                        "warning_count": len(entries["warning"]),
                        "note_count": len(entries["note"]),
                        "chat_count": len(entries["chat"]),
                    },
                },
                title="Expert Information",
            )
        except Exception as e:
            return fmt.format_error(e)
