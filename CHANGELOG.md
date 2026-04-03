# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - v0.3.0

### Added

- **Wireshark profile tools**: `list_wireshark_profiles`, `apply_profile_capture`, `get_color_filters`, `capture_with_profile` — full Wireshark profile integration
- **PCAP diff** — `diff_pcap_files` compares two capture files (packet counts, unique IPs, protocol distributions)
- **PCAP merge** — `merge_pcap_files` combines multiple captures via mergecap (chronological or append)
- **PCAP slice** — `slice_pcap` extracts packet ranges or time windows via editcap, with deduplication
- **Packet decode** — `decode_packet` provides detailed single-packet analysis with full layer dissection
- **Flow visualization** — `visualize_network_flows` generates ASCII art and Mermaid sequence diagrams of network conversations
- **TLS traffic decryption** — `decrypt_tls_traffic` decrypts HTTPS via SSLKEYLOGFILE (NSS Key Log Format)
- **DNS analysis** — `analyze_dns_traffic` extracts queries, response codes, NXDOMAINs, and detects DNS tunneling
- **Expert information** — `get_expert_info` extracts Wireshark expert warnings, errors, and protocol violation notes
- **Large PCAP streaming** — `analyze_large_pcap` processes large files in memory-efficient chunks
- **Dynamic system/info resource** — `netmcp://system/info` auto-lists all registered tools
- Total tools now **40** (was 25), across **9 categories** and **11 modules**
- **564 tests** achieving **95%+ code coverage**

### Changed

- Upgraded test suite from 270+ tests (89%) to 564 tests (95%+)
- Reorganized tool categories: added Network Flows, PCAP Tools, Wireshark Profiles categories
- Updated documentation: API reference, README, COMPARISON, and CHANGELOG reflect all 40 tools

## [0.2.0] — 2026-04-03

### Added

- **New tools**: `quick_capture`, `save_capture_to_file`, `analyze_http_headers`, `geoip_lookup`, `capture_targeted_traffic` — total now 25 tools
- **New prompts**: `traffic_analysis` and `network_baseline` guided workflows — total now 5 prompts
- **GeoIP enrichment** via MaxMind GeoLite2 database for IP geolocation
- **HTTP header analysis** — extract auth tokens, cookies, suspicious headers, user agents
- **Rate limiting** with thread-safe sliding window (30/hr captures, 10/hr scans, 100/hr threat checks)
- **Audit logging** for all sensitive operations with automatic credential masking
- **Structured error codes** (NETMCP_001 through NETMCP_008) with auto-mapped exception types
- **Comprehensive CI/CD pipeline** — GitHub Actions with lint, type check, test matrix (Python 3.11/3.12/3.13)
- **Docker support** — multi-stage Dockerfile for containerized deployment
- **Pre-commit hooks** — ruff + mypy integration
- **Tool annotations** — `readOnly`, `destructive`, `idempotent`, `openWorld` metadata on all tools
- **Documentation**: API reference (`docs/API.md`), architecture (`docs/ARCHITECTURE.md`), comparison (`docs/COMPARISON.md`)
- **270+ tests** achieving **89% code coverage** across all layers

### Changed

- Upgraded test suite from 199 tests (76%) to 270+ tests (89%)
- Improved OutputFormatter with table rendering and configurable truncation
- Enhanced ThreatIntelInterface with LRU cache eviction (max 10,000 entries)
- Refined Nmap argument validation with explicit allowlist/blocklist approach
- Updated GitHub Actions to latest versions (checkout@v5, setup-python@v6, upload-artifact@v5)

### Fixed

- **Security bypass** in file path validation — now resolves symlinks and checks traversal
- **Resource leaks** in subprocess execution — proper cleanup on timeout
- **BPF filter validation** — reject shell metacharacters in capture filters
- **Deprecated API usage** — migrated from deprecated `Optional[]` to `X | None` syntax
- **Nmap test compatibility** — mocked filesystem operations for CI environments
- **Display filter injection** — added metacharacter rejection for display filters
- Lint compliance with ruff (E, W, F, I, N, UP, B, A, C4, SIM, RUF rules)

### Security

- **5-layer defense model**: input validation → command construction → subprocess execution → filesystem → rate limiting
- `shell=False` enforced in ALL subprocess calls (prevents command injection)
- Dangerous Nmap flags blocklist (`--script-args`, `--interactive`, `--privileged`, etc.)
- Path traversal protection with `Path.resolve()` + symlink detection + extension allowlist
- Sensitive fields (`password`, `secret`, `key`, `token`) automatically stripped from audit logs
- File size limit enforcement (100 MB max for PCAP files)
- Network interface name validation with strict regex

## [0.1.0] — 2026-04-03

### Added

- **Core architecture**: `SecurityValidator` + `OutputFormatter` with 78 passing tests
- **Interfaces**: `TsharkInterface` (async tshark wrapper), `NmapInterface` (python-nmap), `ThreatIntelInterface` (URLhaus + AbuseIPDB)
- **23 MCP tools** across 7 categories:
  - Packet Capture: `get_network_interfaces`, `capture_live_packets`
  - Analysis: `analyze_pcap_file`, `get_protocol_statistics`, `get_capture_file_info`, `analyze_http_traffic`, `detect_network_protocols`
  - Streams: `follow_tcp_stream`, `follow_udp_stream`, `list_tcp_streams`
  - Export: `export_packets_json`, `export_packets_csv`, `convert_pcap_format`
  - Nmap: `nmap_port_scan`, `nmap_service_detection`, `nmap_os_detection`, `nmap_vulnerability_scan`, `nmap_quick_scan`, `nmap_comprehensive_scan`
  - Threat Intel: `check_ip_threat_intel`, `scan_capture_for_threats`
  - Credentials: `extract_credentials` (HTTP Basic, FTP, Telnet, Kerberos)
- **3 MCP resources**: `netmcp://interfaces`, `netmcp://captures`, `netmcp://system/info`
- **3 MCP prompts**: `security_audit`, `network_troubleshooting`, `incident_response`
- **CLI entry point**: `netmcp` command (stdio transport by default)
- **Kerberos hash extraction** with hashcat-ready output (modes 7500, 18200)
- **URLhaus + AbuseIPDB** threat intelligence with in-memory caching
- 199 tests with 76% code coverage
- MIT License

[Unreleased]: https://github.com/cortexc0de/netmcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/cortexc0de/netmcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cortexc0de/netmcp/releases/tag/v0.1.0
