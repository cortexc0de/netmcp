# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-03

### Added

#### MCP Tools (27)

- **Packet Capture** — `capture_start`, `capture_stop`, `capture_list_interfaces`, `capture_status`, `capture_info`
- **Traffic Analysis** — `dns_analysis`, `http_analysis`, `tcp_analysis`, `protocol_distribution`, `connection_analysis`
- **Nmap Scanning** — `nmap_scan`, `nmap_service_detect`, `nmap_os_detect`, `nmap_vuln_scan`, `nmap_discovery`
- **Threat Intelligence** — `threat_intel_ip`, `threat_intel_domain`, `threat_intel_url`, `threat_intel_hash`, `threat_intel_enrich`
- **Stream Operations** — `stream_list`, `stream_follow`, `stream_export`
- **Export** — `export_pcap`, `export_csv`, `export_json`
- **Credentials** — `credentials_extract`, `credentials_analyze`
- **Network Info** — `network_info`

#### MCP Prompts (5)

- `security_audit` — Guided security audit workflow
- `network_troubleshooting` — Step-by-step network troubleshooting
- `incident_response` — Incident response investigation workflow
- `traffic_analysis` — Network traffic analysis and anomaly detection
- `network_baseline` — Network baseline establishment and monitoring

#### MCP Resources (3)

- Network configuration and interface details
- Active capture session information
- Protocol statistics and summaries

#### Features

- GeoIP enrichment for IP addresses using MaxMind GeoLite2 database
- HTTP header analysis for security-relevant headers
- Structured input validation with Pydantic models
- Async tool execution for responsive operation
- Comprehensive error handling and reporting
- Environment variable configuration system
- CLI entry point (`netmcp` command)

#### Testing & CI/CD

- 199 tests covering tools, analysis, capture, threat intelligence, and server
- 76% code coverage
- GitHub Actions CI/CD pipeline with linting, type checking, and test matrix
- pytest-asyncio for async test support
- Ruff for linting and formatting
- mypy for type checking

### Security

- MIT license
- No hardcoded credentials or secrets
- Input validation on all tool parameters
- Least-privilege network permission support (Linux capabilities)

### Documentation

- README with project overview and quick start
- Tool, prompt, and resource reference tables
- Installation prerequisites guide

---

[Unreleased]: https://github.com/luxvtz/netmcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/luxvtz/netmcp/releases/tag/v0.1.0
