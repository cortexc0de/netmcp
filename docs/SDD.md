# System Design Document (SDD) — NetMCP

## 1. Overview

NetMCP is a professional-grade Model Context Protocol (MCP) server that provides AI assistants with comprehensive network analysis capabilities. It integrates Wireshark/TShark, Nmap, and threat intelligence APIs into a modular, secure, and extensible Python package.

## 2. Technology Stack

| Layer | Technology | Version | Justification |
|---|---|---|---|
| Runtime | Python | 3.11+ | Async/await, rich ecosystem for network tools |
| MCP Framework | FastMCP (from `mcp` SDK) | >=1.0.0 | Decorator-based, auto-schema, official SDK |
| HTTP Client | httpx | >=0.27.0 | Native async, HTTP/2, better than requests |
| HTTP Cache | httpx-cache | >=0.6.0 | Transparent caching for threat intel APIs |
| Nmap Wrapper | python-nmap | >=0.7.1 | Mature, well-tested Nmap bindings |
| Validation | Pydantic | >=2.0.0 | Built into FastMCP, runtime validation |
| Testing | pytest + pytest-asyncio | >=8.0 | Industry standard, async support |
| Linting | ruff + mypy | latest | Fast linting, type checking |

## 3. Package Structure

```
src/netmcp/
├── __init__.py              # Package metadata, version
├── server.py                # Main entry point: FastMCP server, registration orchestration
│
├── core/
│   ├── __init__.py
│   ├── security.py          # SecurityValidator: input validation, sanitization, rate limiting
│   └── formatter.py         # OutputFormatter: JSON/text response formatting
│
├── interfaces/
│   ├── __init__.py
│   ├── tshark.py            # TsharkInterface: tshark CLI wrapper (capture, analyze, streams)
│   ├── nmap.py              # NmapInterface: python-nmap wrapper (scan, detect, fingerprint)
│   └── threat_intel.py      # ThreatIntelInterface: URLhaus + AbuseIPDB API clients
│
├── tools/
│   ├── __init__.py
│   ├── capture.py           # get_interfaces, capture_live_packets
│   ├── analysis.py          # analyze_pcap, protocol_stats, file_info, targeted_capture, http_analysis, protocol_detect
│   ├── streams.py           # follow_tcp_stream, follow_udp_stream, list_streams
│   ├── export.py            # export_json, export_csv, convert_pcap
│   ├── nmap_scan.py         # port_scan, service_detect, os_detect, vuln_scan, quick_scan, comprehensive
│   ├── threat_intel.py      # check_ip_threat, scan_pcap_threats
│   └── credentials.py       # extract_credentials (HTTP Basic, FTP, Telnet, Kerberos)
│
├── resources/
│   ├── __init__.py
│   ├── interfaces_res.py    # netmcp://interfaces/ — dynamic interface list
│   ├── captures_res.py      # netmcp://captures/ — available PCAP files
│   └── system_info.py       # netmcp://system/info — tool versions, capabilities
│
├── prompts/
│   ├── __init__.py
│   └── workflows.py         # security_audit, network_troubleshooting, incident_response
│
└── utils/
    ├── __init__.py
    └── helpers.py           # Common utilities: find_binary, run_subprocess, etc.
```

## 4. Module Specifications

### 4.1 Core: SecurityValidator

```python
class SecurityValidator:
    def validate_interface(name: str) -> str          # Regex + known interfaces
    def validate_target(target: str) -> str            # IP/CIDR/hostname via ipaddress
    def validate_port_range(ports: str) -> str         # Format "1-65535,80,443"
    def validate_capture_filter(bpf: str) -> str       # Reject dangerous chars
    def validate_display_filter(dfilter: str) -> str   # Wireshark display filter
    def sanitize_filepath(path: str) -> Path           # Resolve, check extension, size
    def check_rate_limit(operation: str) -> bool       # Max 10 nmap/hour
    def is_privileged() -> bool                        # Check root/sudo
```

### 4.2 Core: OutputFormatter

```python
class OutputFormatter:
    def format_json(data: Any) -> str                  # Structured JSON output
    def format_text(data: Any) -> str                  # Human-readable text
    def format_error(error: Exception) -> dict          # Standardized error response
    def format_table(rows: list, headers: list) -> str  # ASCII table output
    def truncate(text: str, max_chars: int = 72000) -> str  # Response size limiter
```

### 4.3 Interface: TsharkInterface

```python
class TsharkInterface:
    """Wraps tshark CLI. All subprocess calls use shell=False with list args."""

    def __init__(self, tshark_path: str | None = None)
    async def capture_live(iface: str, bpf: str, count: int, timeout: float) -> bytes
    async def capture_to_file(iface: str, output: str, bpf: str, duration: int, count: int) -> Path
    async def read_pcap(filepath: str, dfilter: str, max_packets: int) -> list[dict]
    async def protocol_stats(filepath: str) -> dict                       # io,phs
    async def file_info(filepath: str) -> dict                            # capinfos
    async def follow_stream(filepath: str, stream_idx: int, proto: str, fmt: str) -> str
    async def list_streams(filepath: str, proto: str) -> list[dict]       # -z conv,tcp
    async def export_json(filepath: str, dfilter: str, max_packets: int) -> list[dict]
    async def export_fields(filepath: str, fields: list, dfilter: str) -> list[dict]
    async def extract_credentials(filepath: str) -> dict                   # HTTP/FTP/Telnet/Kerberos
```

### 4.4 Interface: NmapInterface

```python
class NmapInterface:
    """Wraps python-nmap. Never auto-escalates privileges."""

    def __init__(self)
    async def port_scan(target: str, ports: str, scan_type: str, args: str) -> dict
    async def service_detect(target: str, ports: str) -> dict
    async def os_detect(target: str) -> dict
    async def vuln_scan(target: str, ports: str) -> dict
    async def quick_scan(target: str) -> dict
    async def comprehensive_scan(target: str) -> dict
```

### 4.5 Interface: ThreatIntelInterface

```python
class ThreatIntelInterface:
    """URLhaus (no key) + AbuseIPDB (requires API key). Responses cached 1hr."""

    def __init__(self, abuseipdb_key: str | None = None)
    async def check_ip(ip: str, providers: list[str] = ["urlhaus", "abuseipdb"]) -> dict
    async def check_pcap(filepath: str, providers: list[str]) -> dict       # Extract IPs, check each
```

### 4.6 Tools Registry (24 tools)

| # | Tool | Category | Description |
|---|---|---|---|
| 1 | `get_network_interfaces` | Capture | List available network interfaces |
| 2 | `capture_live_packets` | Capture | Live packet capture with BPF filter |
| 3 | `analyze_pcap_file` | Analysis | Analyze PCAP with display filters |
| 4 | `get_protocol_statistics` | Analysis | Protocol hierarchy + IP conversations |
| 5 | `get_capture_file_info` | Analysis | PCAP metadata via capinfos |
| 6 | `capture_targeted_traffic` | Analysis | Capture by host/port/protocol |
| 7 | `analyze_http_traffic` | Analysis | HTTP methods, hosts, status codes |
| 8 | `detect_network_protocols` | Analysis | Protocol detection with insights |
| 9 | `follow_tcp_stream` | Streams | Reconstruct TCP conversation |
| 10 | `follow_udp_stream` | Streams | Reconstruct UDP conversation |
| 11 | `list_tcp_streams` | Streams | List all TCP conversations |
| 12 | `export_packets_json` | Export | Export packets to JSON |
| 13 | `export_packets_csv` | Export | Export custom fields to CSV |
| 14 | `convert_pcap_format` | Export | Convert pcap ↔ pcapng |
| 15 | `nmap_port_scan` | Nmap | SYN/connect/UDP port scanning |
| 16 | `nmap_service_detection` | Nmap | Service version detection |
| 17 | `nmap_os_detection` | Nmap | OS fingerprinting |
| 18 | `nmap_vulnerability_scan` | Nmap | NSE vulnerability scripts |
| 19 | `nmap_quick_scan` | Nmap | Top 100 ports |
| 20 | `nmap_comprehensive_scan` | Nmap | Full scan with all features |
| 21 | `check_ip_threat_intel` | Threat | IP threat check (URLhaus+AbuseIPDB) |
| 22 | `scan_capture_for_threats` | Threat | Extract + check all IPs from PCAP |
| 23 | `extract_credentials` | Security | Extract HTTP/FTP/Telnet/Kerberos creds |

### 4.7 Resources (3)

| URI | Description |
|---|---|
| `netmcp://interfaces/` | Dynamic list of network interfaces |
| `netmcp://captures/` | Available PCAP files in common directories |
| `netmcp://system/info` | System capabilities: tshark/nmap versions, available tools |

### 4.8 Prompts (3)

| Name | Description |
|---|---|
| `security_audit` | Guided security analysis workflow for PCAP files |
| `network_troubleshooting` | Network diagnostics workflow |
| `incident_response` | Security incident investigation workflow |

## 5. Data Flow

### Tool Invocation Path

```
Client → FastMCP → @mcp.tool decorated function
                  → SecurityValidator.validate_*()  [Layer 1]
                  → Interface (Tshark/Nmap/Threat)   [Layer 2]
                  → subprocess (shell=False)          [Layer 3]
                  → OutputFormatter                   [Layer 4]
                  → MCP Response
```

### Threat Intel Path

```
Client → check_ip_threat_intel()
       → SecurityValidator.validate_target()
       → ThreatIntelInterface.check_ip()
         → URLhaus API (no key, cached 1hr)
         → AbuseIPDB API (key required, cached 1hr)
       → Aggregate results
       → OutputFormatter.format_json()
       → MCP Response
```

## 6. Security Model

| Layer | Mechanism | Prevents |
|---|---|---|
| 1. Input Validation | Regex, ipaddress module, Pydantic | Malformed input |
| 2. Command Construction | List args, shell=False | Command injection |
| 3. Subprocess Execution | Timeouts, captured output | Shell injection |
| 4. File System | Path.resolve(), extension check | Path traversal |
| 5. Rate Limiting | Operation tracking, time windows | Abuse/DoS |

## 7. Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | No | None | AbuseIPDB API key for threat intel |
| `NETMCP_TSHARK_PATH` | No | None | Custom tshark binary path |
| `NETMCP_MAX_PACKETS` | No | 10000 | Max packets per capture |
| `NETMCP_MAX_FILE_SIZE` | No | 104857600 | Max PCAP file size (100MB) |
| `NETMCP_CAPTURE_TIMEOUT` | No | 300 | Max capture duration (seconds) |
| `NETMCP_NMAP_RATE_LIMIT` | No | 10 | Max nmap scans per hour |

## 8. Testing Strategy

| Test Type | Scope | Tools | Coverage Target |
|---|---|---|---|
| Unit | Individual functions | pytest, pytest-mock | 80%+ |
| Integration | Tool workflows | pytest-asyncio | All tools |
| Security | Injection attempts | Custom test cases | All vectors |
| E2E | Full server lifecycle | FastMCP test client | All flows |

### Test Fixtures
- `test_pcap.pcap` — Small PCAP with HTTP, DNS, TCP traffic (generated with scapy)
- `mock_tshark_output` — Dict of mocked tshark JSON responses
- `mock_nmap_output` — Dict of mocked nmap XML/JSON responses

## 9. Error Handling

All errors follow a standardized format:

```python
{
    "content": [{"type": "text", "text": "Error description"}],
    "isError": True
}
```

Error codes (embedded in text):
- `NETMCP_001` — Tool not found
- `NETMCP_002` — Invalid input parameters
- `NETMCP_003` — External tool not available (tshark/nmap)
- `NETMCP_004` — File not found or inaccessible
- `NETMCP_005` — Capture/scan timed out
- `NETMCP_006` — Rate limit exceeded
- `NETMCP_007` — Permission denied
