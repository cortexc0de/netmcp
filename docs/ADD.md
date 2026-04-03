# Architecture Decision Document (ADD)

**Project**: netmcp -- Professional Network Analysis MCP Server  
**Version**: 1.0  
**Status**: Proposed  
**Date**: 2026-04-03  
**Authors**: netmcp contributors  

---

## Table of Contents

1. [System Context](#1-system-context)
2. [Quality Goals](#2-quality-goals)
3. [Architectural Decisions](#3-architectural-decisions)
4. [Module Decomposition and Dependencies](#4-module-decomposition-and-dependencies)
5. [Deployment View](#5-deployment-view)
6. [Cross-Cutting Concerns](#6-cross-cutting-concerns)
7. [Risks and Technical Debt](#7-risks-and-technical-debt)

---

## 1. System Context

### 1.1 What is netmcp

netmcp is a professional-grade Model Context Protocol (MCP) server that provides AI assistants with comprehensive network analysis capabilities. It unifies the strongest capabilities found across three predecessor projects:

| Source Project | Key Contribution |
|---|---|
| **WireMCP** (Node.js) | Credential extraction from PCAP files (HTTP Basic Auth, FTP, Telnet, Kerberos), URLhaus threat intelligence lookups |
| **Wireshark-MCP** (Python) | Modular layered architecture, nmap integration, MCP resources and prompts, 5-layer security model, structured tool registration |
| **wireshark-mcp** (Python/PyShark) | Targeted traffic capture with BPF filters, HTTP traffic analysis, protocol detection, file-based capture workflows |

netmcp consolidates these into a single Python-based server built on FastMCP (from the official MCP SDK), offering approximately 25 tools, 4+ resources, and 3+ prompts for guided workflows.

### 1.2 Stakeholders and Users

| Role | Description |
|---|---|
| **Security Analyst** | Uses netmcp to analyze suspicious PCAP files, extract credentials, check IPs against threat feeds, and run vulnerability scans |
| **Network Engineer** | Uses netmcp for live traffic capture, protocol detection, stream following, and network troubleshooting |
| **Incident Responder** | Uses guided prompts (incident_response) to systematically investigate security incidents using capture analysis, threat intel, and stream reconstruction |
| **LLM Client** | AI assistant (Claude, Cursor, etc.) that invokes netmcp tools via MCP to perform network analysis on behalf of the human user |
| **Developer/Contributor** | Extends netmcp by adding new tools, interfaces, or resources following the established module patterns |

### 1.3 System Boundary and External Dependencies

```
                    ┌──────────────────────────────────────┐
                    │           LLM Client                  │
                    │  (Claude, Cursor, MCP Inspector)      │
                    └──────────────────┬───────────────────┘
                                       │ MCP protocol (stdio)
                    ┌──────────────────▼───────────────────┐
                    │            netmcp server              │
                    │                                       │
                    │  Tools │ Resources │ Prompts          │
                    └──┬──┬──┬──┴──┬──┬────┴──┬────────────┘
                       │  │  │     │  │       │
         ┌─────────────┘  │  │     │  │       └──────────────┐
         │                │  │     │  │                       │
    ┌────▼─────┐    ┌─────▼──▼─┐  │  │                  ┌────▼─────┐
    │ tshark   │    │  nmap    │  │  │                  │ httpx    │
    │ CLI      │    │ CLI      │  │  │                  │ (async)  │
    └──────────┘    └──────────┘  │  │                  └────┬─────┘
                                  │  │                       │
                         ┌────────▼──▼──────┐          ┌────▼────────┐
                         │ External APIs    │          │ URLhaus     │
                         │ - URLhaus        │          │ AbuseIPDB   │
                         │ - AbuseIPDB      │          │ (threat DB) │
                         └──────────────────┘          └─────────────┘
```

**External dependencies** (must be installed on the host system):

- **tshark** (Wireshark CLI) -- packet capture, PCAP analysis, stream following, protocol statistics
- **nmap** -- port scanning, service detection, OS fingerprinting, vulnerability scanning (optional but recommended)
- **dumpcap** -- low-level packet capture (installed with Wireshark)

**External network services**:

- **URLhaus** (https://urlhaus.abuse.ch/) -- threat intelligence feed (no API key required)
- **AbuseIPDB** (https://www.abuseipdb.com/) -- IP reputation checks (free API key required)

### 1.4 Operating Environment

netmcp runs as a local MCP server communicating over stdio. It requires:

- Python 3.11+ on Linux, macOS, or Windows
- Read/write access to PCAP files on the local filesystem
- Network interface with promiscuous mode capability for live capture
- Appropriate privileges for packet capture (see Section 5)

---

## 2. Quality Goals

### 2.1 Performance

| Goal | Target | Rationale |
|---|---|---|
| Tool response time | < 5 seconds for analysis tools, < 30 seconds for capture/scan tools | LLM clients expect timely responses; captures and scans are inherently slower |
| Concurrent tool calls | Up to 4 via ThreadPoolExecutor | Prevents resource contention while allowing parallel analysis |
| PCAP file size limit | 100 MB maximum | Prevents memory exhaustion on large captures |
| Packet count limit | 10,000 packets per analysis | Balances detail with response size constraints |
| Capture duration limit | 300 seconds maximum | Prevents indefinite resource consumption |

### 2.2 Security

netmcp implements a **5-layer defense-in-depth model**:

| Layer | Mechanism | What It Prevents |
|---|---|---|
| **1. Input Validation** | Regex patterns, `ipaddress` module validation, BPF filter sanitization, file path checks, port range validation | Malformed inputs, injection payloads, out-of-range values |
| **2. Safe Subprocess** | `shell=False` enforced in ALL subprocess calls; list-based command construction; no string interpolation into commands | Command injection, shell metacharacter exploitation |
| **3. Rate Limiting** | Operation history tracking with configurable limits per time window (e.g., max 10 nmap scans/hour) | Abuse, denial-of-service via repeated scans |
| **4. Privilege Detection** | Detects when root/sudo is required; never auto-escalates; returns clear error messages | Silent privilege escalation, unexpected permission errors |
| **5. Path Sanitization** | Resolves absolute paths, restricts to allowed directories, validates file extensions (.pcap, .pcapng) | Path traversal, arbitrary file access, non-capture file reads |

### 2.3 Maintainability

| Goal | Approach |
|---|---|
| Single Responsibility | Each module has one clear purpose (interfaces wrap CLIs, tools orchestrate workflows, core provides shared utilities) |
| Consistent patterns | All tools follow the same registration pattern: `register_<category>_tools(mcp, interfaces, executor)` |
| Type hints | Full type annotations on all public functions and interfaces |
| Testability | Interfaces are abstracted behind classes that can be mocked; subprocess calls are isolated for unit testing |
| No circular dependencies | Dependency flow: core <- interfaces <- tools <- server (strict DAG) |

### 2.4 Extensibility

| Goal | Approach |
|---|---|
| Adding tools | Create a module in `tools/`, define a `register_*_tools()` function, import and call in `server.py` |
| Adding interfaces | Create a module in `interfaces/`, initialize in server constructor, pass to relevant tool registrations |
| Adding resources | Add `@mcp.resource()` decorated functions or create a resource module with a registration function |
| Adding prompts | Add `@mcp.prompt()` decorated functions or create a prompt module |
| Adding threat intel providers | Implement a new provider class following the `ThreatProvider` protocol; register in `ThreatIntelInterface` |

---

## 3. Architectural Decisions

### Decision 3.1: Python as Primary Language

**Chosen: Python 3.11+**

**Alternatives considered**: Node.js (from WireMCP), Go, Rust

**Rationale**:

- The strongest architectural patterns come from the Python-based Wireshark-MCP project, which already implements the modular layered architecture, MCP resources/prompts, and 5-layer security model
- The MCP SDK provides first-class Python support via `mcp.server.fastmcp` (FastMCP), which offers decorator-based tool/resource/prompt registration with minimal boilerplate
- Rich ecosystem for network analysis: pyshark (Python wrapper for tshark), python-nmap, scapy
- Async support via `asyncio` for concurrent threat intel API calls
- Python 3.11+ provides significant performance improvements (10-60% faster than 3.10) and exception groups for better error handling
- The Node.js WireMCP implementation has several production concerns: it uses `exec` with string interpolation for tshark commands (command injection risk), has no rate limiting, and lacks the modular architecture
- Go and Rust would require wrapping tshark/nmap CLIs from scratch with no existing Python-like wrapper ecosystem

**Consequences**:

- Requires Python 3.11+ runtime on the host system
- Leverages mature Python libraries rather than reimplementing packet analysis
- Enables rapid development and prototyping

### Decision 3.2: FastMCP as MCP Framework

**Chosen: `mcp.server.fastmcp.FastMCP` from the official MCP SDK**

**Alternatives considered**: Low-level MCP server builder, custom protocol implementation

**Rationale**:

- FastMCP provides the simplest path to defining tools, resources, and prompts via decorators (`@mcp.tool`, `@mcp.resource`, `@mcp.prompt`)
- Built-in lifespan management via `@asynccontextmanager` for initialization and cleanup
- Native support for `Context` objects providing logging, progress reporting, and lifespan context access
- The wireshark-mcp (PyShark) project already demonstrates FastMCP working correctly with pyshark
- Official Anthropic-maintained library with active development

**Consequences**:

- Tied to the MCP SDK's feature set; custom protocol extensions require dropping to lower-level APIs
- FastMCP's decorator approach means tool definitions are co-located with implementation (good for readability, requires careful module organization)

### Decision 3.3: tshark CLI Wrapper Over PyShark Library

**Chosen: Direct tshark CLI wrapper via `subprocess`**

**Alternatives considered**: PyShark library (used in wireshark-mcp), raw pcap file parsing

**Rationale**:

- PyShark is a thin wrapper around tshark that introduces additional overhead and complexity; it still depends on tshark being installed
- Direct CLI wrapper gives full control over command construction, timeout handling, and error parsing
- PyShark has known issues with async operation and can block the event loop
- Direct subprocess with `shell=False` is the security-preferred approach (established in Wireshark-MCP)
- tshark supports the full range of operations needed: live capture (`-i`), file read (`-r`), JSON output (`-T json`), field extraction (`-T fields`), statistics (`-z`), stream following (`-z follow,*`)
- The WireMCP Node.js project demonstrates that direct tshark CLI usage works reliably across platforms

**Consequences**:

- Requires tshark to be installed and in PATH
- Need to handle platform-specific path resolution for tshark binary
- Output parsing must handle tshark's text/JSON output format
- Cannot use PyShark's convenient Python object model for packet inspection

### Decision 3.4: Modular Layered Architecture

**Chosen: 5-layer module structure (core/ interfaces/ tools/ resources/ prompts/)**

**Alternatives considered**: Flat module structure, single-file server

**Rationale**:

- The Wireshark-MCP architecture demonstrates a well-thought-out layered design with clear separation of concerns
- The `core/` layer holds cross-cutting concerns (security validation, output formatting) used by all tools
- The `interfaces/` layer isolates external system interactions (tshark, nmap, threat APIs) making them independently testable and replaceable
- The `tools/` layer contains the business logic that combines interfaces into MCP tool implementations
- Resources and prompts are separated as they serve different MCP protocol functions
- This structure makes it trivial to identify where new functionality belongs

**Consequences**:

- More files and imports to manage compared to a single-file approach
- Requires disciplined adherence to the dependency direction (tools depend on interfaces, not vice versa)

### Decision 3.5: httpx for Threat Intelligence APIs

**Chosen: `httpx` (async HTTP client)**

**Alternatives considered**: `aiohttp`, `requests`, `urllib`

**Rationale**:

- httpx provides a modern async API compatible with `asyncio`, matching FastMCP's async nature
- httpx has a requests-compatible synchronous API for simplicity when async is not needed
- Built-in support for connection pooling, timeouts, and HTTP/2
- The WireMCP project uses `axios` (Node.js); httpx is the closest Python equivalent in design philosophy
- `requests` is synchronous and would block the event loop in an async MCP server
- `aiohttp` has a more complex API and is not needed for the simple GET/POST operations required

**Consequences**:

- Adds httpx as a dependency
- Need to manage httpx `AsyncClient` lifecycle (creation/cleanup) within the FastMCP lifespan

### Decision 3.6: python-nmap for Nmap Integration

**Chosen: `python-nmap` library**

**Alternatives considered**: Direct nmap CLI wrapper, custom XML parsing

**Rationale**:

- python-nmap provides a clean Python interface to nmap, handling XML output parsing automatically
- Supports all scan types needed: SYN, connect, UDP, service detection, OS detection, NSE scripts
- The Wireshark-MCP project already designed the interface layer around python-nmap patterns
- Direct CLI wrapping would require parsing nmap's XML output manually, which is error-prone

**Consequences**:

- python-nmap must be installed (`pip install python-nmap`)
- nmap binary must be installed on the host system
- Some scan types (SYN, OS detection) require root privileges

---

## 4. Module Decomposition and Dependencies

### 4.1 Package Structure

```
netmcp/
├── pyproject.toml                    # Project metadata, dependencies, entry points
├── README.md                         # User-facing documentation
├── docs/
│   └── ADD.md                        # This document
├── src/
│   └── netmcp/
│       ├── __init__.py               # Package version, exports
│       ├── server.py                 # Main orchestration: FastMCP init, interface setup, registration
│       │
│       ├── core/
│       │   ├── __init__.py
│       │   ├── security.py           # Input validation, sanitization, rate limiting, privilege detection
│       │   └── output_formatter.py   # Response formatting, JSON/text conversion, error standardization
│       │
│       ├── interfaces/
│       │   ├── __init__.py
│       │   ├── tshark_interface.py   # tshark CLI wrapper: capture, analysis, streams, stats
│       │   ├── nmap_interface.py     # nmap wrapper via python-nmap: scans, detection, vuln checks
│       │   └── threat_intel_interface.py  # httpx-based: URLhaus, AbuseIPDB API clients
│       │
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── capture.py            # get_network_interfaces, capture_live_packets, capture_to_file
│       │   ├── analysis.py           # analyze_pcap, get_protocol_statistics, get_capture_file_info
│       │   ├── network_streams.py    # follow_tcp_stream, follow_udp_stream, list_tcp_streams
│       │   ├── export.py             # export_packets_json, export_packets_csv, convert_pcap_format
│       │   ├── nmap_scan.py          # nmap_port_scan, nmap_service_detection, nmap_os_detection, nmap_vulnerability_scan, nmap_quick_scan, nmap_comprehensive_scan
│       │   ├── threat_intel.py       # check_ip_threat_intel, scan_capture_for_threats
│       │   ├── credentials.py        # extract_credentials (HTTP Basic, FTP, Telnet, Kerberos)
│       │   └── targeted_capture.py   # capture_targeted_traffic, analyze_http_traffic, detect_protocols
│       │
│       ├── resources/
│       │   ├── __init__.py
│       │   ├── interface_resource.py # netmcp://interfaces/ - available network interfaces
│       │   ├── capture_resource.py   # netmcp://captures/ - available PCAP files
│       │   ├── system_resource.py    # netmcp://system/info - system capabilities, tool versions
│       │   └── help_resource.py      # netmcp://help - tool documentation
│       │
│       └── prompts/
│           ├── __init__.py
│           ├── security_audit.py     # Guided security analysis workflow
│           ├── network_troubleshooting.py  # Network diagnostics workflow
│           └── incident_response.py  # Security incident investigation workflow
│
└── tests/
    ├── __init__.py
    ├── conftest.py                   # Shared fixtures, mock subprocess setup
    ├── test_security.py              # SecurityValidator unit tests
    ├── test_tshark_interface.py      # tshark wrapper tests with mocked subprocess
    ├── test_nmap_interface.py        # nmap wrapper tests
    ├── test_threat_intel.py          # Threat API tests with mocked httpx
    ├── test_tools_capture.py         # Capture tool tests
    ├── test_tools_analysis.py        # Analysis tool tests
    ├── test_tools_nmap.py            # Nmap scan tool tests
    ├── test_tools_credentials.py     # Credential extraction tests
    └── test_server.py                # Integration tests for full MCP server
```

### 4.2 Module Dependencies

```
                    ┌─────────────┐
                    │   server.py │
                    └──────┬──────┘
                           │ imports and wires
           ┌───────────────┼───────────────────┐
           │               │                   │
    ┌──────▼──────┐ ┌──────▼──────┐    ┌───────▼───────┐
    │   tools/    │ │ resources/  │    │   prompts/    │
    └──────┬──────┘ └─────────────┘    └───────────────┘
           │ depends on
    ┌──────▼──────────────────────────────┐
    │          interfaces/                 │
    │  ┌──────────┬──────────┬──────────┐ │
    │  │ tshark   │ nmap     │ threat   │ │
    │  │_interface│_interface│_intel    │ │
    │  └──────────┴──────────┴──────────┘ │
    └──────────────────┬──────────────────┘
                       │ uses
              ┌────────▼────────┐
              │     core/       │
              │  ┌────────────┐ │
              │  │ security   │ │
              │  │ output_fmt │ │
              │  └────────────┘ │
              └─────────────────┘
```

**Dependency rules** (enforced by import conventions):

1. `server.py` imports from all layers (orchestration responsibility)
2. `tools/` imports from `interfaces/` and `core/` only
3. `resources/` imports from `interfaces/` and `core/` only
4. `prompts/` has no imports from other netmcp layers (self-contained templates)
5. `interfaces/` imports from `core/` only
6. `core/` has no internal netmcp imports (stdlib and third-party only)
7. No circular imports permitted

### 4.3 Interface Specifications

#### 4.3.1 TsharkInterface

```python
class TsharkInterface:
    """Wraps tshark CLI for packet capture and analysis."""

    def __init__(self, tshark_path: str | None = None): ...

    # Capture
    async def list_interfaces(self) -> list[Interface]: ...
    async def capture_live(self, interface: str, count: int, bpf_filter: str, timeout: float) -> CaptureResult: ...
    async def capture_to_file(self, interface: str, output_path: Path, bpf_filter: str, duration: float, packet_limit: int | None) -> CaptureResult: ...

    # Analysis
    async def analyze_pcap(self, filepath: Path, display_filter: str, max_packets: int) -> AnalysisResult: ...
    async def get_protocol_statistics(self, filepath: Path) -> ProtocolStats: ...
    async def get_capture_file_info(self, filepath: Path) -> FileInfo: ...

    # Streams
    async def follow_tcp_stream(self, filepath: Path, stream_index: int, output_format: str) -> str: ...
    async def follow_udp_stream(self, filepath: Path, stream_index: int, output_format: str) -> str: ...
    async def list_tcp_streams(self, filepath: Path) -> list[StreamInfo]: ...

    # Export
    async def export_json(self, filepath: Path, display_filter: str, max_packets: int) -> str: ...
    async def export_csv(self, filepath: Path, fields: list[str], display_filter: str) -> str: ...

    # Credentials
    async def extract_credentials(self, filepath: Path) -> CredentialReport: ...

    # IP extraction for threat checks
    async def extract_ips(self, filepath: Path) -> set[str]: ...
```

#### 4.3.2 NmapInterface

```python
class NmapInterface:
    """Wraps nmap via python-nmap for network scanning."""

    def __init__(self): ...

    async def port_scan(self, target: str, ports: str, scan_type: str) -> ScanResult: ...
    async def service_detection(self, target: str, ports: str) -> ScanResult: ...
    async def os_detection(self, target: str) -> ScanResult: ...
    async def vulnerability_scan(self, target: str, ports: str) -> ScanResult: ...
    async def quick_scan(self, target: str) -> ScanResult: ...
    async def comprehensive_scan(self, target: str) -> ScanResult: ...
```

#### 4.3.3 ThreatIntelInterface

```python
class ThreatIntelInterface:
    """Async HTTP client for threat intelligence APIs."""

    def __init__(self, abuseipdb_api_key: str | None = None, cache_ttl: float = 3600.0): ...

    async def check_ip(self, ip: str, providers: list[str] | None = None) -> ThreatReport: ...
    async def check_ips(self, ips: set[str], providers: list[str] | None = None) -> dict[str, ThreatReport]: ...
```

#### 4.3.4 SecurityValidator

```python
class SecurityValidator:
    """5-layer security enforcement."""

    def validate_interface(self, interface: str, available: list[str]) -> str: ...
    def validate_target(self, target: str) -> str: ...
    def validate_port_range(self, ports: str) -> str: ...
    def validate_bpf_filter(self, filter_expr: str) -> str: ...
    def validate_display_filter(self, filter_expr: str) -> str: ...
    def sanitize_filepath(self, filepath: str, allowed_dirs: list[Path] | None = None) -> Path: ...
    def validate_ip(self, ip: str) -> str: ...
    def check_rate_limit(self, operation: str, max_ops: int, window_seconds: float) -> bool: ...
    def check_privileges(self, operation: str) -> PrivilegeStatus: ...
```

### 4.4 MCP Tool Catalog (~25 Tools)

| # | Tool | Category | Interface(s) | Description |
|---|---|---|---|---|
| 1 | `get_network_interfaces` | Capture | TsharkInterface | List available network interfaces |
| 2 | `capture_live_packets` | Capture | TsharkInterface | Capture live packets with BPF filtering |
| 3 | `capture_to_file` | Capture | TsharkInterface | Capture traffic and save to PCAP file |
| 4 | `capture_targeted_traffic` | Capture | TsharkInterface | Targeted capture by host/port/protocol |
| 5 | `analyze_pcap` | Analysis | TsharkInterface | Analyze PCAP file with display filters |
| 6 | `get_protocol_statistics` | Analysis | TsharkInterface | Protocol hierarchy and IP conversations |
| 7 | `get_capture_file_info` | Analysis | TsharkInterface | PCAP file metadata |
| 8 | `detect_protocols` | Analysis | TsharkInterface | Detect protocols in live or file-based capture |
| 9 | `analyze_http_traffic` | Analysis | TsharkInterface | HTTP traffic analysis from PCAP |
| 10 | `follow_tcp_stream` | Streams | TsharkInterface | Reconstruct TCP conversation |
| 11 | `follow_udp_stream` | Streams | TsharkInterface | Reconstruct UDP conversation |
| 12 | `list_tcp_streams` | Streams | TsharkInterface | List all TCP streams in PCAP |
| 13 | `export_packets_json` | Export | TsharkInterface | Export packets to structured JSON |
| 14 | `export_packets_csv` | Export | TsharkInterface | Export custom fields to CSV |
| 15 | `convert_pcap_format` | Export | TsharkInterface | Convert between pcap/pcapng formats |
| 16 | `nmap_port_scan` | Scanning | NmapInterface | Port scan (SYN, connect, UDP) |
| 17 | `nmap_service_detection` | Scanning | NmapInterface | Detect service versions |
| 18 | `nmap_os_detection` | Scanning | NmapInterface | OS fingerprinting |
| 19 | `nmap_vulnerability_scan` | Scanning | NmapInterface | NSE vulnerability scripts |
| 20 | `nmap_quick_scan` | Scanning | NmapInterface | Quick scan of top 100 ports |
| 21 | `nmap_comprehensive_scan` | Scanning | NmapInterface | Full scan with all features |
| 22 | `check_ip_threat_intel` | Threat Intel | ThreatIntelInterface | Check IP against threat feeds |
| 23 | `scan_capture_for_threats` | Threat Intel | TsharkInterface + ThreatIntelInterface | Extract IPs from PCAP and check threats |
| 24 | `extract_credentials` | Credentials | TsharkInterface | Extract creds from PCAP (HTTP Basic, FTP, Telnet, Kerberos) |

### 4.5 MCP Resource Catalog (4 Resources)

| Resource URI | Description | Source |
|---|---|---|
| `netmcp://interfaces/` | Dynamic list of available network interfaces with status | TsharkInterface |
| `netmcp://captures/` | Available PCAP files in common directories with metadata | Filesystem scan |
| `netmcp://system/info` | System capabilities: tool versions, privileges, available interfaces | TsharkInterface + NmapInterface |
| `netmcp://help` | Comprehensive tool documentation and example workflows | Static content |

### 4.6 MCP Prompt Catalog (3 Prompts)

| Prompt | Purpose | Workflow Steps |
|---|---|---|
| `security_audit` | Guided security analysis of a PCAP file or target | 1. Analyze PCAP stats, 2. Extract IPs, 3. Check threats, 4. Follow suspicious streams, 5. Extract credentials, 6. Generate report |
| `network_troubleshooting` | Network diagnostics workflow | 1. List interfaces, 2. Capture traffic, 3. Analyze protocols, 4. Check connectivity patterns, 5. Identify bottlenecks |
| `incident_response` | Security incident investigation | 1. Capture current traffic, 2. Scan target with nmap, 3. Check threat intel, 4. Extract credentials, 5. Reconstruct malicious streams, 6. Document findings |

---

## 5. Deployment View

### 5.1 Runtime Architecture

netmcp runs as a single-process MCP server using stdio transport:

```
┌─────────────────┐     stdio (MCP protocol)     ┌──────────────────┐
│  MCP Client     │◄────────────────────────────►│  netmcp server   │
│  (Claude,       │         JSON-RPC             │  (Python 3.11+)  │
│   Cursor, etc.) │                              │                  │
└─────────────────┘                              └────────┬─────────┘
                                                         │
                        ┌────────────────────────────────┼──────────────────┐
                        │                                │                  │
                 ┌──────▼──────┐                  ┌──────▼──────┐   ┌──────▼──────┐
                 │ tshark      │                  │ nmap        │   │ httpx       │
                 │ subprocess  │                  │ subprocess  │   │ AsyncClient │
                 └──────┬──────┘                  └──────┬──────┘   └──────┬──────┘
                        │                                │                 │
                 ┌──────▼──────┐                  ┌──────▼──────┐   ┌──────▼──────┐
                 │ Network     │                  │ Target      │   │ URLhaus     │
                 │ interfaces  │                  │ hosts       │   │ AbuseIPDB   │
                 └─────────────┘                  └─────────────┘   └─────────────┘
```

### 5.2 External Dependencies

| Dependency | Type | Required | Installation |
|---|---|---|---|
| Python 3.11+ | Runtime | Yes | System package manager, pyenv, etc. |
| tshark (Wireshark) | CLI tool | Yes | `apt install tshark`, `brew install wireshark`, Windows installer |
| nmap | CLI tool | Recommended | `apt install nmap`, `brew install nmap` |
| dumpcap | CLI tool | Yes (with Wireshark) | Included with Wireshark |
| FastMCP (`mcp` SDK) | Python package | Yes | `pip install mcp` |
| httpx | Python package | Yes | `pip install httpx` |
| python-nmap | Python package | Yes (for nmap tools) | `pip install python-nmap` |

### 5.3 Privilege Requirements

Packet capture requires elevated privileges. netmcp supports three configurations:

| Configuration | Setup | Security Level |
|---|---|---|
| **Capability-based (Linux, recommended)** | `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap` | High -- no root needed |
| **Group-based (Linux)** | `sudo usermod -aG wireshark $USER` | High -- group membership required |
| **Administrator (Windows/macOS)** | Run client as Administrator / root | Lower -- full privileges granted |

netmcp **never auto-escalates privileges**. If a tool requires elevated access, it returns a clear error message indicating the required setup.

### 5.4 Configuration

netmcp is configured via environment variables and MCP client configuration:

```json
{
  "mcpServers": {
    "netmcp": {
      "command": "uv",
      "args": ["run", "netmcp"],
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here",
        "NETMCP_MAX_CAPTURE_DURATION": "300",
        "NETMCP_MAX_PACKET_COUNT": "10000",
        "NETMCP_NMAP_SCAN_LIMIT": "10",
        "NETMCP_NMAP_SCAN_WINDOW": "3600",
        "NETMCP_ALLOWED_CAPTURE_DIRS": "/captures,/tmp"
      }
    }
  }
}
```

| Environment Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_API_KEY` | (not set) | AbuseIPDB API key for threat intel (URLhaus works without a key) |
| `NETMCP_MAX_CAPTURE_DURATION` | 300 | Maximum capture duration in seconds |
| `NETMCP_MAX_PACKET_COUNT` | 10000 | Maximum packets to analyze per operation |
| `NETMCP_NMAP_SCAN_LIMIT` | 10 | Maximum nmap scans per time window |
| `NETMCP_NMAP_SCAN_WINDOW` | 3600 | Rate limit window in seconds for nmap scans |
| `NETMCP_ALLOWED_CAPTURE_DIRS` | (current dir) | Comma-separated list of allowed PCAP file directories |
| `NETMCP_TSHARK_PATH` | (auto-detect) | Absolute path to tshark binary |
| `NETMCP_LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |

### 5.5 Packaging

netmcp is distributed as a Python package via `pyproject.toml`:

```toml
[project]
name = "netmcp"
version = "0.1.0"
description = "Professional network analysis MCP server"
requires-python = ">=3.11"
dependencies = [
    "mcp>=1.0.0",
    "httpx>=0.27.0",
    "python-nmap>=0.7.1",
]

[project.scripts]
netmcp = "netmcp.server:main"
```

Installation:

```bash
# From PyPI (future)
pip install netmcp

# From source
pip install -e .
```

---

## 6. Cross-Cutting Concerns

### 6.1 Security

The 5-layer security model (detailed in Section 2.2) is enforced consistently across all modules:

**Input validation patterns**:

- Interface names are validated against the list returned by `tshark -D`
- IP addresses are validated using Python's `ipaddress` module (`IPv4Address`, `IPv4Network`)
- Port ranges are validated with regex `^\d+(-\d+)?(,\d+(-\d+)?)*$`
- BPF filters are validated by running `tshark -f <filter> -d` (dry-run mode)
- Display filters are validated by running `tshark -Y <filter> -r /dev/null` (syntax check)
- File paths are resolved to absolute paths and checked against allowed directories

**Subprocess safety**:

- ALL subprocess calls use `shell=False`
- Commands are constructed as lists: `["tshark", "-r", str(filepath), "-T", "json"]`
- User input is never interpolated into shell strings
- All subprocess calls specify `timeout` parameter
- stdout and stderr are captured separately

**Rate limiting implementation**:

```python
# Simplified rate limiter
class RateLimiter:
    def __init__(self, max_ops: int, window: float):
        self.history: deque[float] = deque(maxlen=max_ops)
        self.max_ops = max_ops
        self.window = window

    def check(self) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        while self.history and self.history[0] < cutoff:
            self.history.popleft()
        if len(self.history) >= self.max_ops:
            return False
        self.history.append(now)
        return True
```

### 6.2 Logging

All logging uses Python's standard `logging` module:

| Level | Usage |
|---|---|
| DEBUG | Subprocess command details, raw API responses, internal state |
| INFO | Tool invocations, capture completions, scan results summary |
| WARNING | Rate limit approaching, optional dependency unavailable, privilege warnings |
| ERROR | Tool failures, subprocess failures, validation failures |

Log format:

```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

Logging destination: stderr only (to avoid interfering with MCP stdio transport).

### 6.3 Error Handling

**Error response standardization**:

All tools return consistent error responses via the `OutputFormatter`:

```python
# Success
{"content": [{"type": "text", "text": formatted_result}]}

# Error
{"content": [{"type": "text", "text": f"Error [{error_code}]: {user_friendly_message}"}], "isError": True}
```

**Error categories**:

| Error Code | Category | User Message Pattern |
|---|---|---|
| `VALIDATION_ERROR` | Input validation | "Invalid <field>: <reason>. Expected <format>." |
| `PERMISSION_ERROR` | Privilege/permission | "Permission denied: <operation> requires <privilege>. Run: <fix_command>." |
| `TOOL_UNAVAILABLE` | Missing dependency | "<tool> is not installed. Install with: <install_command>." |
| `RATE_LIMITED` | Rate limiting | "Rate limit exceeded: <operation>. Try again in <seconds>s." |
| `EXECUTION_ERROR` | Runtime failure | "<operation> failed: <detail>. Check logs for details." |
| `TIMEOUT_ERROR` | Timeout | "<operation> timed out after <seconds>s." |

**Exception handling strategy**:

- Each tool function has a top-level `try/except` that catches all exceptions
- Specific exception types are mapped to error codes for actionable messages
- Unexpected exceptions are caught by a generic handler that logs the full traceback and returns a generic error message (never exposes stack traces to the client)

### 6.4 Testing

**Test categories**:

| Category | Scope | Approach |
|---|---|---|
| Unit tests | Individual functions, security validator, output formatter | Mock subprocess, mock httpx |
| Interface tests | TsharkInterface, NmapInterface, ThreatIntelInterface | Mock subprocess returns, mock httpx responses |
| Tool tests | Each MCP tool function in isolation | Mock interfaces, verify validation and formatting |
| Integration tests | Full server startup, tool invocation via MCP protocol | Real MCP client simulation, real tshark on test PCAPs |
| Security tests | Command injection attempts, path traversal, rate limit enforcement | Deliberate malicious inputs, verify rejection |

**Test PCAPs**:

A directory of test PCAP files (`tests/fixtures/`) provides known-good captures for testing:

- `http_traffic.pcap` -- HTTP requests with Basic Auth credentials
- `ftp_traffic.pcap` -- FTP login sequences
- `dns_traffic.pcap` -- DNS query/response patterns
- `mixed_protocols.pcap` -- Multi-protocol capture for protocol detection tests
- `kerberos_traffic.pcap` -- Kerberos AS-REQ/TGS-REQ for credential extraction tests

**Testing commands**:

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest --cov=netmcp --cov-report=html tests/

# Security tests only
pytest tests/test_security.py -v

# Integration tests (requires tshark installed)
pytest tests/test_server.py -v
```

### 6.5 Type Safety

- All public functions use type hints with `typing` module constructs
- `from __future__ import annotations` for forward references
- Target: `mypy --strict src/netmcp/` passes with no errors
- Dataclasses used for structured return types (CaptureResult, ScanResult, ThreatReport, etc.)

### 6.6 Code Quality

| Tool | Purpose |
|---|---|
| `ruff` | Linting and formatting (replaces flake8 + black + isort) |
| `mypy` | Static type checking |
| `pytest` | Testing framework |

Enforced via pre-commit hooks and CI pipeline.

---

## 7. Risks and Technical Debt

### 7.1 Technical Risks

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| **tshark output format changes** | Medium | Low | Parse JSON output (`-T json`) where possible; text output parsing with regex is fragile. Add version checks. |
| **Large PCAP files cause memory issues** | High | Medium | Enforce 100 MB file size limit; stream processing for large files where possible; implement chunked analysis. |
| **nmap scans trigger IDS/IPS alerts** | High | Medium | Rate limiting; clear documentation that users must have authorization; log all scan operations. |
| **Threat intel API changes (URLhaus format)** | Medium | Low | Implement resilient parsing with fallback; cache responses; test with real API data. |
| **Privilege requirements on restrictive systems** | High | Medium | Provide clear setup documentation; support capability-based access; graceful degradation (analysis tools work without capture privileges). |
| **Platform compatibility (Windows tshark paths)** | Medium | Medium | Dynamic tshark path detection with common fallback paths; thorough cross-platform testing. |

### 7.2 Known Limitations from Source Projects

| Limitation | Source | Impact | Resolution Plan |
|---|---|---|---|
| WireMCP uses `exec()` with string interpolation | WireMCP | Command injection vulnerability | Replace with subprocess list-based commands with `shell=False` |
| WireMCP has no rate limiting | WireMCP | Abuse potential | Implement RateLimiter class in core/security.py |
| PyShark blocks event loop | wireshark-mcp | Performance degradation | Use direct tshark CLI wrapper instead of PyShark |
| PyShark credential extraction is incomplete | wireshark-mcp | Missing Kerberos, partial Telnet | Implement comprehensive extraction from WireMCP's approach (HTTP Basic, FTP, Telnet, Kerberos) |
| Wireshark-MCP nmap interface not yet implemented | Wireshark-MCP | Missing scanning capability | Implement full python-nmap wrapper with all 6 scan types |

### 7.3 Future Technical Debt

| Debt | Description | Priority |
|---|---|---|
| **Async subprocess management** | Current design uses ThreadPoolExecutor for blocking subprocess calls; native async subprocess (`asyncio.create_subprocess_exec`) would be more efficient but adds complexity | Low -- defer until performance profiling shows it's needed |
| **PCAP streaming analysis** | Analyzing very large PCAP files requires streaming/chunked processing rather than loading entire file into memory | Medium -- implement when file size limit becomes a user constraint |
| **Plugin system** | Hard-coded tool registration limits extensibility; a plugin system would allow third-party tools | Low -- defer until stable core is established |
| **Persistent state** | No database for persistent state (capture history, scan results); currently in-memory only | Low -- add SQLite if users request history features |
| **WebSocket streaming** | Real-time packet streaming to clients rather than batch capture-then-analyze | Low -- significant architectural change; requires bidirectional MCP transport |

### 7.4 Operational Risks

| Risk | Mitigation |
|---|---|
| Running netmcp in production environments without proper access controls | Document security implications; recommend running in isolated environments; never run as root unless necessary |
| Capturing sensitive network traffic (PII, credentials) | Document legal/compliance implications; recommend targeted captures with BPF filters rather than broad captures |
| Dependency on external threat intel services | URLhaus and AbuseIPDB may change APIs or become unavailable; implement graceful degradation and caching |

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| **MCP** | Model Context Protocol -- a standard for AI assistants to interact with external tools and data sources |
| **FastMCP** | High-level Python framework for building MCP servers from the official MCP SDK |
| **tshark** | Command-line packet analyzer from the Wireshark project |
| **BPF filter** | Berkeley Packet Filter expression used to filter packets at capture time (e.g., `tcp port 80`) |
| **Display filter** | Wireshark expression used to filter packets during analysis (e.g., `http.request`) |
| **PCAP** | Packet Capture file format (`.pcap` or `.pcapng`) |
| **URLhaus** | Threat intelligence feed operated by abuse.ch, providing URLs and IPs associated with malware |
| **AbuseIPDB** | IP reputation database with a free API for checking if an IP has been reported for malicious activity |
| **NSE** | Nmap Scripting Engine -- Lua scripts used by nmap for vulnerability detection and service enumeration |

## Appendix B: Comparison with Source Projects

| Feature | WireMCP | Wireshark-MCP | wireshark-mcp | netmcp |
|---|---|---|---|---|
| Language | Node.js | Python | Python | Python |
| MCP Framework | @modelcontextprotocol/sdk | FastMCP | FastMCP | FastMCP |
| Packet capture | tshark CLI (exec) | tshark CLI (subprocess) | PyShark | tshark CLI (subprocess) |
| Credential extraction | HTTP Basic, FTP, Telnet, Kerberos | Planned | No | HTTP Basic, FTP, Telnet, Kerberos |
| Nmap integration | No | Designed, not implemented | No | Yes (6 scan types) |
| Threat intel | URLhaus only | URLhaus + AbuseIPDB | No | URLhaus + AbuseIPDB |
| Security layers | Minimal | 5-layer model | Minimal | 5-layer model |
| MCP Resources | No | Yes (4) | Yes (3) | Yes (4+) |
| MCP Prompts | Yes (6) | Yes (3) | Yes (1) | Yes (3+) |
| Stream following | No | Yes | No | Yes |
| Targeted capture | No | No | Yes | Yes |
| HTTP analysis | No | No | Yes | Yes |
| Rate limiting | No | Yes | No | Yes |

## Appendix C: MCP Tool Parameter Reference

### Capture Tools

**`capture_live_packets`**:
- `interface` (string, required): Network interface name
- `count` (int, optional, default=50, max=1000): Number of packets
- `capture_filter` (string, optional): BPF filter expression
- `timeout` (float, optional, default=30, max=300): Capture timeout
- `format` (string, optional, enum=["text", "json"], default="text"): Output format

**`capture_to_file`**:
- `interface` (string, required): Network interface name
- `output_file` (string, required): Output PCAP path
- `capture_filter` (string, optional): BPF filter expression
- `duration` (float, optional, default=60, max=300): Capture duration
- `packet_limit` (int, optional): Maximum packets

### Analysis Tools

**`analyze_pcap`**:
- `filepath` (string, required): Path to PCAP file
- `display_filter` (string, optional): Wireshark display filter
- `max_packets` (int, optional, default=100, max=10000): Maximum packets

**`extract_credentials`**:
- `filepath` (string, required): Path to PCAP file

### Nmap Tools

**`nmap_port_scan`**:
- `target` (string, required): IP, CIDR, or hostname
- `ports` (string, optional): Port specification (e.g., "80,443" or "1-1000")
- `scan_type` (string, optional, enum=["connect", "syn", "udp"], default="connect")
- `format` (string, optional, enum=["text", "json"], default="text")

### Threat Intel Tools

**`check_ip_threat_intel`**:
- `ip` (string, required): IP address to check
- `providers` (string, optional, default="urlhaus,abuseipdb"): Comma-separated provider list
