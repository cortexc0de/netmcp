# NetMCP

> **Professional-grade network analysis MCP server** — empowering AI assistants with Wireshark, Nmap, and threat intelligence.

[![CI](https://github.com/LuxVTZ/netmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/LuxVTZ/netmcp/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Server-purple.svg)](https://modelcontextprotocol.io/)

NetMCP bridges the gap between raw network data and AI comprehension. It gives Claude, Cursor, and any MCP-compliant client the ability to **capture packets, scan networks, detect threats, and extract credentials** — all through natural language.

---

## 🚀 Quick Start

```bash
# 1. Install system dependencies
sudo apt-get install -y tshark nmap        # Ubuntu/Debian
# brew install wireshark nmap              # macOS

# 2. Install NetMCP
pip install netmcp

# 3. Run
netmcp
```

---

## ✨ Features

### 📡 Packet Capture & Analysis (8 tools)

| Tool | Description |
|---|---|
| `get_network_interfaces` | List available network interfaces |
| `capture_live_packets` | Live packet capture with BPF filtering |
| `analyze_pcap_file` | Deep PCAP analysis with display filters |
| `get_protocol_statistics` | Protocol hierarchy and IP conversations |
| `get_capture_file_info` | PCAP file metadata via capinfos |
| `capture_targeted_traffic` | Capture by host, port, or protocol |
| `analyze_http_traffic` | HTTP methods, hosts, URIs, user agents, status codes |
| `detect_network_protocols` | Protocol detection with insights |

### 🔄 Stream Analysis (3 tools)

| Tool | Description |
|---|---|
| `follow_tcp_stream` | Reconstruct TCP conversations (ascii/hex/raw) |
| `follow_udp_stream` | Reconstruct UDP conversations |
| `list_tcp_streams` | Enumerate all TCP streams in a capture |

### 📤 Data Export (3 tools)

| Tool | Description |
|---|---|
| `export_packets_json` | Export packets to structured JSON |
| `export_packets_csv` | Export custom fields to CSV |
| `convert_pcap_format` | Convert between pcap and pcapng formats |

### 🔍 Nmap Scanning (6 tools)

| Tool | Description |
|---|---|
| `nmap_port_scan` | SYN/connect/UDP port scanning |
| `nmap_service_detection` | Service version identification |
| `nmap_os_detection` | OS fingerprinting (requires root) |
| `nmap_vulnerability_scan` | NSE vulnerability script scanning |
| `nmap_quick_scan` | Fast scan of top 100 ports |
| `nmap_comprehensive_scan` | Full scan with all features |

### 🛡️ Threat Intelligence (2 tools)

| Tool | Description |
|---|---|
| `check_ip_threat_intel` | Check IP against URLhaus + AbuseIPDB |
| `scan_capture_for_threats` | Extract all IPs from PCAP and check threats |

### 🔑 Credential Extraction (1 tool)

| Tool | Description |
|---|---|
| `extract_credentials` | Extract HTTP Basic, FTP, Telnet, and Kerberos credentials |

---

## 📋 Requirements

| Dependency | Required | Install |
|---|---|---|
| **Python** | 3.11+ | `sudo apt install python3.11 python3-pip` |
| **TShark** | Yes | `sudo apt install tshark` |
| **Nmap** | Optional | `sudo apt install nmap` |

### macOS

```bash
brew install wireshark nmap
```

### Windows

1. Download [Wireshark](https://www.wireshark.org/download.html) (includes tshark)
2. Download [Nmap](https://nmap.org/download.html)
3. Add both to your `PATH`

### Network Permissions (Linux)

```bash
# Option 1: Set capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Option 2: Add user to wireshark group
sudo usermod -aG wireshark $USER
newgrp wireshark
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | No | None | AbuseIPDB API key for threat intel. Get free key at [abuseipdb.com](https://www.abuseipdb.com/) |
| `NETMCP_TSHARK_PATH` | No | Auto-detect | Custom path to tshark binary |
| `NETMCP_MAX_PACKETS` | No | 10000 | Max packets per capture |
| `NETMCP_MAX_FILE_SIZE` | No | 104857600 | Max PCAP file size (100MB) |

---

## 🔌 MCP Client Setup

### Claude Desktop

Edit your config:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "netmcp": {
      "command": "netmcp",
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

Or with Python path:

```json
{
  "mcpServers": {
    "netmcp": {
      "command": "python",
      "args": ["-m", "netmcp.server"],
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Cursor

Edit `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "netmcp": {
      "command": "netmcp"
    }
  }
}
```

### Any MCP Client

Use stdio transport:

```bash
netmcp
```

Or programmatic:

```python
from netmcp.server import create_server

server = create_server()
server.run()
```

---

## 🎯 Usage Examples

### Basic Network Capture

```
You: Capture 100 packets from eth0 and tell me what protocols are in use.

Claude: I'll capture live traffic and analyze the protocol distribution.
[Calls capture_live_packets(interface="eth0", packet_count=100)]
[Calls get_protocol_statistics()]
```

### Security Audit Workflow

```
You: Perform a security audit on suspicious.pcap

Claude: I'll run a comprehensive security audit.
1. [Runs get_protocol_statistics — traffic breakdown]
2. [Runs extract_credentials — finds exposed HTTP Basic Auth]
3. [Runs scan_capture_for_threats — 2 malicious IPs found]
4. [Generates full security report]
```

### Nmap Scanning

```
You: Scan 192.168.1.100 for open ports and vulnerabilities

Claude: I'll start with a quick scan, then go deeper.
[Calls nmap_quick_scan("192.168.1.100")]
→ Found ports: 22 (ssh), 80 (http), 443 (https)
[Calls nmap_service_detection("192.168.1.100")]
→ nginx 1.18.0, OpenSSH 8.2
[Calls nmap_vulnerability_scan("192.168.1.100")]
→ No critical vulnerabilities found
```

### Threat Intelligence

```
You: Check if this capture has any malicious IPs

Claude: I'll extract all IPs and check them against threat feeds.
[Calls scan_capture_for_threats("capture.pcap")]
→ 47 unique IPs found, 1 threat detected
→ Malicious IP: 185.220.101.1 (URLhaus — 92% abuse score)
```

---

## 🧠 MCP Resources

| Resource URI | Description |
|---|---|
| `netmcp://interfaces` | Dynamic list of available network interfaces |
| `netmcp://captures` | Available PCAP files in common directories |
| `netmcp://system/info` | System capabilities: tool versions, available features |

## 💬 MCP Prompts

| Prompt | Description |
|---|---|
| `security_audit` | Guided security analysis workflow for PCAP files |
| `network_troubleshooting` | Network diagnostics workflow |
| `incident_response` | Security incident investigation workflow |

---

## 🛡️ Security Model

NetMCP implements **5 layers of defense in depth**:

| Layer | Mechanism | Prevents |
|---|---|---|
| **1. Input Validation** | Regex, ipaddress module, Pydantic | Malformed input |
| **2. Command Construction** | List args, `shell=False` everywhere | Command injection |
| **3. Subprocess Execution** | Timeouts, captured output only | Shell injection |
| **4. File System** | `Path.resolve()`, extension check, size limit | Path traversal |
| **5. Rate Limiting** | Sliding window, per-operation tracking | Abuse / DoS |

Additionally:
- **Never auto-escalates privileges**
- **Clear error messages** for permission issues
- **All operations logged** with timestamps
- **Dangerous nmap flags rejected** (exploit scripts, custom args)

---

## 🧪 Development

### Install dev dependencies

```bash
pip install -e ".[dev]"
```

### Run tests

```bash
pytest tests/ -v                          # All tests
pytest tests/ --cov=netmcp --cov-report=html  # With coverage
pytest tests/test_core/ -v                # Core layer only
pytest tests/test_interfaces/ -v          # Interfaces only
pytest tests/test_tools/ -v               # Tools only
pytest tests/test_e2e.py -v               # E2E tests
```

### Linting

```bash
ruff check src/netmcp/ tests/     # Lint
ruff format --check src/netmcp/   # Format check
ruff format src/netmcp/ tests/    # Auto-format
mypy src/netmcp/                  # Type check
```

### Project Structure

```
src/netmcp/
├── __init__.py              # Package metadata
├── server.py                # Main entry point
├── core/
│   ├── security.py          # 5-layer input validation
│   └── formatter.py         # MCP response formatting
├── interfaces/
│   ├── tshark.py            # TShark CLI wrapper (async)
│   ├── nmap.py              # python-nmap wrapper
│   └── threat_intel.py      # URLhaus + AbuseIPDB
├── tools/                   # 23 MCP tools
│   ├── capture.py           # Live packet capture
│   ├── analysis.py          # PCAP analysis
│   ├── streams.py           # Stream following
│   ├── export_tools.py      # JSON/CSV export
│   ├── nmap_scan.py         # Nmap scanning
│   ├── threat_intel.py      # Threat checks
│   └── credentials.py       # Credential extraction
├── resources/               # MCP Resources
└── prompts/                 # MCP Prompts

tests/
├── test_core/               # Security + Formatter (78 tests)
├── test_interfaces/         # Tshark + Nmap + Threat (32 tests)
├── test_tools/              # Tool integration tests
└── test_e2e.py              # End-to-end tests
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Wireshark/TShark** team for the excellent packet analysis tools
- **Nmap** project for the industry-standard network scanner
- **URLhaus** and **AbuseIPDB** for threat intelligence data
- **Model Context Protocol** community for the framework
- Contributors to the original WireMCP, Wireshark-MCP, and wireshark-mcp projects

---

**Transform your network analysis with AI-powered packet capture, scanning, and threat intelligence.**
