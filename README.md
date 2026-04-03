<div align="center">

# 🌐 NetMCP

**Professional-grade network analysis MCP server — Wireshark/TShark + Nmap + Threat Intelligence**

[![Tests](https://img.shields.io/github/actions/workflow/status/cortexc0de/netmcp/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/cortexc0de/netmcp/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen?style=flat-square)](https://github.com/cortexc0de/netmcp)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/cortexc0de/netmcp/codeql.yml?branch=main&label=CodeQL&style=flat-square)](https://github.com/cortexc0de/netmcp/actions/workflows/codeql.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/netmcp?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/netmcp/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://ghcr.io/cortexc0de/netmcp)
[![MCP](https://img.shields.io/badge/MCP-Server-7C3AED?style=flat-square)](https://modelcontextprotocol.io/)

NetMCP bridges the gap between raw network data and AI comprehension. It gives Claude, Cursor, and any MCP-compliant client the ability to capture packets, scan networks, detect threats, and extract credentials — all through natural language.

[Quick Start](#-quick-start) • [Features](#-features) • [Configuration](#-configuration) • [API Reference](docs/API.md) • [Architecture](docs/ARCHITECTURE.md)

</div>

---

## 🚀 Quick Start

```bash
# Install system dependencies
sudo apt-get install -y tshark nmap        # Ubuntu/Debian
# brew install wireshark nmap              # macOS

# Install NetMCP
pip install netmcp

# Run
netmcp
```

That's it. The server starts on **stdio** transport by default, ready for any MCP client.

---

## ✨ Features

- 📡 **Packet Capture** — Live capture, BPF filtering, targeted traffic, quick capture mode
- 🔬 **Deep Analysis** — PCAP parsing, protocol statistics, HTTP traffic analysis, DNS analysis, expert info, GeoIP enrichment
- 🔄 **Stream Reconstruction** — Follow TCP/UDP conversations, enumerate streams
- 📤 **Flexible Export** — JSON, CSV, pcap/pcapng format conversion
- 🔍 **Nmap Integration** — Port scan, service detection, OS fingerprinting, vulnerability scan
- 🛡️ **Threat Intelligence** — URLhaus + AbuseIPDB IP reputation checks, PCAP-wide threat scan
- 🔑 **Credential Extraction** — HTTP Basic, FTP, Telnet, Kerberos (hashcat-ready)
- 🌍 **GeoIP Mapping** — MaxMind GeoLite2 IP geolocation for traffic analysis
- 🔒 **5-Layer Security** — Input validation, shell=False, rate limiting, path traversal protection, audit logging
- 💬 **Guided Workflows** — Security audit, incident response, troubleshooting, traffic analysis, network baseline prompts

### Advanced Features

- 🔀 **PCAP Diff/Merge/Slice** — Compare captures, combine files via mergecap, extract packet ranges via editcap
- 📊 **Flow Visualization** — ASCII art and Mermaid sequence diagrams of network conversations
- 🔓 **TLS Decryption** — Decrypt HTTPS traffic using SSLKEYLOGFILE (NSS Key Log Format)
- 🎨 **Wireshark Profiles** — List profiles, apply profile settings, parse color filters, capture with profile
- 🧬 **DNS Tunneling Detection** — Analyze DNS traffic and flag suspiciously long subdomain names
- 📦 **Packet Decode** — Detailed single-packet analysis with full protocol layer dissection
- 🏥 **Expert Information** — Extract Wireshark's expert warnings, errors, and protocol violation notes

---

## 📊 Tool Categories

NetMCP provides **48 tools** across **9 categories**, plus **3 resources** and **5 prompts**:

| Category | Tools | Description |
|----------|-------|-------------|
| 📡 **Capture & Analysis** | 5 | `get_network_interfaces` · `capture_live_packets` · `quick_capture` · `save_capture_to_file` · `analyze_large_pcap` |
| 🔬 **Protocol Analysis** | 10 | `analyze_pcap_file` · `get_protocol_statistics` · `get_capture_file_info` · `capture_targeted_traffic` · `analyze_http_traffic` · `detect_network_protocols` · `analyze_http_headers` · `geoip_lookup` · `analyze_dns_traffic` · `get_expert_info` |
| 📊 **Network Flows** | 2 | `visualize_network_flows` (ASCII + Mermaid) · `decrypt_tls_traffic` |
| 🔧 **PCAP Tools** | 4 | `diff_pcap_files` · `merge_pcap_files` · `slice_pcap` · `decode_packet` |
| 🔄 **Streams** | 3 | `follow_tcp_stream` · `follow_udp_stream` · `list_tcp_streams` |
| 📤 **Export** | 3 | `export_packets_json` · `export_packets_csv` · `convert_pcap_format` |
| 🔍 **Nmap** | 6 | `nmap_port_scan` · `nmap_service_detection` · `nmap_os_detection` · `nmap_vulnerability_scan` · `nmap_quick_scan` · `nmap_comprehensive_scan` |
| 🛡️ **Security** | 3 | `extract_credentials` · `check_ip_threat_intel` · `scan_capture_for_threats` |
| 🎨 **Wireshark Profiles** | 4 | `list_wireshark_profiles` · `apply_profile_capture` · `get_color_filters` · `capture_with_profile` |

> 📖 Full API reference with parameters and examples: [docs/API.md](docs/API.md)

---

## 🔌 Transport Options

NetMCP supports all MCP transport protocols:

| Transport | Command | Use Case |
|-----------|---------|----------|
| **stdio** (default) | `netmcp` | Claude Desktop, Cursor, local clients |
| **SSE** | `netmcp --transport sse` | Web-based clients, remote access |
| **Streamable HTTP** | `netmcp --transport streamable-http` | Modern HTTP clients |

---

## ⚙️ Configuration

### Claude Desktop

Edit your config file:
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

### Cursor

Edit `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "netmcp": {
      "command": "netmcp"
    }
  }
}
```

### Windsurf / VS Code

Edit `.vscode/mcp.json`:

```json
{
  "servers": {
    "netmcp": {
      "command": "netmcp",
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | No | — | AbuseIPDB API key for threat intelligence. [Get free key](https://www.abuseipdb.com/) |
| `NETMCP_TSHARK_PATH` | No | Auto-detect | Custom path to tshark binary |
| `NETMCP_MAX_PACKETS` | No | `10000` | Maximum packets per capture operation |
| `NETMCP_MAX_FILE_SIZE` | No | `104857600` | Maximum PCAP file size in bytes (100 MB) |

---

## 📋 Requirements

| Dependency | Required | Install |
|------------|----------|---------|
| **Python** | 3.11+ | `sudo apt install python3.11` |
| **TShark** | Yes | `sudo apt install tshark` |
| **Nmap** | Optional | `sudo apt install nmap` |

### macOS

```bash
brew install wireshark nmap
```

### Linux Permissions

```bash
# Option 1: Set capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Option 2: Add user to wireshark group
sudo usermod -aG wireshark $USER && newgrp wireshark
```

---

## 🛡️ Security Model

NetMCP implements **5 layers of defense in depth**:

| Layer | Mechanism | Prevents |
|-------|-----------|----------|
| **1. Input Validation** | Regex, `ipaddress` module, Pydantic | Malformed input, injection payloads |
| **2. Command Construction** | List args, `shell=False` everywhere | Command injection, shell expansion |
| **3. Subprocess Execution** | Timeouts, captured output only | Runaway processes, resource exhaustion |
| **4. File System** | `Path.resolve()`, extension allowlist, size limits | Path traversal, symlink attacks |
| **5. Rate Limiting** | Sliding window, per-operation tracking | Abuse, DoS attacks |

Additional protections:
- 🔒 Never auto-escalates privileges
- 📝 All operations audit-logged with timestamps
- 🚫 Dangerous nmap flags rejected (`--script-args`, `--interactive`, etc.)
- ⚠️ Clear error messages for permission issues

---

## 🎯 Usage Examples

### Live Packet Capture

```
You: Capture 100 packets from eth0 and analyze the protocols.

Claude: [capture_live_packets(interface="eth0", packet_count=100)]
       [get_protocol_statistics(filepath="capture.pcap")]
       Found 8 protocols: TCP (62%), UDP (24%), DNS (8%), HTTP (4%)...
```

### Security Audit

```
You: Perform a security audit on suspicious.pcap

Claude: 1. [get_protocol_statistics] → traffic breakdown
        2. [extract_credentials] → found HTTP Basic Auth credentials
        3. [scan_capture_for_threats] → 2 malicious IPs detected
        4. Generated full security report with IOCs
```

### Nmap Vulnerability Scan

```
You: Scan 192.168.1.100 for vulnerabilities

Claude: [nmap_quick_scan("192.168.1.100")] → ports 22, 80, 443 open
        [nmap_service_detection("192.168.1.100")] → nginx 1.18.0, OpenSSH 8.2
        [nmap_vulnerability_scan("192.168.1.100")] → no critical CVEs found
```

---

## 🧠 MCP Resources & Prompts

### Resources

| URI | Description |
|-----|-------------|
| `netmcp://interfaces` | Dynamic list of available network interfaces |
| `netmcp://captures` | Available PCAP files in common directories |
| `netmcp://system/info` | System capabilities: tool versions, features |

### Prompts (Guided Workflows)

| Prompt | Description |
|--------|-------------|
| `security_audit` | Comprehensive PCAP security analysis with IOC extraction |
| `network_troubleshooting` | Step-by-step network diagnostics |
| `incident_response` | Security incident investigation workflow |
| `traffic_analysis` | Deep traffic analysis with GeoIP mapping |
| `network_baseline` | Establish normal traffic patterns |

---

## 🧪 Development

```bash
# Clone and setup
git clone https://github.com/cortexc0de/netmcp.git
cd netmcp
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=netmcp --cov-report=html

# Linting
ruff check src/netmcp/ tests/
ruff format --check src/netmcp/
mypy src/netmcp/
```

### Project Structure

```
src/netmcp/
├── server.py                # FastMCP server entry point
├── core/
│   ├── security.py          # 5-layer input validation + rate limiting
│   └── formatter.py         # MCP response formatting
├── interfaces/
│   ├── tshark.py            # TShark async CLI wrapper
│   ├── nmap.py              # python-nmap wrapper
│   └── threat_intel.py      # URLhaus + AbuseIPDB clients
├── tools/                   # 48 MCP tools across 11 modules
├── resources/               # 3 MCP resources
└── prompts/                 # 5 MCP prompts
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Submit a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [Wireshark/TShark](https://www.wireshark.org/) — packet analysis toolkit
- [Nmap](https://nmap.org/) — network scanner
- [URLhaus](https://urlhaus.abuse.ch/) & [AbuseIPDB](https://www.abuseipdb.com/) — threat intelligence
- [Model Context Protocol](https://modelcontextprotocol.io/) — AI tool framework

---

<div align="center">

**Transform your network analysis with AI-powered packet capture, scanning, and threat intelligence.**

</div>
