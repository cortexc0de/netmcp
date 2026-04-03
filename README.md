# NetMCP

> Professional-grade network analysis MCP server with Wireshark, Nmap, and threat intelligence.

NetMCP empowers AI assistants (Claude, Cursor, etc.) with comprehensive network analysis capabilities through the Model Context Protocol (MCP).

## Features

- **Live Packet Capture** — Real-time traffic capture with BPF filtering
- **PCAP Analysis** — Protocol hierarchy, stream following, file analysis
- **Nmap Scanning** — Port scanning, service detection, OS fingerprinting, vulnerability scanning
- **Threat Intelligence** — URLhaus + AbuseIPDB integration for malicious IP detection
- **Credential Extraction** — HTTP Basic Auth, FTP, Telnet, Kerberos hash extraction
- **Data Export** — JSON, CSV, pcap/pcapng conversion
- **Security-First** — 5-layer input validation, command injection prevention, rate limiting

## Quick Start

```bash
pip install netmcp
netmcp
```

## Requirements

- Python 3.11+
- Wireshark/TShark (`sudo apt install tshark` or `brew install wireshark`)
- Nmap (`sudo apt install nmap` or `brew install nmap`)

## License

MIT
