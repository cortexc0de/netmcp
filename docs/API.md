# API Reference — NetMCP

## Overview
NetMCP exposes **40 MCP tools**, **3 resources**, and **5 prompts** via the Model Context Protocol.

All tools follow consistent patterns:
- Input validation via SecurityValidator
- Rate limiting on write operations
- Structured JSON responses via OutputFormatter
- Audit logging for sensitive operations

---

## Tools

### 1. Capture & Analysis (5 tools)

#### `get_network_interfaces`
List all available network interfaces for packet capture.

- **Read-only**: Yes
- **Parameters**: None
- **Returns**: `{ count: int, interfaces: string[] }`

Example:
```json
{ "count": 3, "interfaces": ["eth0", "lo", "wlan0"] }
```

#### `capture_live_packets`
Capture live network packets from a specified interface.

- **Read-only**: No
- **Rate limit**: `live_capture` — 30/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `string` | *required* | Network interface (e.g., eth0, en0) |
| `duration` | `int` | `5` | Max capture duration in seconds |
| `packet_count` | `int` | `100` | Max packets to capture |
| `bpf_filter` | `string` | `""` | BPF filter (e.g., 'tcp port 80') |

Returns: `{ interface, duration, filter, packets_captured, pcap_file, packets[] }`

#### `quick_capture`
Fast packet capture — 3 seconds, minimal config.

- **Read-only**: No
- **Rate limit**: `live_capture` — 30/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `string` | `"eth0"` | Network interface |
| `packet_count` | `int` | `10` | Max packets |

Returns: `{ interface, duration_seconds: 3, packets_captured, unique_ips[], protocols_seen[], pcap_file, packets[] }`

#### `save_capture_to_file`
Capture traffic and save directly to a PCAP file.

- **Read-only**: No
- **Rate limit**: `live_capture` — 30/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `string` | *required* | Network interface |
| `output_file` | `string` | *required* | Output path (.pcap, .pcapng, .cap) |
| `duration` | `int` | `10` | Max duration in seconds |
| `packet_count` | `int` | `500` | Max packets |
| `bpf_filter` | `string` | `""` | BPF filter |

Returns: `{ interface, duration, filter, packets_captured, output_file, file_size_bytes }`

#### `analyze_large_pcap`
Analyze a large PCAP file in chunks for memory efficiency.

Processes packets in batches, accumulating protocol, source IP, and destination IP statistics.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `chunk_size` | `int` | `10000` | Number of packets per processing chunk |
| `display_filter` | `string` | `""` | Optional Wireshark display filter |

Returns: `{ total_packets, chunks_processed, top_protocols[], top_source_ips[], top_dest_ips[] }`

---

### 2. Protocol Analysis (10 tools)

#### `analyze_pcap_file`
Analyze a PCAP file with optional display filters.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `display_filter` | `string` | `""` | Wireshark display filter |
| `max_packets` | `int` | `10000` | Max packets to analyze |

Returns: `{ filepath, total_packets, unique_ips[], protocol_stats: {}, packets[] }`

#### `get_protocol_statistics`
Protocol hierarchy statistics from a PCAP file.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |

Returns: `{ filepath, total_frames, protocols: { name: { frames, bytes } } }`

#### `get_capture_file_info`
Metadata about a PCAP file (via capinfos).

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |

Returns: capinfos key-value dict

#### `capture_targeted_traffic`
Capture traffic filtered by host, port, or protocol.

- **Read-only**: No
- **Rate limit**: `live_capture` — 30/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `string` | *required* | Network interface |
| `target_host` | `string` | `""` | Filter by host IP |
| `target_port` | `int` | `0` | Filter by port |
| `protocol` | `string` | `""` | Filter by protocol (tcp, udp, icmp, arp, ip, ip6, http, https) |
| `duration` | `int` | `10` | Max duration in seconds |
| `packet_limit` | `int` | `500` | Max packets |

Returns: `{ interface, filter, duration, packets_captured, pcap_file, packets[] }`

#### `analyze_http_traffic`
Extract HTTP methods, hosts, URIs, user agents, and status codes.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |

Returns: `{ filepath, total_http_requests, methods: {}, hosts: {}, status_codes: {}, sample_requests[] }`

#### `detect_network_protocols`
Detect protocols from PCAP file or live capture.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | `""` | Path to PCAP file (optional) |
| `interface` | `string` | `""` | Interface for live capture (if no file) |
| `duration` | `int` | `10` | Duration for live capture |

Returns: `{ source, total_protocols, protocols: {}, insights[] }`

#### `analyze_http_headers`
Analyze HTTP headers — auth tokens, cookies, suspicious headers (e.g., X-Forwarded-For spoofing).

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `include_cookies` | `bool` | `true` | Include cookie analysis |

Returns: `{ filepath, auth_tokens_found, cookies_found, suspicious_headers, unique_user_agents, auth_tokens[], cookies[], suspicious[], user_agents[] }`

#### `geoip_lookup`
Geographic IP lookup using MaxMind GeoLite2. Can check specific IPs or extract all from a PCAP file.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ip_addresses` | `string` | *required* | Comma-separated IPs (e.g., '1.1.1.1,8.8.8.8') |
| `filepath` | `string` | `""` | PCAP file to extract IPs from (overrides ip_addresses) |

Returns: `{ total_ips, countries: {}, results[] }`

#### `analyze_dns_traffic`
Analyze DNS queries and responses from a PCAP file. Extracts query names, types, response codes, and detects potential DNS tunneling (unusually long subdomain names).

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `max_queries` | `int` | `1000` | Maximum DNS rows to process |

Returns: `{ total_dns_packets, unique_queries, top_domains[], nxdomain_count, nxdomains[], suspicious_domains[], potential_tunneling: bool }`

Example:
```json
{
  "total_dns_packets": 342,
  "unique_queries": 87,
  "top_domains": [{"domain": "example.com", "count": 45}],
  "nxdomain_count": 3,
  "suspicious_domains": [],
  "potential_tunneling": false
}
```

#### `get_expert_info`
Extract Wireshark expert information from a PCAP file. Returns warnings, errors, notes, and chats from Wireshark's expert system — useful for identifying protocol violations, malformed packets, retransmissions, etc.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |

Returns: `{ errors[], warnings[], notes[], chats[], summary: { error_count, warning_count, note_count, chat_count } }`

Example:
```json
{
  "errors": ["Frame 42: TCP segment not captured"],
  "warnings": ["Frame 100: TCP retransmission"],
  "summary": { "error_count": 1, "warning_count": 5, "note_count": 12, "chat_count": 3 }
}
```

---

### 3. Network Flows (2 tools)

#### `visualize_network_flows`
Generate visual diagrams of network flows from a PCAP file. Produces ASCII art or Mermaid sequence diagrams showing packet exchanges between endpoints.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `flow_type` | `string` | `"tcp"` | Protocol type: `tcp` or `udp` |
| `max_flows` | `int` | `20` | Max packet arrows to include (1–200) |
| `output_format` | `string` | `"text"` | Diagram format: `text` (ASCII art) or `mermaid` |

Returns: `{ filepath, flow_type, flow_count, diagram: string, flows[] }`

Example (Mermaid output):
```
sequenceDiagram
    participant A as 10.0.0.1:443
    participant B as 10.0.0.2:52314
    A->>B: TCP SYN,ACK
    B->>A: HTTP GET /api/data
```

Example (ASCII text output):
```
┌────────────────┐                    ┌────────────────┐
│  10.0.0.1:443  │                    │ 10.0.0.2:52314 │
└───────┬────────┘                    └───────┬────────┘
        │── TCP SYN ──────────────────────────>│
        │<───────────────────── TCP SYN,ACK ───│
```

#### `decrypt_tls_traffic`
Decrypt TLS/HTTPS traffic using an SSLKEYLOGFILE. Requires a TLS key log file (NSS Key Log Format) captured alongside the traffic.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file containing TLS traffic |
| `keylog_file` | `string` | `""` | Path to TLS key log file (NSS format); falls back to `SSLKEYLOGFILE` env var |
| `output_file` | `string` | `""` | Optional path to write decrypted pcapng |

Returns: `{ filepath, keylog_file, decrypted_packets, http_requests[], http_responses[], output_file? }`

Example:
```json
{
  "decrypted_packets": 24,
  "http_requests": [{"method": "GET", "host": "api.example.com", "uri": "/v1/users", "frame": "42"}],
  "http_responses": [{"code": "200", "content_type": "application/json", "frame": "45"}]
}
```

---

### 4. Security (3 tools)

#### `extract_credentials`
Extract credentials from PCAP: HTTP Basic Auth, FTP, Telnet, Kerberos.

- **Read-only**: Yes
- **Audit logged**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |

Returns:
```json
{
  "filepath": "capture.pcap",
  "plaintext_count": 2,
  "encrypted_count": 1,
  "plaintext": [
    { "type": "HTTP Basic Auth", "username": "admin", "password": "***", "frame": "42" },
    { "type": "FTP", "username": "user", "password": "***", "frame": "87" }
  ],
  "encrypted": [
    { "type": "Kerberos", "hash": "$krb5asrep$23$...", "username": "jdoe", "realm": "CORP.LOCAL", "frame": "156", "cracking_command": "hashcat -m 18200 hash.txt wordlist.txt" }
  ]
}
```

Kerberos hash formats:
- AS-REQ/TGS-REQ (msg_type 10/30): `$krb5pa$23$<cname>$<realm>$<cipher>` → `hashcat -m 7500`
- AS-REP (msg_type 11): `$krb5asrep$23$<cname>@<realm>$<cipher>` → `hashcat -m 18200`

#### `check_ip_threat_intel`
Check an IP address against threat intelligence feeds.

- **Read-only**: Yes
- **Rate limit**: `threat_intel` — 100/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ip_address` | `string` | *required* | IP address to check |
| `providers` | `string` | `"urlhaus,abuseipdb"` | Providers to check |

Returns: `{ ip, providers: {}, is_threat: bool, threat_providers[] }`

#### `scan_capture_for_threats`
Extract all IPs from a PCAP file and check against threat feeds.

- **Read-only**: Yes
- **Rate limit**: `threat_scan` — 10/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `providers` | `string` | `"urlhaus,abuseipdb"` | Providers to check |

Returns: `{ filepath, total_ips, threats_found, threat_ips[], ip_results: {} }`

---

### 5. PCAP Tools (4 tools)

#### `diff_pcap_files`
Compare two PCAP files and report differences in packet counts, unique IPs, and protocol distributions.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath1` | `string` | *required* | Path to first PCAP file |
| `filepath2` | `string` | *required* | Path to second PCAP file |
| `display_filter` | `string` | `""` | Optional Wireshark display filter applied to both |

Returns: `{ file1_packets, file2_packets, only_in_file1_ips[], only_in_file2_ips[], protocol_diff: {}, summary: string }`

Example:
```json
{
  "file1_packets": 1200,
  "file2_packets": 980,
  "only_in_file1_ips": ["10.0.0.5"],
  "only_in_file2_ips": ["10.0.0.99"],
  "protocol_diff": { "dns": { "file1_frames": 42, "file2_frames": 18 } },
  "summary": "File1: 1200 packets, File2: 980 packets. 1 IPs only in file1, 1 IPs only in file2, 1 protocol differences."
}
```

#### `merge_pcap_files`
Merge multiple PCAP files into one using mergecap.

- **Read-only**: No

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepaths` | `list[string]` | *required* | List of PCAP file paths to merge |
| `output_file` | `string` | *required* | Output file path (.pcap or .pcapng) |
| `chronological` | `bool` | `true` | Merge by timestamp (true) or append in order (false) |

Returns: `{ output_file, files_merged, file_size_bytes }`

#### `slice_pcap`
Slice or filter a PCAP file using editcap. Extract packets by number range, time range, or remove duplicates.

- **Read-only**: No

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to input PCAP file |
| `output_file` | `string` | *required* | Output file path (.pcap or .pcapng) |
| `start_packet` | `int` | `0` | First packet number to keep (1-based) |
| `end_packet` | `int` | `0` | Last packet number to keep |
| `start_time` | `string` | `""` | Keep packets after this time (editcap `-A` format) |
| `end_time` | `string` | `""` | Keep packets before this time (editcap `-B` format) |
| `remove_duplicates` | `bool` | `false` | Remove duplicate packets |

Returns: `{ input_file, output_file, operation: string, file_size_bytes }`

#### `decode_packet`
Decode a single packet in full detail. Returns verbose text decode or JSON layers for a specific packet number.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP file |
| `packet_number` | `int` | *required* | Packet number to decode (1-based) |
| `verbose` | `bool` | `true` | If true, return verbose text decode; if false, return JSON layers |

Returns: `{ filepath, packet_number, layers[], raw_output: string }`

---

### 6. Network Scanning (6 tools)

All nmap tools: Rate limit `nmap_scan` — 10/hour. Marked as destructive.

#### `nmap_port_scan`
Scan target for open ports.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *required* | IP, hostname, or CIDR range |
| `ports` | `string` | `""` | Port spec (e.g., '80,443', '1-1024') |
| `scan_type` | `string` | `"connect"` | syn (needs root), connect (TCP), udp |

Returns: `{ target, scan_type, result: {} }`

#### `nmap_service_detection`
Detect service versions on open ports.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *required* | IP or hostname |
| `ports` | `string` | `""` | Port spec (optional) |

Returns: `{ target, result: {} }`

#### `nmap_os_detection`
OS fingerprinting (requires root/admin).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *required* | IP or hostname |

Returns: `{ target, result: {} }`

#### `nmap_vulnerability_scan`
Run NSE vulnerability scripts against a target.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *required* | IP or hostname |
| `ports` | `string` | `""` | Port spec (optional) |

Returns: `{ target, result: {} }`

#### `nmap_quick_scan`
Quick scan of top 100 ports.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *required* | IP or hostname |

Returns: `{ target, result: {} }`

#### `nmap_comprehensive_scan`
Full scan: SYN + service detection + OS + default scripts.

Nmap args: `-sS -sV -O -sC -T4 --version-all`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `string` | *required* | IP or hostname |

Returns: `{ target, result: {} }`

---

### 7. Export (3 tools)

#### `export_packets_json`
Export packets as structured JSON.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `display_filter` | `string` | `""` | Wireshark display filter |
| `max_packets` | `int` | `10000` | Max packets to export |

Returns: `{ filepath, packet_count, packets[] }`

#### `export_packets_csv`
Export specific fields as CSV.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `fields` | `string` | `""` | Comma-separated fields (default: standard set) |
| `display_filter` | `string` | `""` | Wireshark display filter |

Default fields: `frame.number`, `frame.time`, `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`, `frame.protocols`, `frame.len`

Returns: `{ filepath, row_count, csv: string }`

#### `convert_pcap_format`
Convert between pcap and pcapng formats.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Source PCAP file |
| `output_format` | `string` | `"pcapng"` | Target: pcap or pcapng |

Returns: `{ input, output, format }`

---

### 8. Wireshark Profiles (4 tools)

#### `list_wireshark_profiles`
List available Wireshark profiles and their configuration files. Scans standard profile directories on macOS and Linux.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| *(none)* | — | — | — |

Returns: `{ profiles[{ name, path, has_colorfilters, has_preferences, has_decode_as }], default_profile_path }`

#### `apply_profile_capture`
Analyze a PCAP file using a specific Wireshark profile's configuration (preferences, decode-as rules, etc.).

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `profile_name` | `string` | *required* | Wireshark profile name to apply |
| `display_filter` | `string` | `""` | Optional Wireshark display filter |
| `max_packets` | `int` | `10000` | Maximum packets to return |

Returns: `{ filepath, profile, packets_analyzed, packets[] }`

#### `get_color_filters`
Read Wireshark color filter rules from a profile or the default config. Parses the `colorfilters` file into structured data.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile_name` | `string` | `""` | Profile name (empty uses default config) |

Returns: `{ profile, filter_count, filters[{ name, display_filter, foreground_rgb, background_rgb, enabled }] }`

Example:
```json
{
  "profile": "default",
  "filter_count": 15,
  "filters": [
    { "name": "Bad TCP", "display_filter": "tcp.analysis.flags", "foreground_rgb": [0,0,0], "background_rgb": [65535,0,0], "enabled": true }
  ]
}
```

#### `capture_with_profile`
Live capture using a Wireshark profile's configuration.

- **Read-only**: No
- **Rate limit**: `profile_capture` — 30/hour

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `string` | *required* | Network interface (e.g., eth0, en0) |
| `profile_name` | `string` | *required* | Wireshark profile name to apply |
| `duration` | `int` | `10` | Capture duration in seconds |
| `packet_count` | `int` | `500` | Maximum packets |

Returns: `{ interface, profile, packets_captured, packets[] }`

---

### 9. Stream Analysis (3 tools)

#### `follow_tcp_stream`
Reconstruct a TCP conversation from a PCAP file.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `stream_index` | `int` | `0` | TCP stream index (0-based) |
| `output_format` | `string` | `"ascii"` | Format: ascii, hex, raw |

Returns: `{ filepath, stream_index, content }`

#### `follow_udp_stream`
Reconstruct a UDP conversation from a PCAP file.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |
| `stream_index` | `int` | `0` | UDP stream index (0-based) |
| `output_format` | `string` | `"ascii"` | Format: ascii, hex, raw |

Returns: `{ filepath, stream_index, content }`

#### `list_tcp_streams`
List all TCP conversations found in a PCAP file.

- **Read-only**: Yes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | `string` | *required* | Path to PCAP/PCAPNG file |

Returns: `{ filepath, stream_count, streams[{ endpoint_a, endpoint_b, raw_output }] }`

---

## Resources

### `netmcp://interfaces`
Dynamic list of available network interfaces.

Returns:
```json
{ "count": 3, "interfaces": ["eth0", "lo", "wlan0"] }
```

### `netmcp://captures`
Available PCAP files in common directories (`~/captures`, `~/pcaps`, current directory).

Returns:
```json
{ "count": 2, "files": [{ "path": "/home/user/captures/trace.pcap", "size_mb": 12.5 }] }
```

### `netmcp://system/info`
System capabilities and tool availability. Dynamically lists all registered tools.

Returns:
```json
{
  "python_version": "3.11.9",
  "platform": "Linux-6.1",
  "tshark_available": true,
  "tshark_path": "/usr/bin/tshark",
  "nmap_available": true,
  "tools": ["get_network_interfaces", "capture_live_packets", "..."]
}
```

---

## Prompts

### `security_audit`
Comprehensive security audit of a PCAP file.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `filepath` | `string` | Yes | Path to PCAP file to audit |

Workflow: protocol stats → extract credentials → scan threats → analyze HTTP → list TCP streams

### `network_troubleshooting`
Network diagnostics through traffic analysis.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `interface` | `string` | `"eth0"` | Network interface |
| `duration` | `int` | `10` | Capture duration |

Workflow: capture live → protocol stats → identify top talkers → check anomalies

### `incident_response`
Security incident investigation.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `target` | `string` | Yes | Target IP or hostname |

Workflow: nmap quick scan → threat intel → vuln scan → comprehensive scan → capture traffic

### `traffic_analysis`
Deep traffic analysis with protocol breakdown and GeoIP mapping.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `filepath` | `string` | Yes | Path to PCAP file |

Workflow: protocol stats → HTTP traffic → HTTP headers → GeoIP lookup → extract credentials

### `network_baseline`
Establish network baseline for normal traffic patterns.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `interface` | `string` | `"eth0"` | Network interface |
| `duration` | `int` | `30` | Capture duration |

Workflow: quick capture → extended capture → protocol stats → list TCP streams

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| `NETMCP_001` | Internal | Unexpected internal error |
| `NETMCP_002` | Validation | Input validation failure |
| `NETMCP_003` | Tool Execution | External tool error (tshark, nmap) |
| `NETMCP_004` | File Error | File not found, permission, or format error |
| `NETMCP_005` | Timeout | Operation timed out |
| `NETMCP_006` | Rate Limited | Rate limit exceeded |
| `NETMCP_007` | Permission | Insufficient permissions |
| `NETMCP_008` | Not Available | Required tool not installed |

---

## Rate Limits

| Operation | Limit | Applied To |
|-----------|-------|------------|
| `live_capture` | 30/hour | All capture tools |
| `profile_capture` | 30/hour | Profile-based capture tools |
| `nmap_scan` | 10/hour | All nmap tools |
| `threat_intel` | 100/hour | IP reputation checks |
| `threat_scan` | 10/hour | PCAP-wide threat scans |
