# Installation Guide

This guide covers installing NetMCP on Linux, macOS, and Windows, including prerequisites, permissions, and MCP client configuration.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
  - [From PyPI (coming soon)](#from-pypi)
  - [From Source](#from-source)
  - [From Docker (coming soon)](#from-docker)
- [Network Permissions](#network-permissions)
- [Configuration](#configuration)
- [MCP Client Setup](#mcp-client-setup)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software

| Software    | Version    | Purpose                              |
|-------------|------------|--------------------------------------|
| Python      | 3.11+      | Runtime environment                    |
| tshark      | 4.0+       | Packet capture and analysis            |
| Wireshark   | 4.0+       | Packet analysis (includes tshark)      |
| Nmap        | 7.80+      | Network scanning and service detection |

### Python Packages (installed automatically)

- `mcp[cli]>=1.0.0` — MCP protocol implementation
- `httpx>=0.27.0` — HTTP client for threat intelligence queries
- `python-nmap>=0.7.1` — Nmap Python bindings
- `pydantic>=2.0.0` — Input validation
- `maxminddb-geolite2>=2018.703` — GeoIP enrichment

## Installation Methods

### From PyPI

> **Note:** NetMCP is not yet published to PyPI. This section will be updated when the package is available.

```bash
pip install netmcp
```

### From Source

This is the recommended installation method for now.

1. **Clone the repository:**

   ```bash
   git clone https://github.com/luxvtz/netmcp.git
   cd netmcp
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install NetMCP:**

   ```bash
   pip install -e .
   ```

4. **Verify installation:**

   ```bash
   netmcp --help
   ```

### From Docker

> **Note:** Docker support is planned for a future release.

## Platform-Specific Setup

### Ubuntu / Debian

1. **Install prerequisites:**

   ```bash
   sudo apt update
   sudo apt install -y python3.11 python3.11-venv python3-pip
   sudo apt install -y wireshark nmap
   ```

   During the Wireshark installation, you may be asked whether non-superusers should be able to capture packets. Select **Yes** if you plan to run captures as a regular user.

2. **Set up network permissions** (see [Network Permissions](#network-permissions)).

### macOS

1. **Install prerequisites using Homebrew:**

   ```bash
   brew install python@3.11 wireshark nmap
   ```

2. **Grant terminal permissions:**

   macOS requires that terminal applications have permission to access the network. Go to:

   **System Settings > Privacy & Security > Developer Tools** — ensure your terminal app (Terminal.app, iTerm2, etc.) is enabled.

3. **tshark access:** macOS may prompt for accessibility permissions when tshark first runs. Grant the permission when prompted.

### Windows

1. **Install Python:**

   Download Python 3.11+ from [python.org](https://www.python.org/downloads/) and ensure "Add Python to PATH" is checked during installation.

2. **Install Wireshark:**

   Download the installer from [wireshark.org](https://www.wireshark.org/download.html). During installation:
   - Install **Npcap** (included in the installer) — this is required for packet capture.
   - Optionally install the USBPcap component for USB traffic.

3. **Install Nmap:**

   Download from [nmap.org/download](https://nmap.org/download.html).

4. **Run as Administrator:**

   Packet capture on Windows typically requires Administrator privileges. Run your terminal or MCP client as Administrator to use capture features.

## Network Permissions

NetMCP requires elevated permissions for packet capture. Use the minimum permissions necessary.

### Linux — Capabilities (Recommended)

Instead of running as root, grant `CAP_NET_RAW` and `CAP_NET_ADMIN` to tshark:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
```

Add your user to the `wireshark` group (if available):

```bash
sudo usermod -aG wireshark $USER
```

Log out and back in for group changes to take effect.

### macOS

No additional configuration is needed beyond the Developer Tools permission described above. However, you may need to run tshark with `sudo` for certain interfaces:

```bash
sudo tshark -i en0
```

### Windows

Run your terminal or MCP client **as Administrator** to enable packet capture. Npcap must be installed (comes with the Wireshark installer).

## Configuration

NetMCP is configured via environment variables.

### Environment Variables

| Variable                 | Description                                      | Default         |
|--------------------------|--------------------------------------------------|-----------------|
| `NETMCP_TSHARK_PATH`     | Path to the tshark binary                        | `tshark`        |
| `NETMCP_NMAP_PATH`       | Path to the nmap binary                          | `nmap`          |
| `NETMCP_CAPTURE_DIR`     | Directory to store capture files                 | `/tmp/netmcp`   |
| `NETMCP_GEOIP_PATH`      | Path to the GeoLite2 database file               | Auto-detected   |
| `NETMCP_THREAT_KEY`      | API key for threat intelligence services         | _(none)_        |
| `NETMCP_LOG_LEVEL`       | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO`      |

### Setting Environment Variables

**Linux/macOS (bash/zsh):**

```bash
export NETMCP_TSHARK_PATH=/usr/bin/tshark
export NETMCP_CAPTURE_DIR=/tmp/netmcp
```

**Windows (PowerShell):**

```powershell
$env:NETMCP_TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
$env:NETMCP_CAPTURE_DIR = "$env:TEMP\netmcp"
```

To make variables persistent, add them to your shell profile (`~/.bashrc`, `~/.zshrc`, or `$PROFILE`).

## MCP Client Setup

NetMCP works with any MCP-compatible client. Here are configurations for common clients.

### Claude Desktop

Add NetMCP to your Claude Desktop configuration:

1. Open Claude Desktop settings.
2. Navigate to the MCP servers section.
3. Add the following server configuration:

```json
{
  "mcpServers": {
    "netmcp": {
      "command": "python",
      "args": ["-m", "netmcp.server"],
      "env": {
        "NETMCP_CAPTURE_DIR": "/tmp/netmcp",
        "NETMCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Cursor

In Cursor settings, navigate to **Features > MCP Servers** and add:

- **Name:** `netmcp`
- **Type:** `stdio`
- **Command:** `python -m netmcp.server`
- **Environment variables:** Set as needed (see [Configuration](#configuration)).

### Custom MCP Client

Connect to NetMCP using the stdio transport:

```python
from mcp import ClientSession, StdioServerParameters

server_params = StdioServerParameters(
    command="python",
    args=["-m", "netmcp.server"],
)

async with ClientSession(server_params) as session:
    # List available tools
    tools = await session.list_tools()
    # Call a tool
    result = await session.call_tool("capture_list_interfaces", {})
```

### Direct CLI

You can also run NetMCP directly for testing:

```bash
python -m netmcp.server
```

This starts the MCP server on stdio. You can interact with it using the MCP CLI:

```bash
mcp client python -m netmcp.server
```

## Troubleshooting

### tshark not found

**Error:** `tshark: command not found` or `FileNotFoundError: tshark`

**Solution:**
- Ensure Wireshark/tshark is installed: `tshark --version`
- Set the `NETMCP_TSHARK_PATH` environment variable to the full path of tshark.
- Ensure tshark is in your `PATH`.

### Permission denied on capture

**Error:** `You don't have permission to capture on that device`

**Solution:**
- **Linux:** Set capabilities on dumpcap/tshark (see [Linux — Capabilities](#linux--capabilities-recommended)).
- **macOS:** Run with `sudo` or grant Developer Tools permission.
- **Windows:** Run your terminal/MCP client as Administrator.

### Nmap scan fails

**Error:** `Host seems down` or scan returns no results.

**Solution:**
- Ensure the target host is reachable from your network.
- Try adding `-Pn` to skip host discovery (in the scan options).
- Check firewall rules that may be blocking scan traffic.
- Ensure Nmap is installed: `nmap --version`.

### GeoIP enrichment not working

**Error:** GeoIP data is missing or shows `unknown` locations.

**Solution:**
- Ensure the `maxminddb-geolite2` package is installed: `pip show maxminddb-geolite2`.
- Set `NETMCP_GEOIP_PATH` to the correct path of the GeoLite2 database.
- Note: GeoLite2 databases may require a free MaxMind account to download the latest version.

### MCP client cannot connect

**Error:** Client fails to start or tools are not listed.

**Solution:**
- Verify NetMCP starts correctly: `python -m netmcp.server` (should not exit immediately).
- Check Python version: `python --version` (must be 3.11+).
- Ensure all dependencies are installed: `pip install -e .`
- Check logs by setting `NETMCP_LOG_LEVEL=DEBUG`.

### Import errors

**Error:** `ModuleNotFoundError: No module named 'netmcp'`

**Solution:**
- Ensure you installed in editable mode: `pip install -e .`
- Verify the virtual environment is activated: `which python` should point to `.venv/bin/python`.
- Reinstall: `pip install --force-reinstall -e .`

### High memory usage during capture

**Solution:**
- Limit capture size with the `max_packets` parameter when starting captures.
- Stop captures when not actively analyzing with `capture_stop`.
- Set a reasonable `NETMCP_CAPTURE_DIR` on a filesystem with adequate space.

---

For additional help, see the [README](README.md) or open an [issue](https://github.com/luxvtz/netmcp/issues).
