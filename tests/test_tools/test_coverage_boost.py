"""Coverage-boosting tests for NetMCP tools."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator


@pytest.fixture
def fmt():
    return OutputFormatter()


@pytest.fixture
def sec():
    return SecurityValidator()


@pytest.fixture
def mock_tshark():
    """Fully mocked TsharkInterface."""
    with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
        from netmcp.interfaces.tshark import TsharkInterface

        t = TsharkInterface()
        t.list_interfaces = AsyncMock(return_value=["eth0", "lo"])
        t.capture_live = AsyncMock(return_value=Path("/tmp/test.pcap"))
        t.read_pcap = AsyncMock(
            return_value=[
                {
                    "_source": {
                        "layers": {
                            "ip.src": ["10.0.0.1"],
                            "ip.dst": ["10.0.0.2"],
                            "frame.number": ["1"],
                            "frame.protocols": ["eth:ip:tcp:http"],
                            "frame.len": ["100"],
                        }
                    }
                }
            ]
        )
        t.protocol_stats = AsyncMock(return_value={"tcp": {"frames": 100, "bytes": 12000}})
        t.follow_stream = AsyncMock(return_value="GET / HTTP/1.1\r\n\r\nHTTP/1.1 200 OK")
        t.list_streams = AsyncMock(return_value=[{"endpoint_a": "a:80", "endpoint_b": "b:443"}])
        t.export_fields = AsyncMock(
            return_value=[
                {
                    "http.request.method": "GET",
                    "http.host": "example.com",
                    "http.request.uri": "/",
                    "http.response.code": "200",
                    "http.user_agent": "Mozilla/5.0",
                    "http.authorization": "",
                    "http.cookie": "",
                    "http.x_forwarded_for": "",
                    "frame.number": "1",
                },
                {
                    "http.authbasic": "dXNlcjpwYXNz",
                    "ftp.request.command": "",
                    "ftp.request.arg": "",
                    "telnet.data": "",
                    "frame.number": "2",
                },
            ]
        )
        t.export_json = AsyncMock(return_value=[{"_source": {"layers": {}}}])
        t.file_info = AsyncMock(return_value={"filepath": "/tmp/test.pcap", "total_frames": "150"})
        t._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        yield t


async def call(mcp: FastMCP, name: str, **kwargs):
    """Helper to call a registered tool by name."""
    return await mcp._tool_manager.call_tool(name, kwargs)


# ── Analysis tools ────────────────────────────────────────────────────


class TestAnalysisCoverage:
    @pytest.mark.asyncio
    async def test_analyze_pcap_file(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_pcap_file", filepath=str(pcap), max_packets=50)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_get_protocol_statistics(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_protocol_statistics", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_get_capture_file_info(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_capture_file_info", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_analyze_http_traffic(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_http_traffic", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_detect_network_protocols_file(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "detect_network_protocols", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_detect_network_protocols_no_input(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "detect_network_protocols")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_analyze_http_headers(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_http_headers", filepath=str(pcap), include_cookies=True)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_geoip_from_pcap(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "geoip_lookup", ip_addresses="", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_geoip_direct(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "geoip_lookup", ip_addresses="8.8.8.8,1.1.1.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_geoip_no_input(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "geoip_lookup", ip_addresses="")
        assert result["isError"] is True


# ── Capture tools ─────────────────────────────────────────────────────


class TestCaptureCoverage:
    @pytest.mark.asyncio
    async def test_get_network_interfaces(self, mock_tshark, fmt, sec):
        from netmcp.tools.capture import register_capture_tools

        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_network_interfaces")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_capture_live_packets(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.capture import register_capture_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "capture_live_packets", interface="eth0", duration=5, packet_count=100
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_quick_capture(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.capture import register_capture_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "quick_capture", interface="eth0", packet_count=10)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_save_capture_to_file(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.capture import register_capture_tools

        pcap = tmp_path / "source.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "save_capture_to_file",
            interface="eth0",
            output_file=str(tmp_path / "saved.pcap"),
            duration=10,
        )
        assert result["isError"] is False


# ── Stream tools ──────────────────────────────────────────────────────


class TestStreamCoverage:
    @pytest.mark.asyncio
    async def test_follow_tcp_stream(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.streams import register_stream_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "follow_tcp_stream", filepath=str(pcap), stream_index=0)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_follow_udp_stream(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.streams import register_stream_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "follow_udp_stream", filepath=str(pcap), stream_index=0, output_format="hex"
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_list_tcp_streams(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.streams import register_stream_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "list_tcp_streams", filepath=str(pcap))
        assert result["isError"] is False


# ── Export tools ──────────────────────────────────────────────────────


class TestExportCoverage:
    @pytest.mark.asyncio
    async def test_export_json(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_json", filepath=str(pcap), max_packets=50)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_export_csv(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.export_fields = AsyncMock(
            return_value=[{"frame.number": "1", "ip.src": "10.0.0.1"}]
        )
        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_convert_pcap(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "convert_pcap_format", filepath=str(pcap), output_format="pcapng")
        assert result["isError"] is False


# ── Nmap tools ────────────────────────────────────────────────────────


class TestNmapCoverage:
    @pytest.mark.asyncio
    async def test_nmap_port_scan(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = True
        mock_nmap.port_scan = AsyncMock(
            return_value={"scan": {"10.0.0.1": {"tcp": {80: {"state": "open"}}}}}
        )
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(
            mcp, "nmap_port_scan", target="10.0.0.1", ports="80", scan_type="connect"
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_nmap_service_detection(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = True
        mock_nmap.service_detect = AsyncMock(
            return_value={"scan": {"10.0.0.1": {"tcp": {80: {"product": "nginx"}}}}}
        )
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(mcp, "nmap_service_detection", target="10.0.0.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_nmap_os_detection(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = True
        mock_nmap.os_detect = AsyncMock(
            return_value={"scan": {"10.0.0.1": {"osmatch": [{"name": "Linux"}]}}}
        )
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(mcp, "nmap_os_detection", target="10.0.0.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_nmap_vulnerability_scan(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = True
        mock_nmap.vuln_scan = AsyncMock(return_value={"scan": {"10.0.0.1": {"tcp": {}}}})
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(mcp, "nmap_vulnerability_scan", target="10.0.0.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_nmap_quick_scan(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = True
        mock_nmap.quick_scan = AsyncMock(
            return_value={"scan": {"10.0.0.1": {"tcp": {80: {"state": "open"}}}}}
        )
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(mcp, "nmap_quick_scan", target="10.0.0.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_nmap_comprehensive_scan(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = True
        mock_nmap.comprehensive_scan = AsyncMock(return_value={"scan": {"10.0.0.1": {}}})
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(mcp, "nmap_comprehensive_scan", target="10.0.0.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_nmap_not_available(self, fmt, sec):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = False
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        result = await call(mcp, "nmap_quick_scan", target="10.0.0.1")
        assert result["isError"] is True


# ── Threat tools ──────────────────────────────────────────────────────


class TestThreatCoverage:
    @pytest.mark.asyncio
    async def test_check_ip_threat_intel(self, fmt, sec):
        from netmcp.tools.threat_intel import register_threat_tools

        mock_tshark = MagicMock()
        mock_threat = MagicMock()
        mock_threat.check_ip = AsyncMock(
            return_value={
                "ip": "10.0.0.1",
                "is_threat": False,
                "providers": {"urlhaus": {"threat": False}},
            }
        )
        mcp = FastMCP("test")
        register_threat_tools(mcp, mock_tshark, mock_threat, fmt, sec)
        result = await call(mcp, "check_ip_threat_intel", ip_address="10.0.0.1")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_scan_capture_for_threats(self, fmt, sec):
        from netmcp.tools.threat_intel import register_threat_tools

        mock_tshark = MagicMock()
        mock_threat = MagicMock()
        mock_threat.scan_pcap = AsyncMock(
            return_value={
                "filepath": "/tmp/test.pcap",
                "total_ips": 5,
                "threats_found": 1,
                "threat_ips": ["10.0.0.1"],
            }
        )
        mcp = FastMCP("test")
        register_threat_tools(mcp, mock_tshark, mock_threat, fmt, sec)
        with patch.object(sec, 'sanitize_filepath', return_value=Path('/tmp/test.pcap')):
            result = await call(mcp, "scan_capture_for_threats", filepath="/tmp/test.pcap")
        assert result["isError"] is False
        return
        # unreachable
        assert result["isError"] is False


# ── Credential tools ──────────────────────────────────────────────────


class TestCredentialCoverage:
    @pytest.mark.asyncio
    async def test_extract_credentials(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.credentials import register_credential_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
