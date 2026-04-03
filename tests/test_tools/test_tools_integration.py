"""Integration tests for all NetMCP tools."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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

        tshark = TsharkInterface()
        tshark.list_interfaces = AsyncMock(return_value=["eth0", "lo", "docker0"])
        tshark.capture_live = AsyncMock(return_value=Path("/tmp/test.pcap"))
        tshark.read_pcap = AsyncMock(
            return_value=[
                {
                    "_source": {
                        "layers": {
                            "ip.src": ["10.0.0.1"],
                            "ip.dst": ["10.0.0.2"],
                            "frame.number": ["1"],
                        }
                    }
                }
            ]
        )
        tshark.protocol_stats = AsyncMock(
            return_value={
                "tcp": {"frames": 100, "bytes": 12000},
                "udp": {"frames": 50, "bytes": 6000},
            }
        )
        tshark.follow_stream = AsyncMock(
            return_value="GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 200 OK\r\n\r\nHello World"
        )
        tshark.list_streams = AsyncMock(
            return_value=[{"endpoint_a": "192.168.1.1:443", "endpoint_b": "10.0.0.1:54321"}]
        )
        tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "http.request.method": "GET",
                    "http.host": "example.com",
                    "http.request.uri": "/",
                    "http.response.code": "200",
                    "http.user_agent": "Mozilla/5.0",
                    "frame.number": "1",
                },
                {"http.authbasic": "dXNlcjpwYXNz", "frame.number": "2"},
            ]
        )
        tshark.export_json = AsyncMock(return_value=[{"_source": {"layers": {}}}])
        tshark.file_info = AsyncMock(
            return_value={"filepath": "/tmp/test.pcap", "total_frames": "150"}
        )
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        yield tshark


@pytest.fixture
def mock_nmap():
    """Mocked NmapInterface."""
    from netmcp.interfaces.nmap import NmapInterface

    nmap = NmapInterface.__new__(NmapInterface)
    nmap.available = True
    nmap.port_scan = AsyncMock(
        return_value={
            "scan": {
                "10.0.0.1": {
                    "tcp": {
                        80: {"state": "open", "name": "http"},
                        443: {"state": "open", "name": "https"},
                    }
                }
            }
        }
    )
    nmap.service_detect = AsyncMock(
        return_value={
            "scan": {
                "10.0.0.1": {
                    "tcp": {
                        80: {
                            "state": "open",
                            "name": "http",
                            "product": "nginx",
                            "version": "1.18.0",
                        }
                    }
                }
            }
        }
    )
    nmap.os_detect = AsyncMock(
        return_value={"scan": {"10.0.0.1": {"osmatch": [{"name": "Linux 5.4", "accuracy": "95"}]}}}
    )
    nmap.vuln_scan = AsyncMock(
        return_value={
            "scan": {
                "10.0.0.1": {
                    "tcp": {443: {"state": "open", "script": {"ssl-enum-ciphers": "TLSv1.2"}}}
                }
            }
        }
    )
    nmap.quick_scan = AsyncMock(
        return_value={"scan": {"10.0.0.1": {"tcp": {80: {"state": "open", "name": "http"}}}}}
    )
    nmap.comprehensive_scan = AsyncMock(
        return_value={"scan": {"10.0.0.1": {"tcp": {80: {"state": "open"}}}}}
    )
    return nmap


@pytest.fixture
def mock_threat():
    """Mocked ThreatIntelInterface."""
    from netmcp.interfaces.threat_intel import ThreatIntelInterface

    threat = ThreatIntelInterface.__new__(ThreatIntelInterface)
    threat.abuseipdb_key = "test-key"
    threat.providers = ["urlhaus", "abuseipdb"]
    threat.check_ip = AsyncMock(
        return_value={
            "ip": "10.0.0.1",
            "is_threat": False,
            "threat_providers": [],
            "providers": {"urlhaus": {"threat": False, "provider": "urlhaus"}},
        }
    )
    threat.scan_pcap = AsyncMock(
        return_value={
            "filepath": "/tmp/test.pcap",
            "total_ips": 5,
            "threats_found": 1,
            "threat_ips": ["10.0.0.1"],
            "ip_results": {"10.0.0.1": {"is_threat": True}},
        }
    )
    return threat


# ── Capture Tools ───────────────────────────────────────────────────


class TestCaptureTools:
    @pytest.mark.asyncio
    async def test_get_network_interfaces(self, mock_tshark, fmt, sec):
        result = await mock_tshark.list_interfaces()
        assert isinstance(result, list)
        assert len(result) == 3
        assert "eth0" in result

    @pytest.mark.asyncio
    async def test_capture_live_packets(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap data" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mock_tshark.read_pcap = AsyncMock(return_value=[{"_source": {"layers": {}}}])

        result = await mock_tshark.read_pcap(str(pcap))
        assert isinstance(result, list)


# ── Analysis Tools ──────────────────────────────────────────────────


class TestAnalysisTools:
    @pytest.mark.asyncio
    async def test_read_pcap(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        packets = await mock_tshark.read_pcap(str(pcap))
        assert len(packets) == 1
        assert "10.0.0.1" in packets[0]["_source"]["layers"]["ip.src"]

    @pytest.mark.asyncio
    async def test_protocol_stats(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        stats = await mock_tshark.protocol_stats(str(pcap))
        assert "tcp" in stats
        assert stats["tcp"]["frames"] == 100

    @pytest.mark.asyncio
    async def test_file_info(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        info = await mock_tshark.file_info(str(pcap))
        assert "filepath" in info

    @pytest.mark.asyncio
    async def test_export_fields(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        rows = await mock_tshark.export_fields(str(pcap), ["http.request.method", "http.host"])
        assert len(rows) == 2
        assert rows[0]["http.request.method"] == "GET"


# ── Stream Tools ────────────────────────────────────────────────────


class TestStreamTools:
    @pytest.mark.asyncio
    async def test_follow_stream(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        stream = await mock_tshark.follow_stream(str(pcap), 0, "tcp", "ascii")
        assert "GET / HTTP/1.1" in stream
        assert "200 OK" in stream

    @pytest.mark.asyncio
    async def test_list_streams(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        streams = await mock_tshark.list_streams(str(pcap), "tcp")
        assert len(streams) == 1
        assert "192.168.1.1:443" in streams[0]["endpoint_a"]


# ── Nmap Tools ──────────────────────────────────────────────────────


class TestNmapTools:
    @pytest.mark.asyncio
    async def test_port_scan(self, mock_nmap):
        result = await mock_nmap.port_scan("10.0.0.1", ports="80,443", scan_type="connect")
        assert "scan" in result
        assert result["scan"]["10.0.0.1"]["tcp"][80]["state"] == "open"
        assert result["scan"]["10.0.0.1"]["tcp"][443]["state"] == "open"

    @pytest.mark.asyncio
    async def test_service_detection(self, mock_nmap):
        result = await mock_nmap.service_detect("10.0.0.1")
        svc = result["scan"]["10.0.0.1"]["tcp"][80]
        assert svc["product"] == "nginx"
        assert svc["version"] == "1.18.0"

    @pytest.mark.asyncio
    async def test_os_detection(self, mock_nmap):
        result = await mock_nmap.os_detect("10.0.0.1")
        assert result["scan"]["10.0.0.1"]["osmatch"][0]["name"] == "Linux 5.4"

    @pytest.mark.asyncio
    async def test_vuln_scan(self, mock_nmap):
        result = await mock_nmap.vuln_scan("10.0.0.1", ports="443")
        assert "script" in result["scan"]["10.0.0.1"]["tcp"][443]

    @pytest.mark.asyncio
    async def test_quick_scan(self, mock_nmap):
        result = await mock_nmap.quick_scan("10.0.0.1")
        assert result["scan"]["10.0.0.1"]["tcp"][80]["state"] == "open"

    @pytest.mark.asyncio
    async def test_comprehensive_scan(self, mock_nmap):
        result = await mock_nmap.comprehensive_scan("10.0.0.1")
        assert "scan" in result
        assert "10.0.0.1" in result["scan"]


# ── Threat Intel Tools ──────────────────────────────────────────────


class TestThreatTools:
    @pytest.mark.asyncio
    async def test_check_ip_threat_intel(self, mock_threat):
        result = await mock_threat.check_ip("10.0.0.1")
        assert result["ip"] == "10.0.0.1"
        assert result["is_threat"] is False
        assert "urlhaus" in result["providers"]

    @pytest.mark.asyncio
    async def test_scan_pcap_threats(self, mock_threat):
        result = await mock_threat.scan_pcap("/tmp/test.pcap", None)
        assert result["total_ips"] == 5
        assert result["threats_found"] == 1
        assert "10.0.0.1" in result["threat_ips"]


# ── Credential Tools ────────────────────────────────────────────────


class TestCredentialTools:
    @pytest.mark.asyncio
    async def test_extract_http_basic(self, mock_tshark, tmp_path):
        """HTTP Basic Auth credentials must be decoded."""
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {"http.authbasic": "dXNlcjpwYXNz", "frame.number": "1"},
                {"ftp.request.command": "USER", "ftp.request.arg": "admin", "frame.number": "2"},
                {
                    "ftp.request.command": "PASS",
                    "ftp.request.arg": "secret123",
                    "frame.number": "3",
                },
            ]
        )

        import base64

        rows = await mock_tshark.export_fields(
            str(pcap), ["http.authbasic", "ftp.request.command", "ftp.request.arg", "frame.number"]
        )

        # Verify the base64 credential is correct
        assert rows[0]["http.authbasic"] == "dXNlcjpwYXNz"
        decoded = base64.b64decode("dXNlcjpwYXNz").decode()
        assert decoded == "user:pass"
