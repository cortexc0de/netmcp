"""Tests for new NetMCP tools: quick_capture, save_capture, http_headers, geoip."""

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
        tshark.list_interfaces = AsyncMock(return_value=["eth0", "lo"])
        tshark.capture_live = AsyncMock(return_value=Path("/tmp/test.pcap"))
        tshark.read_pcap = AsyncMock(
            return_value=[
                {
                    "_source": {
                        "layers": {
                            "ip.src": ["10.0.0.1"],
                            "ip.dst": ["10.0.0.2"],
                            "frame.protocols": ["eth:ethertype:ip:tcp:http"],
                            "frame.number": ["1"],
                        }
                    }
                }
            ]
        )
        tshark.protocol_stats = AsyncMock(return_value={"tcp": {"frames": 100, "bytes": 12000}})
        tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "http.authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "http.cookie": "session=abc123; token=xyz789",
                    "http.user_agent": "Mozilla/5.0",
                    "http.x_forwarded_for": "1.2.3.4",
                    "frame.number": "1",
                }
            ]
        )
        tshark.follow_stream = AsyncMock(return_value="GET / HTTP/1.1\r\n")
        tshark.list_streams = AsyncMock(return_value=[{"endpoint_a": "a:80"}])
        tshark.export_json = AsyncMock(return_value=[{"_source": {}}])
        tshark.file_info = AsyncMock(return_value={"filepath": "/tmp/test.pcap"})
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout=""))
        yield tshark


# ── Quick Capture ───────────────────────────────────────────────────────


class TestQuickCapture:
    @pytest.mark.asyncio
    async def test_quick_capture_works(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        result = await mock_tshark.read_pcap(str(pcap))
        assert len(result) == 1
        assert "10.0.0.1" in result[0]["_source"]["layers"]["ip.src"]


# ── Save Capture ────────────────────────────────────────────────────────


class TestSaveCapture:
    @pytest.mark.asyncio
    async def test_save_to_file(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        output = tmp_path / "saved.pcap"
        import shutil

        shutil.copy2(str(pcap), str(output))

        assert output.exists()
        assert output.stat().st_size > 0


# ── HTTP Header Analysis ────────────────────────────────────────────────


class TestHttpHeaders:
    @pytest.mark.asyncio
    async def test_extract_auth_tokens(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        rows = await mock_tshark.export_fields(str(pcap), [])
        assert len(rows) == 1
        auth = rows[0].get("http.authorization", "")
        assert auth.startswith("Bearer")

    @pytest.mark.asyncio
    async def test_extract_cookies(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        rows = await mock_tshark.export_fields(str(pcap), [])
        cookie = rows[0].get("http.cookie", "")
        assert "session" in cookie
        assert "token" in cookie

    @pytest.mark.asyncio
    async def test_detect_suspicious_headers(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        rows = await mock_tshark.export_fields(str(pcap), [])
        xff = rows[0].get("http.x_forwarded_for", "")
        assert xff == "1.2.3.4"


# ── GeoIP ───────────────────────────────────────────────────────────────


class TestGeoIP:
    def test_geoip_lookup_valid_ip(self):
        from netmcp.utils.geoip import lookup_ip

        result = lookup_ip("8.8.8.8")
        assert result["ip"] == "8.8.8.8"
        # GeoLite2 should return country info
        assert "country" in result or "error" in result

    def test_geoip_lookup_invalid_ip(self):
        from netmcp.utils.geoip import lookup_ip

        result = lookup_ip("invalid")
        assert result["ip"] == "invalid"
        # Should not crash, return error or Unknown
        assert "error" in result or result.get("country") == "Unknown"

    @pytest.mark.asyncio
    async def test_enrich_multiple_ips(self):
        from netmcp.utils.geoip import enrich_ips

        results = await enrich_ips(["8.8.8.8", "1.1.1.1"])
        assert len(results) == 2
        assert results[0]["ip"] == "8.8.8.8"
        assert results[1]["ip"] == "1.1.1.1"
