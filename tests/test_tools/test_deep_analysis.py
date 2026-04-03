"""Tests for deep packet analysis, report generation, and capture info tools."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface
from netmcp.tools.advanced import register_advanced_tools
from netmcp.tools.analysis import register_analysis_tools


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
        tshark = TsharkInterface()
        tshark.read_pcap = AsyncMock(return_value=[])
        tshark.protocol_stats = AsyncMock(return_value={})
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        yield tshark


async def call(mcp: FastMCP, name: str, **kwargs):
    """Helper to call a registered tool by name."""
    return await mcp._tool_manager.call_tool(name, kwargs)


def _make_tshark_json_packets(n: int = 3) -> str:
    """Build fake tshark -T json output."""
    packets = []
    for i in range(n):
        packets.append(
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": str(i + 1),
                            "frame.time_epoch": str(1704067200.0 + i * 0.5),
                            "frame.protocols": "eth:ethertype:ip:tcp:http",
                            "frame.len": str(200 + i * 10),
                        },
                        "ip": {
                            "ip.src": "192.168.1.1",
                            "ip.dst": "10.0.0.1",
                        },
                        "tcp": {
                            "tcp.srcport": "443",
                            "tcp.dstport": "54321",
                        },
                        "http": {
                            "http.request.method": "GET",
                            "http.host": "example.com",
                        },
                    }
                }
            }
        )
    return json.dumps(packets)


# ── deep_packet_analysis ────────────────────────────────────────────────


class TestDeepPacketAnalysis:
    @pytest.mark.asyncio
    @patch("shutil.which", return_value="/usr/bin/tshark")
    async def test_deep_packet_analysis_success(self, _which, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0,
                stdout=_make_tshark_json_packets(5),
                stderr="",
            )
        )

        result = await call(mcp, "deep_packet_analysis", file_path=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]

        # Verify markdown table structure
        assert "Глубокий анализ пакетов" in text
        assert "Сводка" in text
        assert "Распределение протоколов" in text
        assert "Топ отправителей" in text
        assert "192.168.1.1" in text
        assert "HTTP" in text
        assert "Метрика" in text
        assert "Значение" in text

    @pytest.mark.asyncio
    @patch("shutil.which", return_value="/usr/bin/tshark")
    async def test_deep_packet_analysis_empty(self, _which, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "empty.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="[]", stderr=""))

        result = await call(mcp, "deep_packet_analysis", file_path=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Пакеты не найдены" in text


# ── generate_report ─────────────────────────────────────────────────────


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_generate_report_markdown(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "report.pcap"
        pcap.write_bytes(b"fake")

        # Mock tshark._run to return section-specific output
        call_count = 0

        async def side_effect(args, **kwargs):
            nonlocal call_count
            call_count += 1
            return MagicMock(
                returncode=0,
                stdout=f"Section output {call_count}",
                stderr="",
            )

        mock_tshark._run = AsyncMock(side_effect=side_effect)

        result = await call(
            mcp,
            "generate_report",
            file_path=str(pcap),
            report_format="markdown",
            sections="summary,protocols",
        )
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Отчёт по анализу" in text
        assert "Summary" in text
        assert "Protocols" in text
        assert "Section output" in text

    @pytest.mark.asyncio
    async def test_generate_report_html(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "report.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="stats output", stderr="")
        )

        result = await call(
            mcp,
            "generate_report",
            file_path=str(pcap),
            report_format="html",
            sections="summary",
        )
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "<!DOCTYPE html>" in text
        assert "<style>" in text
        assert "#1a1a2e" in text
        assert "#e94560" in text
        assert "<h2>Summary</h2>" in text
        assert "<pre>" in text

    @pytest.mark.asyncio
    async def test_generate_report_invalid_format(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "report.pcap"
        pcap.write_bytes(b"fake")

        result = await call(
            mcp,
            "generate_report",
            file_path=str(pcap),
            report_format="pdf",
        )
        assert result["isError"] is True
        assert "Invalid format" in result["content"][0]["text"]


# ── get_capture_info ────────────────────────────────────────────────────


class TestGetCaptureInfo:
    @pytest.mark.asyncio
    async def test_get_capture_info_success(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "info.pcap"
        pcap.write_bytes(b"fake")

        capinfos_output = (
            f"File name\t{pcap!s}\n"
            "File type\tWireshark/tcpdump/... - pcap\n"
            "File encapsulation\tEthernet\n"
            "Number of packets\t1234\n"
            "File size\t56789 bytes\n"
            "Data size\t45000 bytes\n"
            "First packet time\t2024-01-01 10:00:00.000000\n"
            "Last packet time\t2024-01-01 10:00:05.000000\n"
            "SHA256\tabcdef1234567890\n"
        )

        with patch("shutil.which", return_value="/usr/bin/capinfos"):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(capinfos_output.encode(), b""))
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await call(mcp, "get_capture_info", file_path=str(pcap))

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Информация о файле захвата" in text
        assert "Number of packets" in text
        assert "1234" in text
        assert "SHA256" in text

    @pytest.mark.asyncio
    async def test_get_capture_info_missing_capinfos(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "info.pcap"
        pcap.write_bytes(b"fake")

        with patch("shutil.which", return_value=None):
            result = await call(mcp, "get_capture_info", file_path=str(pcap))

        assert result["isError"] is True
        assert "capinfos" in result["content"][0]["text"].lower()
