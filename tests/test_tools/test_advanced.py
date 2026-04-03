"""Tests for advanced tshark tools and output truncation."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface
from netmcp.tools.advanced import register_advanced_tools


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


# ── extract_objects ─────────────────────────────────────────────────────


class TestExtractObjects:
    @pytest.mark.asyncio
    async def test_extract_objects_success(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")
        out_dir = tmp_path / "export"
        out_dir.mkdir()

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        # Pre-create a fake extracted file
        (out_dir / "image.png").write_bytes(b"\x89PNG" + b"\x00" * 100)

        with (
            patch("netmcp.tools.advanced.shutil.which", return_value="/usr/bin/tshark"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec,
        ):
            result = await call(
                mcp,
                "extract_objects",
                file_path=str(pcap),
                protocol="http",
                output_dir=str(out_dir),
            )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Object Extraction" in text
        assert "image.png" in text

        # Verify tshark args
        call_args = mock_exec.call_args[0]
        assert "--export-objects" in call_args
        assert any("http," in str(a) for a in call_args)

    @pytest.mark.asyncio
    async def test_extract_objects_invalid_protocol(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        result = await call(
            mcp,
            "extract_objects",
            file_path=str(pcap),
            protocol="foobar",
        )
        assert result["isError"] is True
        assert "foobar" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_extract_objects_invalid_path(self, mock_tshark, fmt, sec):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        result = await call(
            mcp,
            "extract_objects",
            file_path="../../../etc/passwd",
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_extract_objects_no_files_found(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")
        out_dir = tmp_path / "empty_export"
        out_dir.mkdir()

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with (
            patch("netmcp.tools.advanced.shutil.which", return_value="/usr/bin/tshark"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await call(
                mcp,
                "extract_objects",
                file_path=str(pcap),
                protocol="http",
                output_dir=str(out_dir),
            )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert '"files_extracted": 0' in text


# ── get_io_statistics ───────────────────────────────────────────────────


class TestGetIoStatistics:
    @pytest.mark.asyncio
    async def test_get_io_statistics_success(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        io_output = (
            "===================================================================\n"
            "| IO Statistics                                                   |\n"
            "| Duration: 10.0 secs                                            |\n"
            "| Interval:  1 secs                                              |\n"
            "|                                                                 |\n"
            "| Interval       | Frames | Bytes                                |\n"
            "|------------------------------------------------------          |\n"
            "|  0 <>  1       |     42 | 3500                                 |\n"
            "|  1 <>  2       |     38 | 3200                                 |\n"
            "|  2 <>  3       |     55 | 4800                                 |\n"
            "===================================================================\n"
        )

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=io_output, stderr="")
        )

        result = await call(
            mcp,
            "get_io_statistics",
            file_path=str(pcap),
            interval="1",
        )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "I/O Statistics" in text
        assert "intervals" in text

    @pytest.mark.asyncio
    async def test_get_io_statistics_with_filter(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="| 0 <> 1 | 10 |\n", stderr="")
        )

        result = await call(
            mcp,
            "get_io_statistics",
            file_path=str(pcap),
            interval="5",
            display_filter="tcp",
        )

        assert result["isError"] is False
        # Verify filter was passed in the tshark args
        call_args = mock_tshark._run.call_args[0][0]
        stat_arg = [a for a in call_args if a.startswith("io,stat,")]
        assert len(stat_arg) == 1
        assert "tcp" in stat_arg[0]

    @pytest.mark.asyncio
    async def test_get_io_statistics_invalid_interval(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        # Non-numeric interval
        result = await call(
            mcp,
            "get_io_statistics",
            file_path=str(pcap),
            interval="abc",
        )
        assert result["isError"] is True
        assert "interval" in result["content"][0]["text"].lower()

        # Negative interval
        result = await call(
            mcp,
            "get_io_statistics",
            file_path=str(pcap),
            interval="-5",
        )
        assert result["isError"] is True
        assert "interval" in result["content"][0]["text"].lower()

        # Zero interval
        result = await call(
            mcp,
            "get_io_statistics",
            file_path=str(pcap),
            interval="0",
        )
        assert result["isError"] is True


# ── get_conversation_stats ──────────────────────────────────────────────


class TestGetConversationStats:
    @pytest.mark.asyncio
    async def test_get_conversation_stats_success(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        conv_output = (
            "================================================================================\n"
            "IPv4 Conversations\n"
            "Filter:<No Filter>\n"
            "                                               |       <-      | |       ->      |\n"
            "                                               | Frames  Bytes | | Frames  Bytes  |\n"
            "==============================================================================\n"
            "10.0.0.1         <-> 10.0.0.2             42   3500     38   3200\n"
            "192.168.1.1      <-> 192.168.1.100        15   1200     12   900\n"
            "================================================================================\n"
        )

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=conv_output, stderr="")
        )

        result = await call(
            mcp,
            "get_conversation_stats",
            file_path=str(pcap),
            conv_type="ip",
        )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Conversation Statistics" in text
        assert "10.0.0.1" in text
        assert "10.0.0.2" in text

    @pytest.mark.asyncio
    async def test_get_conversation_stats_invalid_type(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_advanced_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        result = await call(
            mcp,
            "get_conversation_stats",
            file_path=str(pcap),
            conv_type="foo",
        )
        assert result["isError"] is True
        assert "foo" in result["content"][0]["text"]


# ── truncate_output ─────────────────────────────────────────────────────


class TestTruncateOutput:
    def test_truncate_output_short(self, fmt):
        """Short text should not be truncated."""
        result = fmt.format_success({"key": "value"}, title="Test")
        truncated = fmt.truncate_output(result)
        assert truncated == result

    def test_truncate_output_long(self, fmt):
        """Long text should be truncated with a warning message."""
        long_data = "x" * 600_000
        result = fmt.format_success(long_data, title="Big Output")
        truncated = fmt.truncate_output(result)
        text = truncated["content"][0]["text"]
        assert len(text) < len(result["content"][0]["text"])
        assert "⚠️" in text
        assert "обрезан" in text
        assert truncated["isError"] is False

    def test_truncate_output_custom_limit(self, fmt):
        """Custom limit should be respected."""
        result = fmt.format_success("a" * 200, title="Test")
        truncated = fmt.truncate_output(result, max_chars=50)
        text = truncated["content"][0]["text"]
        assert "⚠️" in text
        # The text content before the title is "=== Test ===\n" + "a"*200
        # With limit 50, it should be truncated
        assert len(text) < 300
