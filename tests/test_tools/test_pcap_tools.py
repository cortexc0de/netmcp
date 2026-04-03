"""Tests for PCAP manipulation tools (diff, merge, slice, decode)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface
from netmcp.tools.pcap_tools import register_pcap_tools


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
        tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )
        yield tshark


async def call(mcp: FastMCP, name: str, **kwargs):
    """Helper to call a registered tool by name."""
    return await mcp._tool_manager.call_tool(name, kwargs)


def _make_packets(ips: list[tuple[str, str]]) -> list[dict]:
    """Build fake tshark JSON packets from (src, dst) tuples."""
    return [
        {"_source": {"layers": {"ip.src": [src], "ip.dst": [dst]}}}
        for src, dst in ips
    ]


# ── diff_pcap_files ────────────────────────────────────────────────────


class TestDiffPcapFiles:
    @pytest.mark.asyncio
    async def test_diff_basic(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        file1 = tmp_path / "a.pcap"
        file2 = tmp_path / "b.pcap"
        file1.write_bytes(b"fake")
        file2.write_bytes(b"fake")

        mock_tshark.read_pcap = AsyncMock(
            side_effect=[
                _make_packets([("10.0.0.1", "10.0.0.2")]),
                _make_packets([("10.0.0.3", "10.0.0.4")]),
            ]
        )
        mock_tshark.protocol_stats = AsyncMock(
            side_effect=[
                {"tcp": {"frames": 50, "bytes": 5000}},
                {"tcp": {"frames": 30, "bytes": 3000}, "udp": {"frames": 10, "bytes": 800}},
            ]
        )

        result = await call(mcp, "diff_pcap_files", filepath1=str(file1), filepath2=str(file2))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "PCAP Diff" in text
        assert "only_in_file1_ips" in text
        assert "only_in_file2_ips" in text
        assert "protocol_diff" in text

    @pytest.mark.asyncio
    async def test_diff_with_display_filter(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        file1 = tmp_path / "a.pcap"
        file2 = tmp_path / "b.pcap"
        file1.write_bytes(b"fake")
        file2.write_bytes(b"fake")

        mock_tshark.read_pcap = AsyncMock(return_value=[])
        mock_tshark.protocol_stats = AsyncMock(return_value={})

        result = await call(
            mcp, "diff_pcap_files",
            filepath1=str(file1), filepath2=str(file2), display_filter="tcp",
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_diff_invalid_path(self, mock_tshark, fmt, sec):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        result = await call(
            mcp, "diff_pcap_files",
            filepath1="../../../etc/passwd", filepath2="b.pcap",
        )
        assert result["isError"] is True


# ── merge_pcap_files ───────────────────────────────────────────────────


class TestMergePcapFiles:
    @pytest.mark.asyncio
    async def test_merge_basic(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        file1 = tmp_path / "a.pcap"
        file2 = tmp_path / "b.pcap"
        out = tmp_path / "merged.pcap"
        file1.write_bytes(b"fake")
        file2.write_bytes(b"fake")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/mergecap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            out.write_bytes(b"merged data here")
            result = await call(
                mcp, "merge_pcap_files",
                filepaths=[str(file1), str(file2)], output_file=str(out),
            )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "PCAP Merge" in text
        assert "files_merged" in text

    @pytest.mark.asyncio
    async def test_merge_append_mode(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        file1 = tmp_path / "a.pcap"
        out = tmp_path / "merged.pcap"
        file1.write_bytes(b"fake")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/mergecap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            out.write_bytes(b"merged data")
            result = await call(
                mcp, "merge_pcap_files",
                filepaths=[str(file1)], output_file=str(out), chronological=False,
            )

        assert result["isError"] is False
        call_args = mock_exec.call_args[0]
        assert "-a" in call_args

    @pytest.mark.asyncio
    async def test_merge_mergecap_not_found(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        file1 = tmp_path / "a.pcap"
        file1.write_bytes(b"fake")

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value=None):
            result = await call(
                mcp, "merge_pcap_files",
                filepaths=[str(file1)], output_file=str(tmp_path / "out.pcap"),
            )

        assert result["isError"] is True
        assert "mergecap" in result["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_merge_empty_filepaths(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        result = await call(
            mcp, "merge_pcap_files",
            filepaths=[], output_file=str(tmp_path / "out.pcap"),
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_merge_invalid_output_ext(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        file1 = tmp_path / "a.pcap"
        file1.write_bytes(b"fake")

        result = await call(
            mcp, "merge_pcap_files",
            filepaths=[str(file1)], output_file=str(tmp_path / "out.txt"),
        )
        assert result["isError"] is True
        assert "extension" in result["content"][0]["text"].lower()


# ── slice_pcap ─────────────────────────────────────────────────────────


class TestSlicePcap:
    @pytest.mark.asyncio
    async def test_slice_packet_range(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        inp = tmp_path / "input.pcap"
        out = tmp_path / "sliced.pcap"
        inp.write_bytes(b"fake")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/editcap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            out.write_bytes(b"sliced data")
            result = await call(
                mcp, "slice_pcap",
                filepath=str(inp), output_file=str(out),
                start_packet=10, end_packet=50,
            )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "PCAP Slice" in text
        call_args = mock_exec.call_args[0]
        assert "-r" in call_args
        assert "10-50" in call_args

    @pytest.mark.asyncio
    async def test_slice_time_range(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        inp = tmp_path / "input.pcap"
        out = tmp_path / "sliced.pcap"
        inp.write_bytes(b"fake")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/editcap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            out.write_bytes(b"sliced data")
            result = await call(
                mcp, "slice_pcap",
                filepath=str(inp), output_file=str(out),
                start_time="2024-01-01 00:00:00",
                end_time="2024-01-01 01:00:00",
            )

        assert result["isError"] is False
        call_args = mock_exec.call_args[0]
        assert "-A" in call_args
        assert "-B" in call_args

    @pytest.mark.asyncio
    async def test_slice_remove_duplicates(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        inp = tmp_path / "input.pcap"
        out = tmp_path / "sliced.pcap"
        inp.write_bytes(b"fake")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/editcap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            out.write_bytes(b"deduped")
            result = await call(
                mcp, "slice_pcap",
                filepath=str(inp), output_file=str(out),
                remove_duplicates=True,
            )

        assert result["isError"] is False
        call_args = mock_exec.call_args[0]
        assert "-d" in call_args

    @pytest.mark.asyncio
    async def test_slice_editcap_not_found(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        inp = tmp_path / "input.pcap"
        inp.write_bytes(b"fake")

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value=None):
            result = await call(
                mcp, "slice_pcap",
                filepath=str(inp), output_file=str(tmp_path / "out.pcap"),
            )

        assert result["isError"] is True
        assert "editcap" in result["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_slice_editcap_failure(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        inp = tmp_path / "input.pcap"
        inp.write_bytes(b"fake")

        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"some error"))

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/editcap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await call(
                mcp, "slice_pcap",
                filepath=str(inp), output_file=str(tmp_path / "out.pcap"),
            )

        assert result["isError"] is True


# ── decode_packet ──────────────────────────────────────────────────────


class TestDecodePacket:
    @pytest.mark.asyncio
    async def test_decode_verbose(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0,
                stdout="Frame 1: 74 bytes\nEthernet II\nInternet Protocol Version 4\n",
                stderr="",
            )
        )

        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=1, verbose=True,
        )
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Packet Decode" in text
        assert "packet_number" in text

    @pytest.mark.asyncio
    async def test_decode_json_mode(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        json_output = json.dumps([{
            "_source": {
                "layers": {
                    "frame": {"frame.number": "1"},
                    "eth": {"eth.src": "00:11:22:33:44:55"},
                    "ip": {"ip.src": "10.0.0.1"},
                }
            }
        }])

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=json_output, stderr="")
        )

        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=1, verbose=False,
        )
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "layers" in text

    @pytest.mark.asyncio
    async def test_decode_invalid_packet_number(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=0,
        )
        assert result["isError"] is True
        assert "greater than 0" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_decode_negative_packet_number(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=-5,
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_decode_packet_not_found(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )

        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=9999,
        )
        assert result["isError"] is True
        assert "not found" in result["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_decode_tshark_failure(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake")

        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=1, stdout="", stderr="tshark error")
        )

        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=1,
        )
        assert result["isError"] is True
