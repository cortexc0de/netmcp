"""Targeted tests for uncovered lines in tools/capture.py."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.tools.capture import register_capture_tools


@pytest.fixture
def fmt():
    return OutputFormatter()


@pytest.fixture
def sec():
    return SecurityValidator()


@pytest.fixture
def mock_tshark():
    with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
        from netmcp.interfaces.tshark import TsharkInterface

        t = TsharkInterface()
        t.list_interfaces = AsyncMock(return_value=["eth0", "lo"])
        t.capture_live = AsyncMock(return_value=Path("/nonexistent/test.pcap"))
        t.read_pcap = AsyncMock(return_value=[])
        yield t


async def call(mcp, name, **kwargs):
    return await mcp._tool_manager.call_tool(name, kwargs)


class TestCaptureErrors:
    @pytest.mark.asyncio
    async def test_get_network_interfaces_error(self, mock_tshark, fmt, sec):
        """Lines 32-33: exception in get_network_interfaces."""
        mock_tshark.list_interfaces = AsyncMock(
            side_effect=RuntimeError("tshark not found")
        )
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_network_interfaces")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_capture_live_rate_limit(self, mock_tshark, fmt, sec):
        """Line 62: rate limit exceeded for capture_live_packets."""
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        with patch.object(sec, "check_rate_limit", return_value=False):
            result = await call(
                mcp, "capture_live_packets", interface="eth0", duration=5
            )
            assert result["isError"] is True
            assert "Rate limit" in str(result)

    @pytest.mark.asyncio
    async def test_capture_live_exception(self, mock_tshark, fmt, sec):
        """Lines 90-93: general exception in capture_live_packets."""
        mock_tshark.capture_live = AsyncMock(
            side_effect=RuntimeError("capture failed")
        )
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "capture_live_packets", interface="eth0", duration=5
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_quick_capture_rate_limit(self, mock_tshark, fmt, sec):
        """Line 120: rate limit exceeded for quick_capture."""
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        with patch.object(sec, "check_rate_limit", return_value=False):
            result = await call(mcp, "quick_capture", interface="eth0")
            assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_quick_capture_exception(self, mock_tshark, fmt, sec):
        """Lines 167-170: exception in quick_capture."""
        mock_tshark.capture_live = AsyncMock(
            side_effect=RuntimeError("capture failed")
        )
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "quick_capture", interface="eth0")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_save_capture_rate_limit(self, mock_tshark, fmt, sec):
        """Line 203: rate limit exceeded for save_capture_to_file."""
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        with patch.object(sec, "check_rate_limit", return_value=False):
            result = await call(
                mcp,
                "save_capture_to_file",
                interface="eth0",
                output_file="/out.pcap",
            )
            assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_save_capture_path_traversal(self, mock_tshark, fmt, sec, tmp_path):
        """Lines 225-226: path traversal in save_capture_to_file."""
        pcap = tmp_path / "source.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "save_capture_to_file",
            interface="eth0",
            output_file="../../../etc/passwd.pcap",
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_save_capture_bad_extension(self, mock_tshark, fmt, sec, tmp_path):
        """Invalid extension in save_capture_to_file."""
        pcap = tmp_path / "source.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "save_capture_to_file",
            interface="eth0",
            output_file=str(tmp_path / "bad.txt"),
        )
        assert result["isError"] is True


class TestCaptureCleanup:
    @pytest.mark.asyncio
    async def test_capture_live_cleanup_oserror(self, mock_tshark, fmt, sec, tmp_path):
        """Lines 90-91: OSError during cleanup in capture_live_packets."""
        pcap = tmp_path / "cleanup.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mock_tshark.read_pcap = AsyncMock(return_value=[])

        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        # Delete the file before unlink runs to trigger OSError

        # original saved for reference

        def unlink_raise(path):
            raise OSError("file gone")

        with patch("os.unlink", side_effect=unlink_raise):
            result = await call(
                mcp, "capture_live_packets", interface="eth0", duration=5
            )
            # Should still succeed despite cleanup error
            assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_quick_capture_cleanup_oserror(self, mock_tshark, fmt, sec, tmp_path):
        """Lines 167-168: OSError during cleanup in quick_capture."""
        pcap = tmp_path / "qc.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mock_tshark.read_pcap = AsyncMock(
            return_value=[
                {
                    "_source": {
                        "layers": {
                            "frame.protocols": "eth:ip:tcp",
                            "ip.src": "10.0.0.1",
                            "ip.dst": "10.0.0.2",
                        }
                    }
                }
            ]
        )

        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        with patch("os.unlink", side_effect=OSError("file gone")):
            result = await call(mcp, "quick_capture", interface="eth0")
            assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_save_capture_resolve_oserror(self, mock_tshark, fmt, sec, tmp_path):
        """Lines 225-226: OSError from Path.resolve()."""
        pcap = tmp_path / "source.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        # Use a null byte in path which makes resolve() fail on some systems
        with patch("pathlib.Path.resolve", side_effect=OSError("invalid path")):
            result = await call(
                mcp,
                "save_capture_to_file",
                interface="eth0",
                output_file="/some/output.pcap",
            )
            assert result["isError"] is True


class TestQuickCaptureParsing:
    @pytest.mark.asyncio
    async def test_quick_capture_with_list_layers(self, mock_tshark, fmt, sec, tmp_path):
        """Lines 138→145, 146→145: parsing branches in quick_capture."""
        pcap = tmp_path / "qc.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        # Packets with list-type layer values
        mock_tshark.read_pcap = AsyncMock(
            return_value=[
                {
                    "_source": {
                        "layers": {
                            "frame.protocols": ["eth:ip:tcp"],
                            "ip.src": ["10.0.0.1"],
                            "ip.dst": ["10.0.0.2"],
                        }
                    }
                },
                {
                    "_source": {
                        "layers": {
                            "frame.protocols": "eth:ip:udp",
                            "ip.src": "192.168.1.1",
                            "ip.dst": "8.8.8.8",
                        }
                    }
                },
                {"_source": {"layers": {}}},
            ]
        )
        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "quick_capture", interface="eth0")
        assert result["isError"] is False
