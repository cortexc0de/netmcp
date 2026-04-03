"""Tests for streaming analysis tools (tools/streaming.py)."""

from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.tools.streaming import register_streaming_tools


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
        t.read_pcap = AsyncMock(return_value=[])
        yield t


async def call(mcp, name, **kwargs):
    return await mcp._tool_manager.call_tool(name, kwargs)


class TestAnalyzeLargePcap:
    @pytest.mark.asyncio
    async def test_basic_analysis(self, mock_tshark, fmt, sec, tmp_path):
        """Happy path: analyze a large PCAP in chunks."""
        pcap = tmp_path / "large.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        # First chunk returns packets, second chunk returns empty (end)
        mock_tshark.read_pcap = AsyncMock(
            side_effect=[
                [
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
                ],
                [],  # empty chunk signals end
            ]
        )

        mcp = FastMCP("test")
        register_streaming_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_large_pcap", filepath=str(pcap), chunk_size=100)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_with_display_filter(self, mock_tshark, fmt, sec, tmp_path):
        """Display filter is passed through."""
        pcap = tmp_path / "filtered.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.read_pcap = AsyncMock(return_value=[])
        mcp = FastMCP("test")
        register_streaming_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "analyze_large_pcap",
            filepath=str(pcap),
            display_filter="http",
            chunk_size=5000,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_partial_chunk(self, mock_tshark, fmt, sec, tmp_path):
        """Chunk smaller than chunk_size → stops early."""
        pcap = tmp_path / "small.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.read_pcap = AsyncMock(
            return_value=[
                {"_source": {"layers": {"frame.protocols": "eth:ip:tcp"}}},
            ]
        )
        mcp = FastMCP("test")
        register_streaming_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_large_pcap", filepath=str(pcap), chunk_size=100)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_empty_pcap(self, mock_tshark, fmt, sec, tmp_path):
        """Empty PCAP file (no packets)."""
        pcap = tmp_path / "empty.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.read_pcap = AsyncMock(return_value=[])
        mcp = FastMCP("test")
        register_streaming_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_large_pcap", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_exception_handled(self, mock_tshark, fmt, sec, tmp_path):
        """Exception → error result."""
        mock_tshark.read_pcap = AsyncMock(side_effect=RuntimeError("read failed"))
        mcp = FastMCP("test")
        register_streaming_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_large_pcap", filepath="/nonexistent.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_packets_without_layers(self, mock_tshark, fmt, sec, tmp_path):
        """Packets missing expected fields still processed."""
        pcap = tmp_path / "sparse.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.read_pcap = AsyncMock(
            return_value=[
                {"_source": {"layers": {}}},
                {"_source": {}},
                {},
            ]
        )
        mcp = FastMCP("test")
        register_streaming_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_large_pcap", filepath=str(pcap), chunk_size=100)
        assert result["isError"] is False
