"""Tests for new features: DNS analysis, expert info, streaming, CLI args."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkNotFoundError


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
        tshark.capture_live = AsyncMock(return_value=Path("/fake/test.pcap"))
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
        tshark.export_fields = AsyncMock(return_value=[])
        tshark.follow_stream = AsyncMock(return_value="GET / HTTP/1.1\r\n")
        tshark.list_streams = AsyncMock(return_value=[{"endpoint_a": "a:80"}])
        tshark.export_json = AsyncMock(return_value=[{"_source": {}}])
        tshark.file_info = AsyncMock(return_value={"filepath": "/fake/test.pcap"})
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        yield tshark


def _get_text(result: dict) -> str:
    """Extract text from an MCP tool result dict."""
    return result["content"][0]["text"]


# ── DNS Analysis ────────────────────────────────────────────────────────


class TestDnsAnalysis:
    @pytest.mark.asyncio
    async def test_dns_basic(self, mock_tshark, fmt, sec, tmp_path):
        """Test DNS analysis with normal query data."""
        pcap = tmp_path / "dns.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {"dns.qry.name": "example.com", "dns.flags.rcode": "0", "ip.src": "10.0.0.1"},
                {"dns.qry.name": "example.com", "dns.flags.rcode": "0", "ip.src": "10.0.0.1"},
                {"dns.qry.name": "google.com", "dns.flags.rcode": "0", "ip.src": "10.0.0.2"},
                {"dns.qry.name": "nxdomain.test", "dns.flags.rcode": "3", "ip.src": "10.0.0.1"},
            ]
        )

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("analyze_dns_traffic", {"filepath": str(pcap)})
        text = _get_text(result)
        assert "DNS Analysis" in text

    @pytest.mark.asyncio
    async def test_dns_tunneling_detection(self, mock_tshark, fmt, sec, tmp_path):
        """Test that long domain names are flagged as suspicious."""
        pcap = tmp_path / "tunnel.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        long_domain = "a" * 65 + ".evil.com"
        many_dots = "a.b.c.d.e.f.g.h.evil.com"
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {"dns.qry.name": long_domain, "dns.flags.rcode": "0"},
                {"dns.qry.name": many_dots, "dns.flags.rcode": "0"},
                {"dns.qry.name": "normal.com", "dns.flags.rcode": "0"},
            ]
        )

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("analyze_dns_traffic", {"filepath": str(pcap)})
        text = _get_text(result)
        assert "potential_tunneling" in text
        assert "true" in text.lower()

    @pytest.mark.asyncio
    async def test_dns_nxdomain_tracking(self, mock_tshark, fmt, sec, tmp_path):
        """Test NXDOMAIN response counting."""
        pcap = tmp_path / "nxdomain.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {"dns.qry.name": "missing1.test", "dns.flags.rcode": "3"},
                {"dns.qry.name": "missing2.test", "dns.flags.rcode": "3"},
                {"dns.qry.name": "good.com", "dns.flags.rcode": "0"},
            ]
        )

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("analyze_dns_traffic", {"filepath": str(pcap)})
        text = _get_text(result)
        assert '"nxdomain_count": 2' in text

    @pytest.mark.asyncio
    async def test_dns_error_handling(self, mock_tshark, fmt, sec):
        """Test DNS analysis with invalid filepath."""
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "analyze_dns_traffic", {"filepath": "/nonexistent/file.pcap"}
        )
        text = _get_text(result)
        assert "NETMCP" in text

    @pytest.mark.asyncio
    async def test_dns_max_queries_limit(self, mock_tshark, fmt, sec, tmp_path):
        """Test that max_queries parameter limits processing."""
        pcap = tmp_path / "many_dns.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        rows = [{"dns.qry.name": f"domain{i}.com", "dns.flags.rcode": "0"} for i in range(50)]
        mock_tshark.export_fields = AsyncMock(return_value=rows)

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "analyze_dns_traffic", {"filepath": str(pcap), "max_queries": 10}
        )
        text = _get_text(result)
        # Only 10 unique queries should be counted (limited by max_queries)
        assert '"unique_queries": 10' in text


# ── Expert Information ──────────────────────────────────────────────────


class TestExpertInfo:
    @pytest.mark.asyncio
    async def test_expert_basic(self, mock_tshark, fmt, sec, tmp_path):
        """Test expert info extraction with typical output."""
        pcap = tmp_path / "expert.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        expert_output = (
            "=== Expert Information ===\n"
            "Errors (2)\n"
            "Malformed packet\n"
            "Bad checksum\n"
            "Warnings (1)\n"
            "TCP window full\n"
            "Notes (1)\n"
            "TCP retransmission\n"
            "Chats (1)\n"
            "TCP connection established\n"
        )
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=expert_output, stderr="")
        )

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("get_expert_info", {"filepath": str(pcap)})
        text = _get_text(result)
        assert "Expert Information" in text
        assert "Malformed packet" in text
        assert "Bad checksum" in text
        assert "TCP window full" in text
        assert "TCP retransmission" in text

    @pytest.mark.asyncio
    async def test_expert_empty_output(self, mock_tshark, fmt, sec, tmp_path):
        """Test expert info with empty tshark output."""
        pcap = tmp_path / "empty_expert.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("get_expert_info", {"filepath": str(pcap)})
        text = _get_text(result)
        assert "Expert Information" in text
        assert '"error_count": 0' in text

    @pytest.mark.asyncio
    async def test_expert_error_handling(self, mock_tshark, fmt, sec):
        """Test expert info with invalid filepath."""
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "get_expert_info", {"filepath": "/nonexistent/file.pcap"}
        )
        text = _get_text(result)
        assert "NETMCP" in text

    @pytest.mark.asyncio
    async def test_expert_severity_counts(self, mock_tshark, fmt, sec, tmp_path):
        """Test that severity counts are accurate in the summary."""
        pcap = tmp_path / "severity.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        expert_output = (
            "Errors (3)\n"
            "Error line 1\n"
            "Error line 2\n"
            "Error line 3\n"
            "Warnings (2)\n"
            "Warn line 1\n"
            "Warn line 2\n"
            "Notes (0)\n"
            "Chats (0)\n"
        )
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=expert_output, stderr="")
        )

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.analysis import register_analysis_tools

        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("get_expert_info", {"filepath": str(pcap)})
        text = _get_text(result)
        assert '"error_count": 3' in text
        assert '"warning_count": 2' in text
        assert '"note_count": 0' in text


# ── Streaming Analysis ──────────────────────────────────────────────────


class TestStreamingAnalysis:
    @pytest.mark.asyncio
    async def test_large_pcap_single_chunk(self, mock_tshark, fmt, sec, tmp_path):
        """Test streaming analysis with data fitting in one chunk."""
        pcap = tmp_path / "large.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.read_pcap = AsyncMock(
            side_effect=[
                [
                    {
                        "_source": {
                            "layers": {
                                "ip.src": ["10.0.0.1"],
                                "ip.dst": ["10.0.0.2"],
                                "frame.protocols": ["eth:ethertype:ip:tcp"],
                            }
                        }
                    },
                    {
                        "_source": {
                            "layers": {
                                "ip.src": ["10.0.0.1"],
                                "ip.dst": ["10.0.0.3"],
                                "frame.protocols": ["eth:ethertype:ip:udp"],
                            }
                        }
                    },
                ],
                [],  # Second call returns empty to stop iteration
            ]
        )

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.streaming import register_streaming_tools

        register_streaming_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "analyze_large_pcap", {"filepath": str(pcap), "chunk_size": 100}
        )
        text = _get_text(result)
        assert "Large PCAP Analysis" in text
        assert '"total_packets": 2' in text

    @pytest.mark.asyncio
    async def test_large_pcap_multiple_chunks(self, mock_tshark, fmt, sec, tmp_path):
        """Test streaming analysis processing multiple chunks."""
        pcap = tmp_path / "multi_chunk.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        chunk1 = [
            {
                "_source": {
                    "layers": {
                        "ip.src": ["10.0.0.1"],
                        "ip.dst": ["10.0.0.2"],
                        "frame.protocols": ["eth:ethertype:ip:tcp"],
                    }
                }
            }
        ] * 5  # Full chunk of 5

        chunk2 = [
            {
                "_source": {
                    "layers": {
                        "ip.src": ["10.0.0.3"],
                        "ip.dst": ["10.0.0.4"],
                        "frame.protocols": ["eth:ethertype:ip:udp"],
                    }
                }
            }
        ] * 3  # Partial chunk of 3 (< chunk_size)

        mock_tshark.read_pcap = AsyncMock(side_effect=[chunk1, chunk2])

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.streaming import register_streaming_tools

        register_streaming_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "analyze_large_pcap", {"filepath": str(pcap), "chunk_size": 5}
        )
        text = _get_text(result)
        assert "Large PCAP Analysis" in text
        assert '"total_packets": 8' in text

    @pytest.mark.asyncio
    async def test_large_pcap_empty(self, mock_tshark, fmt, sec, tmp_path):
        """Test streaming analysis with empty PCAP."""
        pcap = tmp_path / "empty.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.read_pcap = AsyncMock(return_value=[])

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.streaming import register_streaming_tools

        register_streaming_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("analyze_large_pcap", {"filepath": str(pcap)})
        text = _get_text(result)
        assert '"total_packets": 0' in text

    @pytest.mark.asyncio
    async def test_large_pcap_with_display_filter(self, mock_tshark, fmt, sec, tmp_path):
        """Test streaming analysis with a display filter."""
        pcap = tmp_path / "filtered.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.read_pcap = AsyncMock(return_value=[])

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.streaming import register_streaming_tools

        register_streaming_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "analyze_large_pcap",
            {"filepath": str(pcap), "display_filter": "tcp"},
        )
        text = _get_text(result)
        assert "Large PCAP Analysis" in text

        # Verify filter was included in the read_pcap call
        call_kwargs = mock_tshark.read_pcap.call_args
        filter_used = call_kwargs.kwargs.get("display_filter", "")
        assert "tcp" in filter_used

    @pytest.mark.asyncio
    async def test_large_pcap_error_handling(self, mock_tshark, fmt, sec):
        """Test streaming analysis with invalid filepath."""
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.streaming import register_streaming_tools

        register_streaming_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool(
            "analyze_large_pcap", {"filepath": "/nonexistent/file.pcap"}
        )
        text = _get_text(result)
        assert "NETMCP" in text

    @pytest.mark.asyncio
    async def test_large_pcap_protocol_counting(self, mock_tshark, fmt, sec, tmp_path):
        """Test that protocols are correctly counted across chunks."""
        pcap = tmp_path / "protos.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        packets = [
            {
                "_source": {
                    "layers": {
                        "ip.src": "192.168.1.1",
                        "ip.dst": "192.168.1.2",
                        "frame.protocols": "eth:ethertype:ip:tcp:http",
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "ip.src": "192.168.1.1",
                        "ip.dst": "192.168.1.3",
                        "frame.protocols": "eth:ethertype:ip:tcp",
                    }
                }
            },
        ]
        mock_tshark.read_pcap = AsyncMock(side_effect=[packets, []])

        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        from netmcp.tools.streaming import register_streaming_tools

        register_streaming_tools(mcp, mock_tshark, fmt, sec)

        result = await mcp._tool_manager.call_tool("analyze_large_pcap", {"filepath": str(pcap)})
        text = _get_text(result)
        # tcp should appear twice (in both packets)
        assert "tcp" in text
        # http should appear once
        assert "http" in text


# ── CLI Args Parsing ────────────────────────────────────────────────────


class TestCliArgs:
    def test_default_args(self):
        """Test default CLI arguments."""
        from netmcp.server import parse_args

        args = parse_args([])
        assert args.transport == "stdio"
        assert args.host == "0.0.0.0"
        assert args.port == 8080

    def test_transport_stdio(self):
        """Test --transport stdio."""
        from netmcp.server import parse_args

        args = parse_args(["--transport", "stdio"])
        assert args.transport == "stdio"

    def test_transport_sse(self):
        """Test --transport sse."""
        from netmcp.server import parse_args

        args = parse_args(["--transport", "sse"])
        assert args.transport == "sse"

    def test_transport_streamable_http(self):
        """Test --transport streamable-http."""
        from netmcp.server import parse_args

        args = parse_args(["--transport", "streamable-http"])
        assert args.transport == "streamable-http"

    def test_custom_host_port(self):
        """Test custom host and port."""
        from netmcp.server import parse_args

        args = parse_args(["--host", "127.0.0.1", "--port", "9090"])
        assert args.host == "127.0.0.1"
        assert args.port == 9090

    def test_invalid_transport(self):
        """Test invalid transport choice raises error."""
        from netmcp.server import parse_args

        with pytest.raises(SystemExit):
            parse_args(["--transport", "invalid"])

    def test_all_args_combined(self):
        """Test all args together."""
        from netmcp.server import parse_args

        args = parse_args(
            [
                "--transport",
                "streamable-http",
                "--host",
                "localhost",
                "--port",
                "3000",
            ]
        )
        assert args.transport == "streamable-http"
        assert args.host == "localhost"
        assert args.port == 3000


# ── Server Transport Integration ────────────────────────────────────────


class TestServerTransport:
    def test_create_server_with_host_port(self):
        """Test create_server passes host/port to FastMCP."""
        with patch(
            "netmcp.server.TsharkInterface",
            side_effect=TsharkNotFoundError("skip"),
        ):
            from netmcp.server import create_server

            server = create_server(host="127.0.0.1", port=9090)
            assert server.settings.host == "127.0.0.1"
            assert server.settings.port == 9090

    def test_create_server_default_host_port(self):
        """Test create_server uses correct defaults."""
        with patch(
            "netmcp.server.TsharkInterface",
            side_effect=TsharkNotFoundError("skip"),
        ):
            from netmcp.server import create_server

            server = create_server()
            assert server.settings.host == "0.0.0.0"
            assert server.settings.port == 8080

    def test_main_calls_run_with_transport(self):
        """Test that main() passes transport argument to server.run()."""
        from netmcp.server import main

        mock_server = MagicMock()
        with (
            patch("netmcp.server.parse_args") as mock_parse,
            patch("netmcp.server.create_server", return_value=mock_server),
        ):
            mock_parse.return_value = MagicMock(
                transport="streamable-http", host="0.0.0.0", port=8080
            )
            main()
            mock_server.run.assert_called_once_with(transport="streamable-http")

    def test_main_passes_host_port_to_create_server(self):
        """Test that main() passes host/port from args to create_server()."""
        from netmcp.server import main

        mock_server = MagicMock()
        with (
            patch("netmcp.server.parse_args") as mock_parse,
            patch("netmcp.server.create_server", return_value=mock_server) as mock_create,
        ):
            mock_parse.return_value = MagicMock(transport="sse", host="localhost", port=3000)
            main()
            mock_create.assert_called_once_with(host="localhost", port=3000)
