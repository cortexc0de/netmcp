"""Tests for flow visualization and TLS decryption tools."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.tools.flow_tls import (
    _build_flow_diagram_mermaid,
    _build_flow_diagram_text,
    _parse_packet_rows,
    _summarize_conversations,
)


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
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        tshark.export_fields = AsyncMock(return_value=[])
        tshark.list_streams = AsyncMock(return_value=[])
        yield tshark


@pytest.fixture
def sample_pcap(tmp_path):
    """Create a fake pcap file that passes sanitize_filepath."""
    pcap = tmp_path / "test.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    return pcap


@pytest.fixture
def sample_keylog(tmp_path):
    """Create a fake TLS key log file."""
    keylog = tmp_path / "keylog.txt"
    keylog.write_text("CLIENT_RANDOM abc123 def456\n")
    return keylog


# ── Helper function tests ──────────────────────────────────────────────


class TestParsePacketRows:
    def test_parses_tcp_syn(self):
        rows = [
            {
                "ip.src": "192.168.1.1",
                "ip.dst": "10.0.0.1",
                "tcp.srcport": "54321",
                "tcp.dstport": "80",
                "tcp.flags.str": "··S·····",
                "http.request.method": "",
                "http.request.uri": "",
                "http.response.code": "",
                "frame.number": "1",
                "frame.len": "66",
            }
        ]
        parsed = _parse_packet_rows(rows)
        assert len(parsed) == 1
        assert parsed[0]["src"] == "192.168.1.1:54321"
        assert parsed[0]["dst"] == "10.0.0.1:80"
        assert "SYN" in parsed[0]["summary"]

    def test_parses_http_request(self):
        rows = [
            {
                "ip.src": "192.168.1.1",
                "ip.dst": "10.0.0.1",
                "tcp.srcport": "54321",
                "tcp.dstport": "80",
                "tcp.flags.str": "·AP·····",
                "http.request.method": "GET",
                "http.request.uri": "/index.html",
                "http.response.code": "",
                "frame.number": "4",
                "frame.len": "200",
            }
        ]
        parsed = _parse_packet_rows(rows)
        assert len(parsed) == 1
        assert "HTTP GET /index.html" in parsed[0]["summary"]

    def test_parses_http_response(self):
        rows = [
            {
                "ip.src": "10.0.0.1",
                "ip.dst": "192.168.1.1",
                "tcp.srcport": "80",
                "tcp.dstport": "54321",
                "tcp.flags.str": "·AP·····",
                "http.request.method": "",
                "http.request.uri": "",
                "http.response.code": "200",
                "frame.number": "5",
                "frame.len": "1234",
            }
        ]
        parsed = _parse_packet_rows(rows)
        assert len(parsed) == 1
        assert "HTTP 200" in parsed[0]["summary"]
        assert "1234 bytes" in parsed[0]["summary"]

    def test_skips_rows_without_ips(self):
        rows = [{"ip.src": "", "ip.dst": ""}]
        parsed = _parse_packet_rows(rows)
        assert len(parsed) == 0

    def test_handles_missing_ports(self):
        rows = [
            {
                "ip.src": "192.168.1.1",
                "ip.dst": "10.0.0.1",
                "frame.len": "100",
            }
        ]
        parsed = _parse_packet_rows(rows)
        assert len(parsed) == 1
        assert parsed[0]["src"] == "192.168.1.1"
        assert parsed[0]["dst"] == "10.0.0.1"


class TestSummarizeConversations:
    def test_groups_bidirectional(self):
        flows = [
            {"src": "A:80", "dst": "B:1234", "frame_len": 100},
            {"src": "B:1234", "dst": "A:80", "frame_len": 200},
            {"src": "A:80", "dst": "B:1234", "frame_len": 50},
        ]
        convs = _summarize_conversations(flows)
        assert len(convs) == 1
        assert convs[0]["packets"] == 3
        assert convs[0]["bytes"] == 350


class TestBuildFlowDiagramText:
    def test_produces_text_diagram(self):
        flows = [
            {"src": "192.168.1.1:54321", "dst": "10.0.0.1:80", "summary": "TCP SYN"},
            {"src": "10.0.0.1:80", "dst": "192.168.1.1:54321", "summary": "TCP SYN,ACK"},
        ]
        diagram = _build_flow_diagram_text(flows)
        assert "192.168.1.1:54321" in diagram
        assert "10.0.0.1:80" in diagram
        assert "TCP SYN" in diagram

    def test_empty_flows(self):
        diagram = _build_flow_diagram_text([])
        assert "no flows" in diagram


class TestBuildFlowDiagramMermaid:
    def test_produces_mermaid_diagram(self):
        flows = [
            {"src": "192.168.1.1:54321", "dst": "10.0.0.1:80", "summary": "TCP SYN"},
            {"src": "10.0.0.1:80", "dst": "192.168.1.1:54321", "summary": "TCP SYN,ACK"},
        ]
        diagram = _build_flow_diagram_mermaid(flows)
        assert "sequenceDiagram" in diagram
        assert "participant A as 192.168.1.1:54321" in diagram
        assert "participant B as 10.0.0.1:80" in diagram
        assert "A->>B: TCP SYN" in diagram
        assert "B->>A: TCP SYN,ACK" in diagram

    def test_empty_flows(self):
        diagram = _build_flow_diagram_mermaid([])
        assert "sequenceDiagram" in diagram
        assert "No flows found" in diagram


# ── Tool integration tests ─────────────────────────────────────────────


def _register_tools(mock_tshark, fmt, sec):
    """Register flow_tls tools on a fresh FastMCP instance and return it."""
    from mcp.server.fastmcp import FastMCP

    from netmcp.tools.flow_tls import register_flow_tls_tools

    mcp = FastMCP("test")
    register_flow_tls_tools(mcp, mock_tshark, fmt, sec)
    return mcp


class TestVisualizeNetworkFlows:
    @pytest.mark.asyncio
    async def test_text_output(self, mock_tshark, fmt, sec, sample_pcap):
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "ip.src": "192.168.1.1",
                    "ip.dst": "10.0.0.1",
                    "tcp.srcport": "54321",
                    "tcp.dstport": "80",
                    "tcp.flags.str": "··S·····",
                    "http.request.method": "",
                    "http.request.uri": "",
                    "http.response.code": "",
                    "frame.number": "1",
                    "frame.len": "66",
                },
                {
                    "ip.src": "10.0.0.1",
                    "ip.dst": "192.168.1.1",
                    "tcp.srcport": "80",
                    "tcp.dstport": "54321",
                    "tcp.flags.str": "·AS·····",
                    "http.request.method": "",
                    "http.request.uri": "",
                    "http.response.code": "",
                    "frame.number": "2",
                    "frame.len": "66",
                },
            ]
        )
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap), output_format="text")
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "192.168.1.1" in text
        assert "10.0.0.1" in text

    @pytest.mark.asyncio
    async def test_mermaid_output(self, mock_tshark, fmt, sec, sample_pcap):
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "ip.src": "192.168.1.1",
                    "ip.dst": "10.0.0.1",
                    "tcp.srcport": "54321",
                    "tcp.dstport": "80",
                    "tcp.flags.str": "··S·····",
                    "http.request.method": "",
                    "http.request.uri": "",
                    "http.response.code": "",
                    "frame.number": "1",
                    "frame.len": "66",
                },
            ]
        )
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap), output_format="mermaid")
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "sequenceDiagram" in text
        assert "participant" in text

    @pytest.mark.asyncio
    async def test_invalid_flow_type(self, mock_tshark, fmt, sec, sample_pcap):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap), flow_type="icmp")
        assert result["isError"] is True
        assert "Invalid flow_type" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_invalid_output_format(self, mock_tshark, fmt, sec, sample_pcap):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap), output_format="svg")
        assert result["isError"] is True
        assert "Invalid output_format" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_invalid_filepath(self, mock_tshark, fmt, sec):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath="/nonexistent/file.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_empty_flows(self, mock_tshark, fmt, sec, sample_pcap):
        mock_tshark.export_fields = AsyncMock(return_value=[])
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "flow_count" in text

    @pytest.mark.asyncio
    async def test_udp_flow_type(self, mock_tshark, fmt, sec, sample_pcap):
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "ip.src": "192.168.1.1",
                    "ip.dst": "8.8.8.8",
                    "udp.srcport": "12345",
                    "udp.dstport": "53",
                    "frame.number": "1",
                    "frame.len": "70",
                },
            ]
        )
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "visualize_network_flows":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap), flow_type="udp")
        assert result["isError"] is False
        # Verify export_fields was called with udp filter
        mock_tshark.export_fields.assert_called_once()
        call_args = mock_tshark.export_fields.call_args
        assert (
            call_args.kwargs.get("display_filter") == "udp"
            or call_args[1].get("display_filter") == "udp"
        )


class TestDecryptTlsTraffic:
    @pytest.mark.asyncio
    async def test_decrypt_with_keylog(self, mock_tshark, fmt, sec, sample_pcap, sample_keylog):
        # Mock tshark returning decrypted HTTP data
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0,
                stdout="GET\texample.com\t/index.html\t\t\t1\n\t\t\t200\ttext/html\t2\n",
                stderr="",
            )
        )
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(filepath=str(sample_pcap), keylog_file=str(sample_keylog))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "http_requests" in text
        assert "http_responses" in text
        assert "example.com" in text

    @pytest.mark.asyncio
    async def test_decrypt_no_keylog_error(self, mock_tshark, fmt, sec, sample_pcap):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        # Ensure SSLKEYLOGFILE is not set
        with patch.dict(os.environ, {}, clear=True):
            # Remove SSLKEYLOGFILE if present
            os.environ.pop("SSLKEYLOGFILE", None)
            result = await tool_fn(filepath=str(sample_pcap))

        assert result["isError"] is True
        text = result["content"][0]["text"]
        assert "SSLKEYLOGFILE" in text

    @pytest.mark.asyncio
    async def test_decrypt_env_var_fallback(
        self, mock_tshark, fmt, sec, sample_pcap, sample_keylog
    ):
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0,
                stdout="GET\texample.com\t/\t\t\t1\n",
                stderr="",
            )
        )
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(sample_keylog)}):
            result = await tool_fn(filepath=str(sample_pcap))

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "http_requests" in text

    @pytest.mark.asyncio
    async def test_decrypt_with_output_file(
        self, mock_tshark, fmt, sec, sample_pcap, sample_keylog, tmp_path
    ):
        output_pcap = tmp_path / "decrypted.pcapng"
        # First call: HTTP extraction; second call: write decrypted pcapng
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0,
                stdout="GET\texample.com\t/api\t\t\t1\n",
                stderr="",
            )
        )
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(
            filepath=str(sample_pcap),
            keylog_file=str(sample_keylog),
            output_file=str(output_pcap),
        )
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "output_file" in text
        # Two _run calls: one for HTTP extraction, one for writing
        assert mock_tshark._run.call_count == 2

    @pytest.mark.asyncio
    async def test_decrypt_invalid_filepath(self, mock_tshark, fmt, sec, sample_keylog):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(
            filepath="/nonexistent/file.pcap",
            keylog_file=str(sample_keylog),
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_decrypt_invalid_keylog(self, mock_tshark, fmt, sec, sample_pcap):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(
            filepath=str(sample_pcap),
            keylog_file="/nonexistent/keylog.txt",
        )
        assert result["isError"] is True
        assert "does not exist" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_decrypt_invalid_output_extension(
        self, mock_tshark, fmt, sec, sample_pcap, sample_keylog, tmp_path
    ):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(
            filepath=str(sample_pcap),
            keylog_file=str(sample_keylog),
            output_file=str(tmp_path / "out.txt"),
        )
        assert result["isError"] is True
        assert "Invalid output extension" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_decrypt_path_traversal_keylog(self, mock_tshark, fmt, sec, sample_pcap):
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(
            filepath=str(sample_pcap),
            keylog_file="../../etc/passwd",
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_decrypt_write_failure(
        self, mock_tshark, fmt, sec, sample_pcap, sample_keylog, tmp_path
    ):
        output_pcap = tmp_path / "decrypted.pcapng"
        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return MagicMock(returncode=0, stdout="GET\tex.com\t/\t\t\t1\n", stderr="")
            return MagicMock(returncode=1, stdout="", stderr="write error")

        mock_tshark._run = AsyncMock(side_effect=side_effect)
        mcp = _register_tools(mock_tshark, fmt, sec)
        tool_fn = None
        for t in mcp._tool_manager._tools.values():
            if t.name == "decrypt_tls_traffic":
                tool_fn = t.fn
                break

        result = await tool_fn(
            filepath=str(sample_pcap),
            keylog_file=str(sample_keylog),
            output_file=str(output_pcap),
        )
        assert result["isError"] is True
        assert "Failed to write" in result["content"][0]["text"]
