"""Tests for tshark feature gaps (hex dump, CSV export, packet summary, stream formats, editcap, BPF presets)."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


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
        tshark.follow_stream = AsyncMock(return_value="stream content")
        tshark.export_fields = AsyncMock(return_value=[])
        tshark.export_json = AsyncMock(return_value=[])
        tshark.convert_format = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )
        tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )
        yield tshark


async def call(mcp: FastMCP, name: str, **kwargs):
    """Helper to call a registered tool by name."""
    return await mcp._tool_manager.call_tool(name, kwargs)


# ── Gap 1: hex dump in decode_packet ────────────────────────────────────


class TestDecodePacketHexDump:
    @pytest.mark.asyncio
    async def test_decode_packet_hex_dump(self, mock_tshark, fmt, sec, tmp_path):
        """When hex_dump=True, -x flag is passed to tshark."""
        from netmcp.tools.pcap_tools import register_pcap_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0,
                stdout="Frame 1: 100 bytes\n  0000  aa bb cc dd\n",
                stderr="",
            )
        )

        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=1, verbose=True, hex_dump=True,
        )

        assert result["isError"] is False
        # Verify -x was passed in the args
        call_args = mock_tshark._run.call_args[0][0]
        assert "-x" in call_args
        assert "-V" in call_args

    @pytest.mark.asyncio
    async def test_decode_packet_no_hex_dump(self, mock_tshark, fmt, sec, tmp_path):
        """When hex_dump=False (default), -x flag is NOT passed."""
        from netmcp.tools.pcap_tools import register_pcap_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(
                returncode=0, stdout="Frame 1: 100 bytes\n", stderr=""
            )
        )

        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "decode_packet",
            filepath=str(pcap), packet_number=1, verbose=True, hex_dump=False,
        )

        assert result["isError"] is False
        call_args = mock_tshark._run.call_args[0][0]
        assert "-x" not in call_args


# ── Gap 2: CSV export with -E flags ────────────────────────────────────


class TestExportPacketsCsv:
    @pytest.mark.asyncio
    async def test_export_packets_csv_success(self, mock_tshark, fmt, sec, tmp_path):
        """CSV export uses tshark -E flags correctly."""
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        csv_output = '"frame.number","ip.src"\n"1","10.0.0.1"\n'
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=csv_output, stderr="")
        )

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath=str(pcap))

        assert result["isError"] is False

        # Verify -E flags in args
        call_args = mock_tshark._run.call_args[0][0]
        assert "-T" in call_args
        assert "fields" in call_args
        assert "-E" in call_args
        # Check for header=y and quote=d
        e_args = [call_args[i + 1] for i, v in enumerate(call_args) if v == "-E"]
        assert "header=y" in e_args
        assert "quote=d" in e_args
        assert any("separator=" in a for a in e_args)

    @pytest.mark.asyncio
    async def test_export_packets_csv_custom_separator(self, mock_tshark, fmt, sec, tmp_path):
        """Custom separator is passed to tshark -E separator flag."""
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="header\ndata\n", stderr="")
        )

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "export_packets_csv",
            filepath=str(pcap), separator="|",
        )

        assert result["isError"] is False
        call_args = mock_tshark._run.call_args[0][0]
        e_args = [call_args[i + 1] for i, v in enumerate(call_args) if v == "-E"]
        assert "separator=|" in e_args

    @pytest.mark.asyncio
    async def test_export_packets_csv_with_filter(self, mock_tshark, fmt, sec, tmp_path):
        """Display filter is passed with -Y flag."""
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "export_packets_csv",
            filepath=str(pcap), display_filter="http",
        )

        assert result["isError"] is False
        call_args = mock_tshark._run.call_args[0][0]
        assert "-Y" in call_args
        y_idx = call_args.index("-Y")
        assert call_args[y_idx + 1] == "http"

    @pytest.mark.asyncio
    async def test_export_packets_csv_default_fields(self, mock_tshark, fmt, sec, tmp_path):
        """Default fields include _ws.col.Protocol and _ws.col.Info."""
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath=str(pcap))

        assert result["isError"] is False
        call_args = mock_tshark._run.call_args[0][0]
        # Collect all -e field values
        e_fields = [call_args[i + 1] for i, v in enumerate(call_args) if v == "-e"]
        assert "_ws.col.Protocol" in e_fields
        assert "_ws.col.Info" in e_fields


# ── Gap 3: get_packet_summary ───────────────────────────────────────────


class TestGetPacketSummary:
    @pytest.mark.asyncio
    async def test_get_packet_summary(self, mock_tshark, fmt, sec, tmp_path):
        """Packet summary uses column fields for readable output."""
        from netmcp.tools.export_tools import register_export_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        summary_out = (
            "frame.number\tframe.time_relative\tip.src\tip.dst\t_ws.col.Protocol\tframe.len\t_ws.col.Info\n"
            "1\t0.000\t10.0.0.1\t10.0.0.2\tTCP\t100\tSYN\n"
        )
        mock_tshark._run = AsyncMock(
            return_value=MagicMock(returncode=0, stdout=summary_out, stderr="")
        )

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_packet_summary", file_path=str(pcap), count=20)

        assert result["isError"] is False

        # Verify column fields used
        call_args = mock_tshark._run.call_args[0][0]
        e_fields = [call_args[i + 1] for i, v in enumerate(call_args) if v == "-e"]
        assert "_ws.col.Protocol" in e_fields
        assert "_ws.col.Info" in e_fields
        assert "frame.time_relative" in e_fields

        # Verify -c flag for count
        assert "-c" in call_args
        c_idx = call_args.index("-c")
        assert call_args[c_idx + 1] == "20"


# ── Gap 4: Stream follow format exposure ────────────────────────────────


class TestFollowStreamFormat:
    @pytest.mark.asyncio
    async def test_follow_tcp_stream_hex_format(self, mock_tshark, fmt, sec, tmp_path):
        """TCP stream follow with hex format passes format to tshark."""
        from netmcp.tools.streams import register_stream_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.follow_stream = AsyncMock(return_value="00000000  47 45 54 20 2f")

        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "follow_tcp_stream",
            filepath=str(pcap), stream_index=0, output_format="hex",
        )

        assert result["isError"] is False
        mock_tshark.follow_stream.assert_called_once_with(
            str(pcap.resolve()), 0, "tcp", "hex"
        )

    @pytest.mark.asyncio
    async def test_follow_tcp_stream_invalid_format(self, mock_tshark, fmt, sec, tmp_path):
        """Invalid format raises error from tshark interface."""
        from netmcp.tools.streams import register_stream_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.follow_stream = AsyncMock(
            side_effect=ValueError("Invalid format: 'binary'. Allowed: ascii, hex, raw")
        )

        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "follow_tcp_stream",
            filepath=str(pcap), stream_index=0, output_format="binary",
        )

        assert result["isError"] is True
        assert "binary" in result["content"][0]["text"]


# ── Gap 5: editcap -F format conversion ────────────────────────────────


class TestConvertPcapFormatEditcap:
    @pytest.mark.asyncio
    async def test_convert_pcap_format_success(self, mock_tshark, fmt, sec, tmp_path):
        """Successful format conversion with editcap -F."""
        from netmcp.tools.pcap_tools import register_pcap_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/editcap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            result = await call(
                mcp, "convert_pcap_format",
                file_path=str(pcap), output_format="pcapng",
            )

        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Format Conversion" in text

        # Verify editcap -F was used
        call_args = mock_exec.call_args[0]
        assert "-F" in call_args
        assert "pcapng" in call_args

    @pytest.mark.asyncio
    async def test_convert_pcap_format_invalid_format(self, mock_tshark, fmt, sec, tmp_path):
        """Invalid format is rejected."""
        from netmcp.tools.pcap_tools import register_pcap_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp, "convert_pcap_format",
            file_path=str(pcap), output_format="invalid_format",
        )

        assert result["isError"] is True
        assert "invalid_format" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_convert_pcap_format_snoop(self, mock_tshark, fmt, sec, tmp_path):
        """Conversion to snoop format is allowed."""
        from netmcp.tools.pcap_tools import register_pcap_tools

        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        mcp = FastMCP("test")
        register_pcap_tools(mcp, mock_tshark, fmt, sec)

        with patch("netmcp.tools.pcap_tools.shutil.which", return_value="/usr/bin/editcap"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await call(
                mcp, "convert_pcap_format",
                file_path=str(pcap), output_format="snoop",
            )

        assert result["isError"] is False


# ── Gap 6: BPF filter presets ───────────────────────────────────────────


class TestBpfPresets:
    def test_bpf_preset_http(self):
        """HTTP preset expands to correct BPF filter."""
        from netmcp.tools.capture import BPF_PRESETS

        assert BPF_PRESETS["http"] == "tcp port 80 or tcp port 443"

    def test_bpf_preset_dns(self):
        """DNS preset is available."""
        from netmcp.tools.capture import BPF_PRESETS

        assert BPF_PRESETS["dns"] == "port 53"

    def test_bpf_preset_passthrough(self):
        """Custom filter not in presets is passed through unchanged."""
        from netmcp.tools.capture import BPF_PRESETS

        custom_filter = "tcp port 8080 and host 10.0.0.1"
        result = BPF_PRESETS.get(custom_filter, custom_filter)
        assert result == custom_filter

    @pytest.mark.asyncio
    async def test_bpf_preset_applied_in_capture(self, mock_tshark, fmt, sec):
        """BPF preset is applied when capturing with a preset name."""
        from netmcp.tools.capture import register_capture_tools

        mcp = FastMCP("test")
        register_capture_tools(mcp, mock_tshark, fmt, sec)

        mock_tshark.capture_live = AsyncMock(
            return_value=Path("/nonexistent/test.pcap")
        )
        mock_tshark.read_pcap = AsyncMock(return_value=[])

        # Patch os.unlink so cleanup doesn't fail
        with patch("os.unlink"):
            await call(
                mcp, "capture_live_packets",
                interface="eth0", duration=1, bpf_filter="dns",
            )

        # The capture should have been called with expanded filter
        mock_tshark.capture_live.assert_called_once()
        captured_filter = mock_tshark.capture_live.call_args[1]["bpf_filter"]
        assert captured_filter == "port 53"
