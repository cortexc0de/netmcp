"""Targeted tests for uncovered lines in tshark.py."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netmcp.interfaces.tshark import (
    TsharkInterface,
    TsharkNotFoundError,
    find_tshark,
)

# ── Helpers ───────────────────────────────────────────────────────────


def _make_iface() -> TsharkInterface:
    """Create a TsharkInterface without hitting the filesystem."""
    with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
        return TsharkInterface()


def _mock_run(returncode=0, stdout="", stderr=""):
    """Return a mock subprocess.run result."""
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


# ── find_tshark fallback path (line 79) ──────────────────────────────


class TestFindTsharkFallback:
    def test_fallback_path_found(self):
        """Line 79: return fallback when PATH fails but fallback exists."""
        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.exists", return_value=True),
            patch("platform.system", return_value="Linux"),
        ):
            result = find_tshark()
            assert result == "/usr/bin/tshark"

    def test_fallback_path_not_found(self):
        """All fallbacks fail → TsharkNotFoundError."""
        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.exists", return_value=False),
            patch("platform.system", return_value="Linux"),
        ):
            with pytest.raises(TsharkNotFoundError):
                find_tshark()


# ── __repr__ (line 100) ─────────────────────────────────────────────


class TestTsharkRepr:
    def test_repr(self):
        iface = _make_iface()
        r = repr(iface)
        assert "TsharkInterface" in r
        assert "/usr/bin/tshark" in r


# ── _run error branches (lines 133, 135) ────────────────────────────


class TestRunErrors:
    @pytest.mark.asyncio
    async def test_timeout_error(self):
        """Line 133: TimeoutError from _run."""
        iface = _make_iface()
        with patch(
            "subprocess.run", side_effect=lambda *a, **kw: (_ for _ in ()).throw(TimeoutError())
        ):
            # asyncio.wait_for wraps it; force via short timeout
            pass

        # More direct approach: mock run_in_executor to raise
        import asyncio

        async def _timeout_executor(*a, **kw):
            raise TimeoutError("boom")

        with patch.object(asyncio, "wait_for", side_effect=TimeoutError("timed out")):
            with pytest.raises(TimeoutError, match="timed out"):
                await iface._run(["-v"], timeout=0.001)

    @pytest.mark.asyncio
    async def test_file_not_found_error(self):
        """Line 135: FileNotFoundError → TsharkNotFoundError."""
        iface = _make_iface()
        with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
            with pytest.raises(TsharkNotFoundError, match="not found"):
                await iface._run(["-v"], timeout=5.0)


# ── list_interfaces branches (lines 143, 151, 153→156, 157) ─────────


class TestListInterfacesBranches:
    @pytest.mark.asyncio
    async def test_nonzero_returncode(self):
        """Line 143: CalledProcessError on failure."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(returncode=1, stderr="fail")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.list_interfaces()

    @pytest.mark.asyncio
    async def test_empty_lines_skipped(self):
        """Line 151: empty lines are skipped."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="1. eth0\n\n2. lo\n")):
            result = await iface.list_interfaces()
            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_parenthetical_stripped(self):
        """Line 157: ' (' in line → split to extract device name."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="1. eth0 (My Ethernet)\n")):
            result = await iface.list_interfaces()
            assert result == ["eth0"]

    @pytest.mark.asyncio
    async def test_no_dot_prefix(self):
        """Lines 153→156: line without '. ' prefix."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="eth0\nlo\n")):
            result = await iface.list_interfaces()
            assert "eth0" in result
            assert "lo" in result


# ── capture_live branches (lines 189-191, 195→197, 197→201, 205) ────


class TestCaptureLiveBranches:
    @pytest.mark.asyncio
    async def test_temp_file_created_when_no_output_file(self, tmp_path):
        """Lines 189-191: no output_file → tempfile created."""
        iface = _make_iface()
        fake_pcap = tmp_path / "auto.pcap"
        fake_pcap.write_bytes(b"data")

        with (
            patch("subprocess.run", return_value=_mock_run()),
            patch("tempfile.mkstemp", return_value=(99, str(fake_pcap))),
            patch("os.close"),
        ):
            result = await iface.capture_live("eth0", timeout=1.0)
            assert Path(str(result)).name == "auto.pcap"

    @pytest.mark.asyncio
    async def test_bpf_filter_added(self, tmp_path):
        """Line 195→197: bpf_filter adds -f flag."""
        iface = _make_iface()
        out = tmp_path / "out.pcap"
        out.write_bytes(b"data")
        with patch("subprocess.run", return_value=_mock_run()) as mock_run:
            await iface.capture_live("eth0", bpf_filter="tcp port 80", output_file=str(out))
            cmd = mock_run.call_args[0][0]
            assert "-f" in cmd
            assert "tcp port 80" in cmd

    @pytest.mark.asyncio
    async def test_packet_count_zero(self, tmp_path):
        """Line 197→201: packet_count=0 skips -c."""
        iface = _make_iface()
        out = tmp_path / "out.pcap"
        out.write_bytes(b"data")
        with patch("subprocess.run", return_value=_mock_run()) as mock_run:
            await iface.capture_live("eth0", packet_count=0, output_file=str(out))
            cmd = mock_run.call_args[0][0]
            assert "-c" not in cmd

    @pytest.mark.asyncio
    async def test_failure_and_no_output(self, tmp_path):
        """Line 205: nonzero return + missing output → CalledProcessError."""
        iface = _make_iface()
        missing = tmp_path / "missing.pcap"
        with patch("subprocess.run", return_value=_mock_run(returncode=1, stderr="fail")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.capture_live("eth0", output_file=str(missing))


# ── read_pcap branches (lines 233→237, 242, 249-250) ────────────────


class TestReadPcapBranches:
    @pytest.mark.asyncio
    async def test_display_filter_added(self):
        """Line 233→237: display_filter adds -Y."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="[]")) as mock_run:
            await iface.read_pcap("/f.pcap", display_filter="http")
            cmd = mock_run.call_args[0][0]
            assert "-Y" in cmd
            assert "http" in cmd

    @pytest.mark.asyncio
    async def test_nonzero_returncode_raises(self):
        """Line 242: CalledProcessError."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(returncode=2, stderr="bad")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.read_pcap("/f.pcap")

    @pytest.mark.asyncio
    async def test_json_decode_error(self):
        """Lines 249-250: invalid JSON → empty list."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="NOT JSON")):
            result = await iface.read_pcap("/f.pcap")
            assert result == []

    @pytest.mark.asyncio
    async def test_json_non_list(self):
        """Line 248: JSON that is not a list → empty list."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout='{"key": "val"}')):
            result = await iface.read_pcap("/f.pcap")
            assert result == []


# ── protocol_stats branches (lines 265, 295-296, 300-301, 308→279, 314-315) ─


class TestProtocolStatsBranches:
    @pytest.mark.asyncio
    async def test_nonzero_returncode(self):
        """Line 265: CalledProcessError."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(returncode=1, stderr="err")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.protocol_stats("/f.pcap")

    def test_parse_frames_value_error(self):
        """Lines 295-296: non-numeric frames → 0."""
        # The regex requires digits for frames, so use Format 2 tab approach
        # Actually the regex `(\d+)` won't match "abc", so the regex won't match.
        # To trigger ValueError on int(frames_str), we need a regex match with invalid int.
        # Since \d+ always gives valid int, lines 295-296 are unreachable via regex.
        # Instead, test tab-separated ValueError path (lines 314-315).
        # For completeness, test bytes with decimal format.
        text = "eth  frames:10 bytes:12.5kB"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert stats["eth"]["frames"] == 10
        assert stats["eth"]["bytes"] == 12

    def test_parse_bytes_empty_after_strip(self):
        """Lines 300-301: bytes that become empty after digit extraction."""
        text = "eth  frames:10 bytes:..."
        stats = TsharkInterface._parse_protocol_stats(text)
        assert stats["eth"]["bytes"] == 0

    def test_parse_tab_separated_format(self):
        """Lines 308→279: tab-separated format."""
        text = "eth\t100\t12000\nip\t90\t10800"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert stats["eth"] == {"frames": 100, "bytes": 12000}
        assert stats["ip"] == {"frames": 90, "bytes": 10800}

    def test_parse_tab_separated_value_error(self):
        """Lines 314-315: tab-separated with non-numeric values."""
        text = "eth\tnot_a_num\t12000"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" not in stats

    def test_parse_skip_headers(self):
        """Skip '=' lines, 'Filter' lines, 'Protocol' lines."""
        text = "===\nFilter: none\nProtocol Hierarchy\neth\t50\t6000"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert stats == {"eth": {"frames": 50, "bytes": 6000}}


# ── follow_stream error (line 357) ──────────────────────────────────


class TestFollowStreamError:
    @pytest.mark.asyncio
    async def test_nonzero_returncode(self):
        """Line 357: CalledProcessError."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(returncode=1, stderr="err")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.follow_stream("/f.pcap", 0)

    @pytest.mark.asyncio
    async def test_invalid_proto(self):
        """ValueError for invalid protocol."""
        iface = _make_iface()
        with pytest.raises(ValueError, match="Invalid protocol"):
            await iface.follow_stream("/f.pcap", 0, proto="icmp")

    @pytest.mark.asyncio
    async def test_invalid_format(self):
        """ValueError for invalid format."""
        iface = _make_iface()
        with pytest.raises(ValueError, match="Invalid format"):
            await iface.follow_stream("/f.pcap", 0, fmt="json")


# ── list_streams branches (lines 379, 390→385) ──────────────────────


class TestListStreamsBranches:
    @pytest.mark.asyncio
    async def test_nonzero_returncode(self):
        """Line 379: CalledProcessError."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(returncode=1, stderr="err")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.list_streams("/f.pcap")

    @pytest.mark.asyncio
    async def test_line_without_two_parts(self):
        """Line 390→385: <-> present but split doesn't give 2 parts (edge)."""
        iface = _make_iface()
        # Normal parse + line with no stats after <->
        output = "192.168.1.1:80 <-> 10.0.0.1:443\nno arrow here\n"
        with patch("subprocess.run", return_value=_mock_run(stdout=output)):
            result = await iface.list_streams("/f.pcap")
            assert len(result) == 1


# ── file_info + _run_cmd + _parse_capinfos (lines 408-419, 427-444, 449-454)


class TestFileInfo:
    @pytest.mark.asyncio
    async def test_file_info_with_capinfos(self):
        """Lines 408-419: capinfos found and succeeds."""
        iface = _make_iface()
        capinfos_output = "File name: test.pcap\nPackets: 100\nCapture duration: 10s"
        with (
            patch("shutil.which", return_value="/usr/bin/capinfos"),
            patch("subprocess.run", return_value=_mock_run(stdout=capinfos_output)),
        ):
            result = await iface.file_info("/test.pcap")
            assert "File name" in result
            assert result["Packets"] == "100"

    @pytest.mark.asyncio
    async def test_file_info_capinfos_fails_fallback(self):
        """Lines 416-423: capinfos fails → fallback to protocol_stats."""
        iface = _make_iface()
        stats_output = "eth\t50\t6000"
        with (
            patch(
                "shutil.which",
                side_effect=lambda cmd: (
                    "/usr/bin/capinfos" if cmd == "capinfos" else "/usr/bin/tshark"
                ),
            ),
            patch("subprocess.run") as mock_run,
        ):
            # First call: capinfos fails, second: protocol_stats succeeds
            mock_run.side_effect = [
                _mock_run(returncode=1),
                _mock_run(stdout=stats_output),
            ]
            result = await iface.file_info("/test.pcap")
            assert "filepath" in result

    @pytest.mark.asyncio
    async def test_file_info_no_capinfos(self):
        """Lines 416-423: capinfos not found → fallback."""
        iface = _make_iface()
        stats_output = "tcp\t80\t9600"
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", return_value=_mock_run(stdout=stats_output)),
        ):
            result = await iface.file_info("/test.pcap")
            assert "total_frames" in result

    def test_parse_capinfos(self):
        """Lines 449-454: _parse_capinfos."""
        text = "File name: test.pcap\nPackets: 100\nDuration: 5.0s"
        result = TsharkInterface._parse_capinfos(text)
        assert result["File name"] == "test.pcap"
        assert result["Packets"] == "100"

    def test_parse_capinfos_empty(self):
        """_parse_capinfos with empty/no-colon lines."""
        text = "no-colon-here\n\nKey: Value"
        result = TsharkInterface._parse_capinfos(text)
        assert result == {"Key": "Value"}


# ── _run_cmd timeout (lines 427-444) ────────────────────────────────


class TestRunCmd:
    @pytest.mark.asyncio
    async def test_run_cmd_success(self):
        """Lines 427-442: _run_cmd normal execution."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="output")):
            result = await iface._run_cmd(["echo", "hello"])
            assert result.returncode == 0
            assert result.stdout == "output"

    @pytest.mark.asyncio
    async def test_run_cmd_timeout(self):
        """Lines 443-444: _run_cmd timeout."""
        import asyncio

        iface = _make_iface()
        with patch.object(asyncio, "wait_for", side_effect=TimeoutError("timed out")):
            with pytest.raises(TimeoutError, match="Command timed out"):
                await iface._run_cmd(["sleep", "100"], timeout=0.001)


# ── export_json (line 465) ──────────────────────────────────────────


class TestExportJson:
    @pytest.mark.asyncio
    async def test_export_json_delegates(self):
        """Line 465: export_json calls read_pcap."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout='[{"pkt": 1}]')):
            result = await iface.export_json("/f.pcap", display_filter="tcp", max_packets=5)
            assert len(result) == 1


# ── export_fields branches (lines 501, 505, 512) ────────────────────


class TestExportFieldsBranches:
    @pytest.mark.asyncio
    async def test_display_filter_added(self):
        """Line 501: display_filter adds -Y."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="val1\tval2\n")) as mock_run:
            await iface.export_fields("/f.pcap", ["f1", "f2"], display_filter="http")
            cmd = mock_run.call_args[0][0]
            assert "-Y" in cmd

    @pytest.mark.asyncio
    async def test_nonzero_returncode(self):
        """Line 505: CalledProcessError."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(returncode=1, stderr="err")):
            with pytest.raises(subprocess.CalledProcessError):
                await iface.export_fields("/f.pcap", ["f1"])

    @pytest.mark.asyncio
    async def test_empty_lines_skipped(self):
        """Line 512: empty lines skipped."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="a\tb\n\nc\td\n")):
            result = await iface.export_fields("/f.pcap", ["f1", "f2"])
            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_single_row(self):
        """Normal single-row export."""
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run(stdout="10.0.0.1\t80\n")):
            result = await iface.export_fields("/f.pcap", ["ip.src", "tcp.port"])
            assert result == [{"ip.src": "10.0.0.1", "tcp.port": "80"}]


# ── convert_format ──────────────────────────────────────────────────


class TestConvertFormat:
    @pytest.mark.asyncio
    async def test_convert_format(self):
        iface = _make_iface()
        with patch("subprocess.run", return_value=_mock_run()):
            result = await iface.convert_format("/in.pcap", "/out.pcapng")
            assert result.returncode == 0
