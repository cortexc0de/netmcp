"""Tests for TsharkInterface."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from netmcp.interfaces.tshark import TsharkInterface, TsharkNotFoundError


@pytest.fixture
def mock_pcap(tmp_path):
    """Create a minimal mock pcap file."""
    p = tmp_path / "mock.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)
    return p


class TestTsharkInit:
    def test_auto_find_tshark(self):
        """Should find tshark in PATH or raise."""
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            iface = TsharkInterface()
            assert iface.tshark_path == "/usr/bin/tshark"

    def test_custom_path(self):
        """Should accept custom tshark path."""
        iface = TsharkInterface("/custom/tshark")
        assert iface.tshark_path == "/custom/tshark"

    def test_not_found_raises(self):
        """Should raise TsharkNotFoundError if tshark not found."""
        with patch("shutil.which", return_value=None):
            with patch("pathlib.Path.exists", return_value=False):
                with pytest.raises(TsharkNotFoundError, match="tshark not found"):
                    TsharkInterface()

    def test_version_check(self):
        """Should successfully run tshark --version."""
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="TShark 4.2.0")
                iface = TsharkInterface()
                assert iface.tshark_path == "/usr/bin/tshark"


class TestListInterfaces:
    @pytest.mark.asyncio
    async def test_returns_interfaces(self):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="1. eth0\n2. lo\n3. docker0\n",
                )
                iface = TsharkInterface()
                result = await iface.list_interfaces()
                assert len(result) == 3
                assert any("eth0" in i for i in result)
                assert any("lo" in i for i in result)

    @pytest.mark.asyncio
    async def test_failure_raises(self):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.CalledProcessError(1, "tshark")
                iface = TsharkInterface()
                with pytest.raises(subprocess.CalledProcessError):
                    await iface.list_interfaces()


class TestCaptureLive:
    @pytest.mark.asyncio
    async def test_basic_capture(self, tmp_path):
        output_file = tmp_path / "test.pcap"
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="")
                # Create the output file so it exists
                output_file.write_bytes(b"fake pcap")

                iface = TsharkInterface()
                await iface.capture_live(
                    interface="eth0",
                    bpf_filter="tcp port 80",
                    packet_count=10,
                    timeout=5.0,
                    output_file=str(output_file),
                )
                # Verify subprocess was called with correct args
                assert mock_run.call_count >= 1
                call_args = mock_run.call_args
                cmd = call_args[0][0]  # First positional arg is the command list
                assert "tshark" in cmd[0] or "-i" in cmd
                assert "-i" in cmd
                assert "eth0" in cmd


class TestReadPcap:
    @pytest.mark.asyncio
    async def test_read_pcap_json(self, mock_pcap):
        packets = [
            {
                "_source": {
                    "layers": {
                        "frame": {"number": "1"},
                        "ip": {"src": "10.0.0.1", "dst": "10.0.0.2"},
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"number": "2"},
                        "ip": {"src": "10.0.0.2", "dst": "10.0.0.1"},
                    }
                }
            },
        ]
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps(packets),
                )
                iface = TsharkInterface()
                result = await iface.read_pcap(str(mock_pcap))
                assert len(result) == 2
                assert result[0]["_source"]["layers"]["ip"]["src"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_read_pcap_with_filter(self, mock_pcap):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="[]")
                iface = TsharkInterface()
                await iface.read_pcap(str(mock_pcap), display_filter="http")
                call_args = mock_run.call_args[0][0]
                assert "-Y" in call_args
                assert "http" in call_args

    @pytest.mark.asyncio
    async def test_read_pcap_max_packets(self, mock_pcap):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="[]")
                iface = TsharkInterface()
                await iface.read_pcap(str(mock_pcap), max_packets=100)
                call_args = mock_run.call_args[0][0]
                assert "-c" in call_args
                assert "100" in call_args

    @pytest.mark.asyncio
    async def test_tshark_error_raises(self, mock_pcap):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.CalledProcessError(
                    1, "tshark", stderr="invalid pcap"
                )
                iface = TsharkInterface()
                with pytest.raises(subprocess.CalledProcessError):
                    await iface.read_pcap(str(mock_pcap))


class TestProtocolStats:
    @pytest.mark.asyncio
    async def test_returns_stats(self, mock_pcap):
        stats_output = """
===================================================================
Protocol Hierarchy Statistics

Filter:

eth                                    frames:100 bytes:12000
  ip                                   frames:90 bytes:10800
    tcp                                frames:80 bytes:9600
      http                             frames:20 bytes:2400
    udp                                frames:10 bytes:1200
      dns                              frames:10 bytes:1200
===================================================================
"""
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=stats_output)
                iface = TsharkInterface()
                result = await iface.protocol_stats(str(mock_pcap))
                assert "eth" in result
                assert result["eth"]["frames"] == 100


class TestFollowStream:
    @pytest.mark.asyncio
    async def test_follow_tcp_ascii(self, mock_pcap):
        stream_data = """GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 200 OK\r\n\r\nHello"""
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=stream_data)
                iface = TsharkInterface()
                result = await iface.follow_stream(
                    str(mock_pcap), stream_idx=0, proto="tcp", fmt="ascii"
                )
                assert "GET / HTTP/1.1" in result
                assert "200 OK" in result


class TestListStreams:
    @pytest.mark.asyncio
    async def test_list_tcp_streams(self, mock_pcap):
        conv_output = """
================================================================================
TCP Conversations
Filter:<No Filter>
                                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.1.1:443              <-> 10.0.0.1:54321                    100 120 kB       50 60 kB        150 180 kB      0.000000000       10.123456
================================================================================
"""
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=conv_output)
                iface = TsharkInterface()
                result = await iface.list_streams(str(mock_pcap), "tcp")
                assert len(result) > 0
                assert "192.168.1.1" in result[0]["endpoint_a"]


class TestFileExists:
    def test_tshark_property(self):
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            iface = TsharkInterface()
            assert iface.tshark_path == "/usr/bin/tshark"
