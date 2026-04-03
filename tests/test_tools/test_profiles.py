"""Tests for Wireshark profile tools."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface, TsharkResult
from netmcp.tools.profiles import (
    _find_profile_dir,
    _parse_colorfilters,
    register_profile_tools,
)

# ── Fixtures ────────────────────────────────────────────────────────────


def _parse_result_json(result: dict) -> dict:
    """Extract JSON data from a format_success result, stripping any title header."""
    text = result["content"][0]["text"]
    # format_success prepends "=== Title ===\n" before the JSON
    if text.startswith("==="):
        text = text.split("\n", 1)[1]
    return json.loads(text)


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
        tshark._run = AsyncMock(
            return_value=TsharkResult(
                returncode=0,
                stdout=json.dumps(
                    [
                        {
                            "_source": {
                                "layers": {
                                    "ip.src": ["10.0.0.1"],
                                    "ip.dst": ["10.0.0.2"],
                                    "frame.number": ["1"],
                                    "frame.protocols": ["eth:ethertype:ip:tcp"],
                                }
                            }
                        }
                    ]
                ),
                stderr="",
            )
        )
        yield tshark


# ── Unit tests for helpers ──────────────────────────────────────────────


class TestParseColorfilters:
    def test_parse_basic(self):
        content = "@HTTP@http@[0,0,0][255,255,255]\n"
        result = _parse_colorfilters(content)
        assert len(result) == 1
        assert result[0]["name"] == "HTTP"
        assert result[0]["display_filter"] == "http"
        assert result[0]["foreground_rgb"] == [0, 0, 0]
        assert result[0]["background_rgb"] == [255, 255, 255]
        assert result[0]["enabled"] is True

    def test_parse_disabled(self):
        content = "!@Disabled Rule@tcp.port==80@[0,0,0][128,128,128]\n"
        result = _parse_colorfilters(content)
        assert len(result) == 1
        assert result[0]["name"] == "Disabled Rule"
        assert result[0]["enabled"] is False

    def test_parse_multiple(self):
        content = (
            "@DNS@dns@[0,0,0][200,200,255]\n"
            "@TCP RST@tcp.flags.reset==1@[255,0,0][255,255,255]\n"
            "# comment line\n"
            "\n"
        )
        result = _parse_colorfilters(content)
        assert len(result) == 2
        assert result[0]["name"] == "DNS"
        assert result[1]["name"] == "TCP RST"

    def test_parse_empty(self):
        assert _parse_colorfilters("") == []
        assert _parse_colorfilters("# only comments\n") == []

    def test_parse_malformed_skipped(self):
        content = "@incomplete\nnot a filter\n@Valid@tcp@[1,2,3][4,5,6]\n"
        result = _parse_colorfilters(content)
        assert len(result) == 1
        assert result[0]["name"] == "Valid"


class TestFindProfileDir:
    def test_profile_not_found(self):
        with pytest.raises(ValueError, match="not found"):
            _find_profile_dir("nonexistent_profile_xyz")

    def test_empty_name(self):
        with pytest.raises(ValueError, match="non-empty"):
            _find_profile_dir("")

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="Invalid characters"):
            _find_profile_dir("../../etc")

    def test_shell_metachar_rejected(self):
        for bad in ["prof;rm", "prof|ls", "prof&bg", "prof`cmd`"]:
            with pytest.raises(ValueError, match="Invalid characters"):
                _find_profile_dir(bad)

    def test_found(self, tmp_path):
        profile_dir = tmp_path / "profiles" / "myprofile"
        profile_dir.mkdir(parents=True)
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            result = _find_profile_dir("myprofile")
            assert result == profile_dir


# ── Tool tests ──────────────────────────────────────────────────────────


class TestListWiresharkProfiles:
    @pytest.mark.asyncio
    async def test_list_profiles(self, mock_tshark, fmt, sec, tmp_path):
        # Set up fake profiles
        profiles_dir = tmp_path / "profiles"
        prof_a = profiles_dir / "alpha"
        prof_a.mkdir(parents=True)
        (prof_a / "colorfilters").write_text("@test@tcp@[0,0,0][1,1,1]\n")
        (prof_a / "preferences").write_text("gui.column.format: ...\n")

        prof_b = profiles_dir / "beta"
        prof_b.mkdir(parents=True)
        (prof_b / "decode_as_entries").write_text("...\n")

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[profiles_dir],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["list_wireshark_profiles"].fn
            result = await tool_fn()

        assert result["isError"] is False
        data = _parse_result_json(result)
        assert len(data["profiles"]) == 2
        alpha = next(p for p in data["profiles"] if p["name"] == "alpha")
        assert alpha["has_colorfilters"] is True
        assert alpha["has_preferences"] is True
        assert alpha["has_decode_as"] is False

        beta = next(p for p in data["profiles"] if p["name"] == "beta")
        assert beta["has_decode_as"] is True

    @pytest.mark.asyncio
    async def test_list_profiles_empty(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "nonexistent"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["list_wireshark_profiles"].fn
            result = await tool_fn()

        assert result["isError"] is False
        data = _parse_result_json(result)
        assert data["profiles"] == []


class TestApplyProfileCapture:
    @pytest.mark.asyncio
    async def test_apply_success(self, mock_tshark, fmt, sec, tmp_path):
        # Create pcap file and profile
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        profile_dir = tmp_path / "profiles" / "myprof"
        profile_dir.mkdir(parents=True)

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["apply_profile_capture"].fn
            result = await tool_fn(filepath=str(pcap), profile_name="myprof")

        assert result["isError"] is False
        data = _parse_result_json(result)
        assert data["profile"] == "myprof"
        assert data["packets_analyzed"] == 1
        assert len(data["packets"]) == 1

        # Verify tshark was called with -C flag
        call_args = mock_tshark._run.call_args[0][0]
        assert "-C" in call_args
        assert "myprof" in call_args

    @pytest.mark.asyncio
    async def test_apply_profile_not_found(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "empty_profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["apply_profile_capture"].fn
            result = await tool_fn(filepath=str(pcap), profile_name="nonexistent")

        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_apply_tshark_failure(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        profile_dir = tmp_path / "profiles" / "failprof"
        profile_dir.mkdir(parents=True)

        mock_tshark._run = AsyncMock(
            return_value=TsharkResult(returncode=1, stdout="", stderr="tshark error")
        )

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["apply_profile_capture"].fn
            result = await tool_fn(filepath=str(pcap), profile_name="failprof")

        assert result["isError"] is True


class TestGetColorFilters:
    @pytest.mark.asyncio
    async def test_get_from_profile(self, mock_tshark, fmt, sec, tmp_path):
        profile_dir = tmp_path / "profiles" / "colorful"
        profile_dir.mkdir(parents=True)
        (profile_dir / "colorfilters").write_text(
            "@HTTP@http@[0,0,0][128,255,128]\n"
            "@DNS@dns@[0,0,128][200,200,255]\n"
        )

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["get_color_filters"].fn
            result = await tool_fn(profile_name="colorful")

        assert result["isError"] is False
        data = _parse_result_json(result)
        assert data["profile"] == "colorful"
        assert data["filter_count"] == 2
        assert data["filters"][0]["name"] == "HTTP"
        assert data["filters"][1]["background_rgb"] == [200, 200, 255]

    @pytest.mark.asyncio
    async def test_get_default(self, mock_tshark, fmt, sec, tmp_path):
        default_dir = tmp_path / "wireshark_config"
        default_dir.mkdir()
        (default_dir / "colorfilters").write_text("@TCP@tcp@[0,0,0][255,255,255]\n")

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._default_config_dir",
            return_value=default_dir,
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["get_color_filters"].fn
            result = await tool_fn(profile_name="")

        assert result["isError"] is False
        data = _parse_result_json(result)
        assert data["profile"] == "default"
        assert data["filter_count"] == 1

    @pytest.mark.asyncio
    async def test_colorfilters_not_found(self, mock_tshark, fmt, sec, tmp_path):
        profile_dir = tmp_path / "profiles" / "empty"
        profile_dir.mkdir(parents=True)

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["get_color_filters"].fn
            result = await tool_fn(profile_name="empty")

        assert result["isError"] is True
        assert "not found" in result["content"][0]["text"].lower()

    @pytest.mark.asyncio
    async def test_no_default_config(self, mock_tshark, fmt, sec):
        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._default_config_dir",
            return_value=None,
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["get_color_filters"].fn
            result = await tool_fn(profile_name="")

        assert result["isError"] is True


class TestCaptureWithProfile:
    @pytest.mark.asyncio
    async def test_capture_success(self, mock_tshark, fmt, sec, tmp_path):
        profile_dir = tmp_path / "profiles" / "capprof"
        profile_dir.mkdir(parents=True)

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["capture_with_profile"].fn
            result = await tool_fn(
                interface="eth0", profile_name="capprof", duration=5, packet_count=100
            )

        assert result["isError"] is False
        data = _parse_result_json(result)
        assert data["interface"] == "eth0"
        assert data["profile"] == "capprof"
        assert data["packets_captured"] == 1

        # Should have been called twice: capture and read
        assert mock_tshark._run.call_count == 2
        capture_args = mock_tshark._run.call_args_list[0][0][0]
        assert "-C" in capture_args
        assert "-i" in capture_args
        assert "eth0" in capture_args

    @pytest.mark.asyncio
    async def test_capture_profile_not_found(self, mock_tshark, fmt, sec, tmp_path):
        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "no_profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["capture_with_profile"].fn
            result = await tool_fn(interface="eth0", profile_name="ghost")

        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_capture_tshark_failure(self, mock_tshark, fmt, sec, tmp_path):
        profile_dir = tmp_path / "profiles" / "failcap"
        profile_dir.mkdir(parents=True)

        mock_tshark._run = AsyncMock(
            return_value=TsharkResult(returncode=1, stdout="", stderr="capture error")
        )

        mcp = FastMCP("test")
        with patch(
            "netmcp.tools.profiles._profile_search_dirs",
            return_value=[tmp_path / "profiles"],
        ):
            register_profile_tools(mcp, mock_tshark, fmt, sec)
            tool_fn = mcp._tool_manager._tools["capture_with_profile"].fn
            result = await tool_fn(interface="eth0", profile_name="failcap")

        assert result["isError"] is True
