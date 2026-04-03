"""Security regression tests for NetMCP fixes."""

import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netmcp.core.security import SecurityValidator
from netmcp.interfaces.threat_intel import CACHE_MAX_SIZE, CacheEntry, ThreatIntelInterface


@pytest.fixture
def validator():
    return SecurityValidator()


# ── Helpers ─────────────────────────────────────────────────────────────


def _make_mcp_capture(tshark, sec=None):
    """Register capture tools on a fresh FastMCP and return it."""
    from mcp.server.fastmcp import FastMCP

    from netmcp.core.formatter import OutputFormatter
    from netmcp.tools.capture import register_capture_tools

    mcp = FastMCP("test")
    register_capture_tools(mcp, tshark, OutputFormatter(), sec or SecurityValidator())
    return mcp


def _make_mcp_analysis(tshark, sec=None):
    """Register analysis tools on a fresh FastMCP and return it."""
    from mcp.server.fastmcp import FastMCP

    from netmcp.core.formatter import OutputFormatter
    from netmcp.tools.analysis import register_analysis_tools

    mcp = FastMCP("test")
    register_analysis_tools(mcp, tshark, OutputFormatter(), sec or SecurityValidator())
    return mcp


def _tool_text(result) -> str:
    """Extract text from an MCP tool result (dict with 'content' list)."""
    if isinstance(result, dict):
        content = result.get("content", [])
        return content[0]["text"] if content else str(result)
    # Fallback for list-style result
    return result[0].text if hasattr(result[0], "text") else str(result[0])


# ── CRITICAL-01: save_capture_to_file rejects path traversal ───────────


class TestSaveCapturePathValidation:
    """Tests for CRITICAL-01 fix: arbitrary file write prevention."""

    @pytest.mark.asyncio
    async def test_reject_path_traversal(self, tmp_path):
        """output_file with '..' in path parts is rejected with ValueError."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "src.pcap"
            pcap.write_bytes(b"fake pcap data")
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_capture(tshark)

            result = await mcp._tool_manager.call_tool(
                "save_capture_to_file",
                {"interface": "eth0", "output_file": "../../etc/evil.pcap"},
            )
            text = _tool_text(result)
            assert "Path traversal" in text

    @pytest.mark.asyncio
    async def test_reject_invalid_extensions(self, tmp_path):
        """output_file with .txt, .sh, .py extensions is rejected."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "src.pcap"
            pcap.write_bytes(b"fake pcap data")
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_capture(tshark)

            for bad_ext in [".txt", ".sh", ".py"]:
                result = await mcp._tool_manager.call_tool(
                    "save_capture_to_file",
                    {"interface": "eth0", "output_file": str(tmp_path / f"out{bad_ext}")},
                )
                text = _tool_text(result)
                assert "extension" in text.lower(), f"{bad_ext} not rejected: {text}"

    @pytest.mark.asyncio
    async def test_accept_valid_extensions(self, tmp_path):
        """output_file with .pcap, .pcapng, .cap extensions is accepted."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "src.pcap"
            pcap.write_bytes(b"fake pcap data" * 10)
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_capture(tshark)

            for ext in [".pcap", ".pcapng", ".cap"]:
                result = await mcp._tool_manager.call_tool(
                    "save_capture_to_file",
                    {"interface": "eth0", "output_file": str(tmp_path / f"out{ext}")},
                )
                text = _tool_text(result)
                assert "Invalid output extension" not in text, f"{ext} wrongly rejected"


# ── CRITICAL-02: capture_targeted_traffic rejects invalid protocols ─────


class TestProtocolWhitelist:
    """Tests for CRITICAL-02 fix: protocol injection prevention."""

    @pytest.mark.asyncio
    async def test_tcp_accepted(self, tmp_path):
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "c.pcap"
            pcap.write_bytes(b"fake")
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_analysis(tshark)
            result = await mcp._tool_manager.call_tool(
                "capture_targeted_traffic", {"interface": "eth0", "protocol": "tcp"}
            )
            assert "Invalid protocol" not in _tool_text(result)

    @pytest.mark.asyncio
    async def test_udp_accepted(self, tmp_path):
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "c.pcap"
            pcap.write_bytes(b"fake")
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_analysis(tshark)
            result = await mcp._tool_manager.call_tool(
                "capture_targeted_traffic", {"interface": "eth0", "protocol": "udp"}
            )
            assert "Invalid protocol" not in _tool_text(result)

    @pytest.mark.asyncio
    async def test_icmp_accepted(self, tmp_path):
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "c.pcap"
            pcap.write_bytes(b"fake")
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_analysis(tshark)
            result = await mcp._tool_manager.call_tool(
                "capture_targeted_traffic", {"interface": "eth0", "protocol": "icmp"}
            )
            assert "Invalid protocol" not in _tool_text(result)

    @pytest.mark.asyncio
    async def test_http_accepted(self, tmp_path):
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            pcap = tmp_path / "c.pcap"
            pcap.write_bytes(b"fake")
            tshark.capture_live = AsyncMock(return_value=pcap)
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_analysis(tshark)
            result = await mcp._tool_manager.call_tool(
                "capture_targeted_traffic", {"interface": "eth0", "protocol": "http"}
            )
            assert "Invalid protocol" not in _tool_text(result)

    @pytest.mark.asyncio
    async def test_evil_injection_rejected(self):
        """protocol='evil_injection' raises ValueError."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            tshark.capture_live = AsyncMock(return_value=Path("/dev/null"))
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_analysis(tshark)
            result = await mcp._tool_manager.call_tool(
                "capture_targeted_traffic",
                {"interface": "eth0", "protocol": "evil_injection"},
            )
            assert "Invalid protocol" in _tool_text(result)

    @pytest.mark.asyncio
    async def test_injection_with_spaces_rejected(self):
        """protocol='tcp or host attacker.com' raises ValueError."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            tshark.capture_live = AsyncMock(return_value=Path("/dev/null"))
            tshark.read_pcap = AsyncMock(return_value=[])

            mcp = _make_mcp_analysis(tshark)
            result = await mcp._tool_manager.call_tool(
                "capture_targeted_traffic",
                {"interface": "eth0", "protocol": "tcp or host attacker.com"},
            )
            text = _tool_text(result)
            assert "Invalid protocol" in text or "error" in text.lower()


# ── CRITICAL-03: follow_stream validates proto and fmt ──────────────────


class TestFollowStreamValidation:
    """Tests for CRITICAL-03 fix: proto/fmt validation."""

    @pytest.mark.asyncio
    async def test_tcp_ascii_works(self):
        """proto='tcp', fmt='ascii' works."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            tshark._run = AsyncMock(
                return_value=MagicMock(returncode=0, stdout="stream data", stderr="")
            )
            result = await tshark.follow_stream("/f.pcap", 0, proto="tcp", fmt="ascii")
            assert result == "stream data"

    @pytest.mark.asyncio
    async def test_udp_hex_works(self):
        """proto='udp', fmt='hex' works."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            tshark._run = AsyncMock(
                return_value=MagicMock(returncode=0, stdout="hex data", stderr="")
            )
            result = await tshark.follow_stream("/f.pcap", 0, proto="udp", fmt="hex")
            assert result == "hex data"

    @pytest.mark.asyncio
    async def test_invalid_proto_raises(self):
        """proto='invalid' raises ValueError."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            with pytest.raises(ValueError, match="Invalid protocol"):
                await tshark.follow_stream("/f.pcap", 0, proto="invalid")

    @pytest.mark.asyncio
    async def test_invalid_fmt_raises(self):
        """fmt='invalid' raises ValueError."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            with pytest.raises(ValueError, match="Invalid format"):
                await tshark.follow_stream("/f.pcap", 0, proto="tcp", fmt="invalid")

    @pytest.mark.asyncio
    async def test_injection_in_proto_raises(self):
        """proto='tcp,ascii,0 -w /tmp/evil' raises ValueError."""
        with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
            from netmcp.interfaces.tshark import TsharkInterface

            tshark = TsharkInterface()
            with pytest.raises(ValueError, match="Invalid protocol"):
                await tshark.follow_stream(
                    "/f.pcap", 0, proto="tcp,ascii,0 -w /tmp/evil", fmt="ascii"
                )


# ── CRITICAL-04: nmap _run_scan doesn't scan twice ─────────────────────


class TestNmapSingleScan:
    """Tests for CRITICAL-04 fix: double scan elimination."""

    @pytest.mark.asyncio
    async def test_scanner_scan_called_once(self):
        """Mock nmap.PortScanner — scanner.scan() must be called exactly ONCE."""
        from netmcp.interfaces.nmap import NmapInterface

        mock_scanner = MagicMock()
        expected = {"scan": {"10.0.0.1": {"tcp": {80: {"state": "open"}}}}}
        mock_scanner.scan.return_value = expected

        nmap_iface = NmapInterface.__new__(NmapInterface)
        nmap_iface.available = True
        nmap_iface._scanner = mock_scanner
        nmap_iface._security = None

        await nmap_iface._run_scan("10.0.0.1", "-sT -T4", timeout=10.0)

        mock_scanner.scan.assert_called_once_with(hosts="10.0.0.1", arguments="-sT -T4")

    @pytest.mark.asyncio
    async def test_single_scan_result_returned(self):
        """The result from the single scan must be returned correctly."""
        from netmcp.interfaces.nmap import NmapInterface

        mock_scanner = MagicMock()
        expected = {"scan": {"10.0.0.1": {"tcp": {22: {"state": "open"}}}}}
        mock_scanner.scan.return_value = expected

        nmap_iface = NmapInterface.__new__(NmapInterface)
        nmap_iface.available = True
        nmap_iface._scanner = mock_scanner
        nmap_iface._security = None

        result = await nmap_iface._run_scan("10.0.0.1", "-F -T4", timeout=10.0)
        assert result == expected


# ── SEC-01: Rate limiting is enforced ───────────────────────────────────


class TestRateLimiting:
    """Tests for SEC-01 fix: rate limiting enforcement."""

    def test_nmap_blocked_after_10(self, validator):
        """Nmap tools return error after 10 calls."""
        for _ in range(10):
            assert validator.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600) is True
        assert validator.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600) is False

    def test_capture_blocked_after_30(self, validator):
        """Capture tools return error after 30 calls."""
        for _ in range(30):
            assert (
                validator.check_rate_limit("live_capture", max_ops=30, window_seconds=3600) is True
            )
        assert (
            validator.check_rate_limit("live_capture", max_ops=30, window_seconds=3600) is False
        )

    def test_threat_intel_blocked_after_100(self, validator):
        """Threat intel returns error after 100 calls."""
        for _ in range(100):
            assert (
                validator.check_rate_limit("threat_intel", max_ops=100, window_seconds=3600) is True
            )
        assert (
            validator.check_rate_limit("threat_intel", max_ops=100, window_seconds=3600) is False
        )

    def test_different_operations_independent(self, validator):
        """Exhausting one operation's limit must not affect another."""
        for _ in range(10):
            validator.check_rate_limit("nmap_scan", max_ops=10)
        assert validator.check_rate_limit("nmap_scan", max_ops=10) is False
        assert validator.check_rate_limit("live_capture", max_ops=30) is True
        assert validator.check_rate_limit("threat_intel", max_ops=100) is True


# ── SEC-05: GeoIP reader is thread-safe ─────────────────────────────────


class TestGeoIPThreadSafety:
    """Tests for SEC-05 fix: thread-safe singleton."""

    def test_concurrent_get_reader_10_threads(self):
        """_get_reader() called from 10 threads simultaneously without error."""
        from netmcp.utils.geoip import _get_reader

        results = []
        errors = []

        def call_reader():
            try:
                r = _get_reader()
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=call_reader) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Errors in concurrent _get_reader: {errors}"
        assert len(results) == 10
        # All threads must return the same singleton (or all None if unavailable)
        unique = {id(r) for r in results}
        assert len(unique) == 1, "All threads should get the same reader instance"


# ── SEC-04: Threat intel cache has bounded size ─────────────────────────


class TestThreatCacheBounds:
    """Tests for SEC-04 fix: bounded cache."""

    def test_cache_does_not_exceed_max_size(self):
        """Cache must not grow beyond CACHE_MAX_SIZE."""
        ti = ThreatIntelInterface()

        # Fill cache to the limit
        now = time.monotonic()
        for i in range(CACHE_MAX_SIZE):
            ti._cache[f"key:{i}"] = CacheEntry(data={"test": True}, timestamp=now + i)
        assert len(ti._cache) == CACHE_MAX_SIZE

        # Adding one more via _set_cache triggers eviction
        ti._set_cache("overflow_key", {"overflow": True})
        assert len(ti._cache) <= CACHE_MAX_SIZE
        assert "overflow_key" in ti._cache

    def test_old_entries_evicted(self):
        """Oldest entries must be evicted when limit is reached."""
        ti = ThreatIntelInterface()

        now = time.monotonic()
        for i in range(CACHE_MAX_SIZE):
            ti._cache[f"key:{i}"] = CacheEntry(data=i, timestamp=now + i)

        # Trigger eviction
        ti._set_cache("new_key", {"new": True})

        # Oldest 25% should be gone
        eviction_count = CACHE_MAX_SIZE // 4
        for i in range(eviction_count):
            assert f"key:{i}" not in ti._cache, f"Old entry key:{i} should have been evicted"

        # Newest entries and new key survive
        assert f"key:{CACHE_MAX_SIZE - 1}" in ti._cache
        assert "new_key" in ti._cache
