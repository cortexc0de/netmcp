"""Targeted tests for uncovered lines in tools/threat_intel.py."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.tools.threat_intel import register_threat_tools


@pytest.fixture
def fmt():
    return OutputFormatter()


@pytest.fixture
def sec():
    return SecurityValidator()


async def call(mcp, name, **kwargs):
    return await mcp._tool_manager.call_tool(name, kwargs)


class TestThreatToolRateLimits:
    @pytest.mark.asyncio
    async def test_check_ip_rate_limit(self, fmt, sec):
        """Line 44: rate limit exceeded for check_ip_threat_intel."""
        mock_tshark = MagicMock()
        mock_threat = MagicMock()
        mock_threat.check_ip = AsyncMock()
        mcp = FastMCP("test")
        register_threat_tools(mcp, mock_tshark, mock_threat, fmt, sec)
        with patch.object(sec, "check_rate_limit", return_value=False):
            result = await call(mcp, "check_ip_threat_intel", ip_address="10.0.0.1")
            assert result["isError"] is True
            assert "Rate limit" in str(result)

    @pytest.mark.asyncio
    async def test_scan_capture_rate_limit(self, fmt, sec):
        """Line 75: rate limit exceeded for scan_capture_for_threats."""
        mock_tshark = MagicMock()
        mock_threat = MagicMock()
        mock_threat.scan_pcap = AsyncMock()
        mcp = FastMCP("test")
        register_threat_tools(mcp, mock_tshark, mock_threat, fmt, sec)
        with (
            patch.object(sec, "sanitize_filepath", return_value=Path("/test.pcap")),
            patch.object(sec, "check_rate_limit", return_value=False),
        ):
            result = await call(mcp, "scan_capture_for_threats", filepath="/test.pcap")
            assert result["isError"] is True
            assert "Rate limit" in str(result)


class TestThreatToolErrors:
    @pytest.mark.asyncio
    async def test_check_ip_exception(self, fmt, sec):
        """Lines 49-50: exception in check_ip_threat_intel."""
        mock_tshark = MagicMock()
        mock_threat = MagicMock()
        mock_threat.check_ip = AsyncMock(side_effect=RuntimeError("connection failed"))
        mcp = FastMCP("test")
        register_threat_tools(mcp, mock_tshark, mock_threat, fmt, sec)
        result = await call(mcp, "check_ip_threat_intel", ip_address="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_scan_capture_exception(self, fmt, sec):
        """Lines 80-81: exception in scan_capture_for_threats."""
        mock_tshark = MagicMock()
        mock_threat = MagicMock()
        mock_threat.scan_pcap = AsyncMock(side_effect=RuntimeError("scan failed"))
        mcp = FastMCP("test")
        register_threat_tools(mcp, mock_tshark, mock_threat, fmt, sec)
        with patch.object(sec, "sanitize_filepath", return_value=Path("/test.pcap")):
            result = await call(mcp, "scan_capture_for_threats", filepath="/test.pcap")
            assert result["isError"] is True
