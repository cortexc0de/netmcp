"""Tests for MCP resources."""

import asyncio
from unittest.mock import MagicMock

import pytest

from netmcp.core.formatter import OutputFormatter
from netmcp.core.history import CaptureHistory
from netmcp.resources import register_resources


@pytest.fixture
def mcp():
    """Create a mock MCP server that captures resource registrations."""
    mock = MagicMock()
    mock._resources = {}

    def resource_decorator(uri):
        def wrapper(fn):
            mock._resources[uri] = fn
            return fn
        return wrapper

    mock.resource = resource_decorator
    return mock


@pytest.fixture
def fmt():
    return OutputFormatter()


@pytest.fixture
def tshark():
    mock = MagicMock()
    mock.tshark_path = "/usr/bin/tshark"
    return mock


@pytest.fixture
def nmap():
    mock = MagicMock()
    mock.available = True
    return mock


def _register(mcp, tshark, nmap, fmt, history=None):
    register_resources(mcp, tshark, nmap, fmt, history)
    return mcp._resources


class TestAnalysisHistoryEmpty:
    def test_analysis_history_empty(self, mcp, tshark, nmap, fmt):
        history = CaptureHistory()
        resources = _register(mcp, tshark, nmap, fmt, history)
        result = asyncio.get_event_loop().run_until_complete(
            resources["analysis://history"]()
        )
        assert result == "No analysis history yet."

    def test_analysis_history_none(self, mcp, tshark, nmap, fmt):
        resources = _register(mcp, tshark, nmap, fmt, history=None)
        result = asyncio.get_event_loop().run_until_complete(
            resources["analysis://history"]()
        )
        assert result == "History tracking not enabled."


class TestAnalysisHistoryWithEntries:
    def test_analysis_history_with_entries(self, mcp, tshark, nmap, fmt):
        history = CaptureHistory()
        history.add("analyze_pcap", "/data/test.pcap", "100 packets", duration=2.5)
        history.add("scan_network", "192.168.1.0/24", "3 hosts found")

        resources = _register(mcp, tshark, nmap, fmt, history)
        result = asyncio.get_event_loop().run_until_complete(
            resources["analysis://history"]()
        )

        assert "# Analysis History" in result
        assert "analyze_pcap" in result
        assert "/data/test.pcap" in result
        assert "100 packets" in result
        assert "Duration: 2.5s" in result
        assert "scan_network" in result
        assert "192.168.1.0/24" in result
        assert "3 hosts found" in result


class TestNetworkHelpResource:
    def test_network_help_resource(self, mcp, tshark, nmap, fmt):
        resources = _register(mcp, tshark, nmap, fmt)
        result = asyncio.get_event_loop().run_until_complete(
            resources["network://help"]()
        )

        assert "# NetMCP" in result
        assert "Quick Start" in result
        assert "analyze_pcap" in result
        assert "quick_capture" in result
        assert "scan_network" in result
        assert "Tool Categories" in result
        assert "Capture & Analysis" in result
        assert "Security" in result
        assert "Resources" in result
        assert "analysis://history" in result
        assert "network://help" in result
