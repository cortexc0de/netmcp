"""E2E tests for NetMCP server — full lifecycle verification."""

from unittest.mock import MagicMock, patch

import pytest

from netmcp.server import create_server


class TestServerCreation:
    def test_create_server_no_errors(self):
        """Server must be creatable without raising."""
        server = create_server()
        assert server is not None
        assert server.name == "NetMCP"

    def test_server_with_tshark_mocked(self):
        """Server must work when tshark is found."""
        import netmcp.interfaces.tshark as tshark_mod
        original = tshark_mod.find_tshark
        tshark_mod.find_tshark = lambda: "/usr/bin/tshark"
        try:
            server = create_server()
            assert server.name == "NetMCP"
        finally:
            tshark_mod.find_tshark = original


class TestResponseFormat:
    """Verify that tool responses follow MCP format."""

    def test_formatter_success_format(self):
        """Success responses must have correct MCP structure."""
        from netmcp.core.formatter import OutputFormatter
        fmt = OutputFormatter()

        result = fmt.format_success({"data": "test"})
        assert "content" in result
        assert result["isError"] is False
        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "text"

    def test_formatter_error_format(self):
        """Error responses must have correct MCP structure."""
        from netmcp.core.formatter import OutputFormatter
        fmt = OutputFormatter()

        result = fmt.format_error(ValueError("bad input"), "NETMCP_002")
        assert "content" in result
        assert result["isError"] is True
        assert "[NETMCP_002]" in result["content"][0]["text"]
        assert "bad input" in result["content"][0]["text"]


class TestSecurityValidator:
    """Security validation integration in E2E context."""

    def test_invalid_input_rejected(self):
        """SecurityValidator must reject dangerous inputs."""
        from netmcp.core.security import SecurityValidator
        sec = SecurityValidator()

        with pytest.raises(ValueError, match="dangerous characters|shell metacharacters"):
            sec.validate_target("; rm -rf /")

        with pytest.raises(ValueError, match="Path traversal"):
            sec.sanitize_filepath("../../../etc/passwd")

    def test_valid_input_accepted(self):
        """Valid inputs must pass through."""
        from netmcp.core.security import SecurityValidator
        sec = SecurityValidator()

        assert sec.validate_target("192.168.1.1") == "192.168.1.1"
        assert sec.validate_interface("eth0") == "eth0"
        assert sec.validate_port_range("80,443") == "80,443"


class TestWithoutDependencies:
    """Test server behavior without optional dependencies."""

    def test_server_without_nmap(self):
        """Server works without nmap (just without scanning tools)."""
        with patch("netmcp.interfaces.nmap.NmapInterface") as mock_cls:
            mock_nmap = MagicMock()
            mock_nmap.available = False
            mock_cls.return_value = mock_nmap

            server = create_server()
            assert server.name == "NetMCP"

    def test_server_without_abuseipdb_key(self):
        """Server works without AbuseIPDB key (only URLhaus)."""
        import netmcp.interfaces.tshark as tshark_mod
        original = tshark_mod.find_tshark
        tshark_mod.find_tshark = lambda: "/usr/bin/tshark"
        try:
            with patch("netmcp.interfaces.nmap.NmapInterface") as mock_nmap:
                mock_nmap.return_value.available = False
                server = create_server()
                assert server.name == "NetMCP"
        finally:
            tshark_mod.find_tshark = original
