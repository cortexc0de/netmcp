"""Comprehensive integration tests to achieve 80%+ coverage."""

import logging
import re
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import ErrorCode, OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def fmt():
    return OutputFormatter()


@pytest.fixture
def sec():
    return SecurityValidator()


@pytest.fixture
def mock_tshark():
    with patch("netmcp.interfaces.tshark.find_tshark", return_value="/usr/bin/tshark"):
        tshark = TsharkInterface()
        tshark.list_interfaces = AsyncMock(return_value=["eth0", "lo"])
        tshark.capture_live = AsyncMock(return_value=Path("/tmp/test.pcap"))
        tshark.read_pcap = AsyncMock(
            return_value=[
                {
                    "_source": {
                        "layers": {
                            "ip.src": ["10.0.0.1"],
                            "ip.dst": ["10.0.0.2"],
                            "frame.number": ["1"],
                            "frame.protocols": ["eth:ethertype:ip:tcp:http"],
                            "frame.len": ["100"],
                        }
                    }
                }
            ]
        )
        tshark.protocol_stats = AsyncMock(
            return_value={
                "tcp": {"frames": 100, "bytes": 12000},
                "udp": {"frames": 50, "bytes": 6000},
            }
        )
        tshark.follow_stream = AsyncMock(return_value="GET / HTTP/1.1\r\nHost: example.com\r\n")
        tshark.list_streams = AsyncMock(
            return_value=[{"endpoint_a": "192.168.1.1:443", "endpoint_b": "10.0.0.1:54321"}]
        )
        tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "http.request.method": "GET",
                    "http.host": "example.com",
                    "http.request.uri": "/api",
                    "http.response.code": "200",
                    "http.user_agent": "Mozilla/5.0",
                    "http.authorization": "Bearer eyJ...",
                    "http.cookie": "session=abc",
                    "http.x_forwarded_for": "",
                    "frame.number": "1",
                },
            ]
        )
        tshark.export_json = AsyncMock(return_value=[{"_source": {"layers": {}}}])
        tshark.file_info = AsyncMock(
            return_value={"filepath": "/tmp/test.pcap", "total_frames": "150"}
        )
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        tshark.convert_format = AsyncMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )
        yield tshark


async def call(mcp: FastMCP, name: str, **kwargs):
    """Helper to call a registered tool by name."""
    return await mcp._tool_manager.call_tool(name, kwargs)


# ── Credential extraction tests ───────────────────────────────────────


class TestCredentialExtraction:
    """Test extract_credentials tool with various credential types."""

    @pytest.mark.asyncio
    async def test_http_basic_auth_extraction(self, mock_tshark, fmt, sec, tmp_path):
        """HTTP Basic Auth credentials decoded from base64."""
        pcap = tmp_path / "creds.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        # base64("admin:password123") = "YWRtaW46cGFzc3dvcmQxMjM="
        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [
                    {
                        "http.authbasic": "YWRtaW46cGFzc3dvcmQxMjM=",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "telnet.data": "",
                        "frame.number": "1",
                    }
                ],
                [],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "admin" in text
        assert "password123" in text

    @pytest.mark.asyncio
    async def test_http_basic_auth_invalid_base64(self, mock_tshark, fmt, sec, tmp_path):
        """Invalid base64 in auth header is skipped gracefully."""
        pcap = tmp_path / "bad_auth.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [
                    {
                        "http.authbasic": "not-valid-base64!!!",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "telnet.data": "",
                        "frame.number": "1",
                    }
                ],
                [],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_ftp_user_pass_paired(self, mock_tshark, fmt, sec, tmp_path):
        """FTP USER/PASS commands paired correctly."""
        pcap = tmp_path / "ftp.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [
                    {
                        "ftp.request.command": "USER",
                        "ftp.request.arg": "admin",
                        "http.authbasic": "",
                        "telnet.data": "",
                        "frame.number": "1",
                    },
                    {
                        "ftp.request.command": "PASS",
                        "ftp.request.arg": "secret123",
                        "http.authbasic": "",
                        "telnet.data": "",
                        "frame.number": "2",
                    },
                ],
                [],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "admin" in text
        assert "secret123" in text

    @pytest.mark.asyncio
    async def test_ftp_user_without_pass(self, mock_tshark, fmt, sec, tmp_path):
        """FTP USER without PASS still records username."""
        pcap = tmp_path / "ftp_nopass.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [
                    {
                        "ftp.request.command": "USER",
                        "ftp.request.arg": "anonymous",
                        "http.authbasic": "",
                        "telnet.data": "",
                        "frame.number": "1",
                    },
                ],
                [],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "anonymous" in text

    @pytest.mark.asyncio
    async def test_telnet_login_password_prompts(self, mock_tshark, fmt, sec, tmp_path):
        """Telnet login prompts and responses detected."""
        pcap = tmp_path / "telnet.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [
                    {
                        "telnet.data": "login: ",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "http.authbasic": "",
                        "frame.number": "1",
                    },
                    {
                        "telnet.data": "admin",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "http.authbasic": "",
                        "frame.number": "2",
                    },
                    {
                        "telnet.data": "password: ",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "http.authbasic": "",
                        "frame.number": "3",
                    },
                    {
                        "telnet.data": "secret",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "http.authbasic": "",
                        "frame.number": "4",
                    },
                ],
                [],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Telnet" in text

    @pytest.mark.asyncio
    async def test_kerberos_as_rep_hash(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos AS-REP hashes extracted with hashcat -m 18200."""
        pcap = tmp_path / "krb.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],
                [
                    {
                        "kerberos.CNameString": "jdoe",
                        "kerberos.realm": "CORP.LOCAL",
                        "kerberos.cipher": "abc123cipher",
                        "kerberos.type": "",
                        "kerberos.msg_type": "11",
                        "frame.number": "5",
                    }
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Kerberos" in text
        assert "18200" in text
        assert "jdoe" in text

    @pytest.mark.asyncio
    async def test_kerberos_as_req_hash(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos AS-REQ hashes extracted with hashcat -m 7500."""
        pcap = tmp_path / "krb_req.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],
                [
                    {
                        "kerberos.CNameString": "admin",
                        "kerberos.realm": "DOMAIN.COM",
                        "kerberos.cipher": "deadbeef",
                        "kerberos.type": "",
                        "kerberos.msg_type": "10",
                        "frame.number": "3",
                    }
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "7500" in text

    @pytest.mark.asyncio
    async def test_kerberos_tgs_req_hash(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos TGS-REQ (msg_type 30) also uses hashcat -m 7500."""
        pcap = tmp_path / "krb_tgs.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],
                [
                    {
                        "kerberos.CNameString": "svc",
                        "kerberos.realm": "REALM",
                        "kerberos.cipher": "cafebabe",
                        "kerberos.type": "",
                        "kerberos.msg_type": "30",
                        "frame.number": "7",
                    }
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "7500" in text

    @pytest.mark.asyncio
    async def test_kerberos_unknown_msg_type_skipped(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos rows with unknown msg_type produce no hash."""
        pcap = tmp_path / "krb_unk.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],
                [
                    {
                        "kerberos.CNameString": "user",
                        "kerberos.realm": "X",
                        "kerberos.cipher": "xyz",
                        "kerberos.type": "",
                        "kerberos.msg_type": "99",
                        "frame.number": "1",
                    }
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert '"encrypted_count": 0' in text

    @pytest.mark.asyncio
    async def test_kerberos_no_cipher_skipped(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos rows without cipher are skipped."""
        pcap = tmp_path / "krb_nocipher.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],
                [
                    {
                        "kerberos.CNameString": "user",
                        "kerberos.realm": "X",
                        "kerberos.cipher": "",
                        "kerberos.type": "",
                        "kerberos.msg_type": "11",
                        "frame.number": "1",
                    }
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert '"encrypted_count": 0' in text

    @pytest.mark.asyncio
    async def test_empty_credentials(self, mock_tshark, fmt, sec, tmp_path):
        """No credentials found returns zero counts."""
        pcap = tmp_path / "empty.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [
                    {
                        "http.authbasic": "",
                        "ftp.request.command": "",
                        "ftp.request.arg": "",
                        "telnet.data": "",
                        "frame.number": "1",
                    }
                ],
                [],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert '"plaintext_count": 0' in text
        assert '"encrypted_count": 0' in text

    @pytest.mark.asyncio
    async def test_credential_extraction_error(self, mock_tshark, fmt, sec, tmp_path):
        """Error during extraction returns formatted error."""
        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath="/nonexistent/file.pcap")
        assert result["isError"] is True


# ── Security validator tests ──────────────────────────────────────────


class TestNmapFlagsValidation:
    """Test nmap argument validation."""

    def test_allowed_flags(self, sec):
        assert sec.validate_nmap_arguments("-sT -T4") == "-sT -T4"
        assert sec.validate_nmap_arguments("-sS -T4 -p 80,443") == "-sS -T4 -p 80,443"
        assert sec.validate_nmap_arguments("-sV -T4") == "-sV -T4"
        assert sec.validate_nmap_arguments("-F -T4") == "-F -T4"
        assert sec.validate_nmap_arguments("") == ""
        assert sec.validate_nmap_arguments("-O --osscan-guess") == "-O --osscan-guess"

    def test_script_allowed_categories(self, sec):
        assert sec.validate_nmap_arguments("--script=vuln") == "--script=vuln"
        assert sec.validate_nmap_arguments("--script=default") == "--script=default"
        assert sec.validate_nmap_arguments("--script=safe") == "--script=safe"

    def test_script_disallowed_category(self, sec):
        with pytest.raises(ValueError, match="not in allowed"):
            sec.validate_nmap_arguments("--script=exploit")

    def test_dangerous_flags_rejected(self, sec):
        with pytest.raises(ValueError, match="Dangerous"):
            sec.validate_nmap_arguments("--script-args 'user=admin'")
        with pytest.raises(ValueError, match="Dangerous"):
            sec.validate_nmap_arguments("--interactive")
        with pytest.raises(ValueError, match="Dangerous"):
            sec.validate_nmap_arguments("--packet-trace")
        with pytest.raises(ValueError, match="Dangerous"):
            sec.validate_nmap_arguments("--privileged")

    def test_unknown_flags_rejected(self, sec):
        with pytest.raises(ValueError, match="not in allowed"):
            sec.validate_nmap_arguments("--some-random-flag")
        with pytest.raises(ValueError, match="not in allowed"):
            sec.validate_nmap_arguments("-X")

    def test_port_spec_flag_allowed(self, sec):
        assert sec.validate_nmap_arguments("-p 1-1024") == "-p 1-1024"

    def test_malformed_arguments(self, sec):
        with pytest.raises(ValueError, match="Malformed"):
            sec.validate_nmap_arguments("--flag 'unterminated")

    def test_non_flag_tokens_skipped(self, sec):
        assert sec.validate_nmap_arguments("-sT 10.0.0.1") == "-sT 10.0.0.1"

    def test_script_without_value(self, sec):
        result = sec.validate_nmap_arguments("--script vuln")
        assert result == "--script vuln"


class TestSymlinkRejection:
    """Test that symlinks are rejected in sanitize_filepath."""

    def test_symlink_rejected(self, sec, tmp_path):
        target = tmp_path / "real.pcap"
        target.write_bytes(b"fake pcap data")
        link = tmp_path / "link.pcap"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="Symbolic links"):
            sec.sanitize_filepath(str(link))

    def test_regular_file_accepted(self, sec, tmp_path):
        f = tmp_path / "normal.pcap"
        f.write_bytes(b"fake pcap data")
        result = sec.sanitize_filepath(str(f))
        assert result == f.resolve()


class TestAuditLogging:
    """Test audit logging functionality."""

    def test_audit_log_basic(self, sec, caplog):
        with caplog.at_level(logging.INFO, logger="netmcp.security"):
            sec.audit_log("test_operation", {"target": "10.0.0.1"})
        assert "AUDIT: test_operation" in caplog.text
        assert "10.0.0.1" in caplog.text

    def test_audit_log_filters_secrets(self, sec, caplog):
        with caplog.at_level(logging.INFO, logger="netmcp.security"):
            sec.audit_log(
                "test_op",
                {
                    "target": "10.0.0.1",
                    "password": "secret123",
                    "token": "abc",
                    "key": "apikey",
                    "secret": "shh",
                },
            )
        assert "secret123" not in caplog.text
        assert "abc" not in caplog.text
        assert "apikey" not in caplog.text
        assert "shh" not in caplog.text
        assert "10.0.0.1" in caplog.text

    def test_audit_log_no_details(self, sec, caplog):
        with caplog.at_level(logging.INFO, logger="netmcp.security"):
            sec.audit_log("simple_op")
        assert "AUDIT: simple_op" in caplog.text


class TestSecurityEdgeCases:
    """Test additional security validator branches."""

    def test_validate_interface_spaces(self, sec):
        with pytest.raises(ValueError, match="spaces"):
            sec.validate_interface("eth 0")

    def test_validate_target_cidr(self, sec):
        result = sec.validate_target("192.168.1.0/24")
        assert result == "192.168.1.0/24"

    def test_validate_target_hostname(self, sec):
        result = sec.validate_target("example.com")
        assert result == "example.com"

    def test_validate_target_invalid(self, sec):
        with pytest.raises(ValueError, match="dangerous characters"):
            sec.validate_target("not_a_valid!!target")

    def test_validate_target_invalid_hostname(self, sec):
        with pytest.raises(ValueError, match="not a valid IP"):
            sec.validate_target("not-a-valid-target-/bad")

    def test_validate_port_range_non_numeric(self, sec):
        with pytest.raises(ValueError, match="non-numeric"):
            sec.validate_port_range("abc")

    def test_validate_port_range_bad_range(self, sec):
        with pytest.raises(ValueError, match="non-numeric"):
            sec.validate_port_range("a-b")

    def test_sanitize_filepath_path_traversal(self, sec, tmp_path):
        with pytest.raises(ValueError, match="traversal"):
            sec.sanitize_filepath(str(tmp_path / ".." / "etc" / "passwd.pcap"))

    def test_sanitize_filepath_nonexistent(self, sec, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            sec.sanitize_filepath(str(tmp_path / "missing.pcap"))

    def test_sanitize_filepath_bad_extension(self, sec, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"data")
        with pytest.raises(ValueError, match="Invalid file extension"):
            sec.sanitize_filepath(str(f))


# ── Error codes tests ─────────────────────────────────────────────────


class TestErrorCodes:
    """Test standardized error codes."""

    def test_error_code_constants_exist(self):
        assert ErrorCode.INTERNAL == "NETMCP_001"
        assert ErrorCode.VALIDATION == "NETMCP_002"
        assert ErrorCode.TOOL_EXECUTION == "NETMCP_003"
        assert ErrorCode.FILE_ERROR == "NETMCP_004"
        assert ErrorCode.TIMEOUT == "NETMCP_005"
        assert ErrorCode.RATE_LIMITED == "NETMCP_006"
        assert ErrorCode.PERMISSION == "NETMCP_007"
        assert ErrorCode.NOT_AVAILABLE == "NETMCP_008"

    def test_format_error_maps_correctly(self, fmt):
        assert "[NETMCP_002]" in fmt.format_error(ValueError("bad"))["content"][0]["text"]
        assert (
            "[NETMCP_004]" in fmt.format_error(FileNotFoundError("missing"))["content"][0]["text"]
        )
        assert "[NETMCP_005]" in fmt.format_error(TimeoutError("slow"))["content"][0]["text"]
        assert "[NETMCP_007]" in fmt.format_error(PermissionError("denied"))["content"][0]["text"]
        assert (
            "[NETMCP_003]"
            in fmt.format_error(subprocess.CalledProcessError(1, "cmd"))["content"][0]["text"]
        )

    def test_format_error_unknown_exception(self, fmt):
        result = fmt.format_error(Exception("generic"))
        assert "[NETMCP_001]" in result["content"][0]["text"]

    def test_format_error_with_explicit_code(self, fmt):
        result = fmt.format_error(Exception("msg"), code="NETMCP_006")
        assert "[NETMCP_006]" in result["content"][0]["text"]


# ── Resources tests ───────────────────────────────────────────────────


class TestResources:
    """Test MCP resource registration and execution."""

    def test_resources_registered(self):
        from netmcp.server import create_server

        server = create_server()
        assert hasattr(server, "_resource_manager")

    def test_register_resources(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

    def test_get_interfaces_resource(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = True
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="1. eth0\n2. lo (Loopback)\n3. wlan0\n",
                stderr="",
            )
            resources = mcp._resource_manager._resources
            for uri, resource in resources.items():
                if "interfaces" in str(uri):
                    result = resource.fn()
                    assert "eth0" in result
                    assert "wlan0" in result
                    break

    def test_get_interfaces_tshark_not_found(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        with patch("subprocess.run", side_effect=FileNotFoundError):
            resources = mcp._resource_manager._resources
            for uri, resource in resources.items():
                if "interfaces" in str(uri):
                    result = resource.fn()
                    assert "not found" in result.lower() or "Error" in result
                    break

    def test_get_interfaces_timeout(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 10)):
            resources = mcp._resource_manager._resources
            for uri, resource in resources.items():
                if "interfaces" in str(uri):
                    result = resource.fn()
                    assert "timed out" in result.lower()
                    break

    def test_get_interfaces_returncode_error(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="permission denied")
            resources = mcp._resource_manager._resources
            for uri, resource in resources.items():
                if "interfaces" in str(uri):
                    result = resource.fn()
                    assert "Error" in result
                    break

    def test_get_captures_resource(self, mock_tshark, fmt, tmp_path):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        resources = mcp._resource_manager._resources
        for uri, resource in resources.items():
            if "captures" in str(uri):
                result = resource.fn()
                assert "count" in result
                break

    def test_get_system_info_resource(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = True
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        resources = mcp._resource_manager._resources
        for uri, resource in resources.items():
            if "system" in str(uri):
                result = resource.fn()
                assert "python_version" in result
                assert "tools" in result
                break

    def test_get_interfaces_generic_exception(self, mock_tshark, fmt):
        from netmcp.resources import register_resources

        nmap = MagicMock()
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)

        with patch("subprocess.run", side_effect=RuntimeError("something broke")):
            resources = mcp._resource_manager._resources
            for uri, resource in resources.items():
                if "interfaces" in str(uri):
                    result = resource.fn()
                    assert "Error" in result
                    break


# ── Nmap tool rate-limit + validation branches ────────────────────────


class TestNmapToolBranches:
    """Test nmap tool branches: not available, rate limit, invalid scan_type."""

    def _make_nmap_mcp(self, fmt, sec, available=True):
        from netmcp.tools.nmap_scan import register_nmap_tools

        mock_nmap = MagicMock()
        mock_nmap.available = available
        mock_nmap.port_scan = AsyncMock(return_value={"scan": {}})
        mock_nmap.service_detect = AsyncMock(return_value={"scan": {}})
        mock_nmap.os_detect = AsyncMock(return_value={"scan": {}})
        mock_nmap.vuln_scan = AsyncMock(return_value={"scan": {}})
        mock_nmap.quick_scan = AsyncMock(return_value={"scan": {}})
        mock_nmap.comprehensive_scan = AsyncMock(return_value={"scan": {}})
        mcp = FastMCP("test")
        register_nmap_tools(mcp, mock_nmap, fmt, sec)
        return mcp

    @pytest.mark.asyncio
    async def test_port_scan_not_available(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec, available=False)
        result = await call(
            mcp, "nmap_port_scan", target="10.0.0.1", ports="80", scan_type="connect"
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_port_scan_invalid_scan_type(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        result = await call(mcp, "nmap_port_scan", target="10.0.0.1", scan_type="invalid")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_port_scan_rate_limited(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        for _ in range(10):
            sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600)
        result = await call(mcp, "nmap_port_scan", target="10.0.0.1", scan_type="connect")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_service_detection_not_available(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec, available=False)
        result = await call(mcp, "nmap_service_detection", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_service_detection_rate_limited(self, fmt):
        sec = SecurityValidator()
        mcp = self._make_nmap_mcp(fmt, sec)
        for _ in range(10):
            sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600)
        result = await call(mcp, "nmap_service_detection", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_service_detection_with_ports(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        result = await call(mcp, "nmap_service_detection", target="10.0.0.1", ports="80,443")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_os_detection_not_available(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec, available=False)
        result = await call(mcp, "nmap_os_detection", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_os_detection_rate_limited(self, fmt):
        sec = SecurityValidator()
        mcp = self._make_nmap_mcp(fmt, sec)
        for _ in range(10):
            sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600)
        result = await call(mcp, "nmap_os_detection", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_vuln_scan_not_available(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec, available=False)
        result = await call(mcp, "nmap_vulnerability_scan", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_vuln_scan_rate_limited(self, fmt):
        sec = SecurityValidator()
        mcp = self._make_nmap_mcp(fmt, sec)
        for _ in range(10):
            sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600)
        result = await call(mcp, "nmap_vulnerability_scan", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_vuln_scan_with_ports(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        result = await call(mcp, "nmap_vulnerability_scan", target="10.0.0.1", ports="22,80")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_quick_scan_not_available(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec, available=False)
        result = await call(mcp, "nmap_quick_scan", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_quick_scan_rate_limited(self, fmt):
        sec = SecurityValidator()
        mcp = self._make_nmap_mcp(fmt, sec)
        for _ in range(10):
            sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600)
        result = await call(mcp, "nmap_quick_scan", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_comprehensive_not_available(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec, available=False)
        result = await call(mcp, "nmap_comprehensive_scan", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_comprehensive_rate_limited(self, fmt):
        sec = SecurityValidator()
        mcp = self._make_nmap_mcp(fmt, sec)
        for _ in range(10):
            sec.check_rate_limit("nmap_scan", max_ops=10, window_seconds=3600)
        result = await call(mcp, "nmap_comprehensive_scan", target="10.0.0.1")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_port_scan_with_ports_validation(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        result = await call(
            mcp, "nmap_port_scan", target="10.0.0.1", ports="1-1024", scan_type="connect"
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_port_scan_syn(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        result = await call(mcp, "nmap_port_scan", target="10.0.0.1", scan_type="syn")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_port_scan_udp(self, fmt, sec):
        mcp = self._make_nmap_mcp(fmt, sec)
        result = await call(mcp, "nmap_port_scan", target="10.0.0.1", scan_type="udp")
        assert result["isError"] is False


# ── Tshark field validation ───────────────────────────────────────────


class TestTsharkFieldValidation:
    """Test tshark field name validation in export."""

    def test_invalid_fields_rejected(self):
        tshark_field_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{0,127}$")
        bad_fields = ["$(whoami)", "; rm -rf", "field with spaces", "123invalid", ""]
        for field in bad_fields:
            assert not tshark_field_re.match(field), f"{field} should be rejected"

    def test_valid_fields_accepted(self):
        tshark_field_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{0,127}$")
        good_fields = ["http.host", "frame.number", "ip.src", "tcp.dstport"]
        for field in good_fields:
            assert tshark_field_re.match(field), f"{field} should be accepted"

    @pytest.mark.asyncio
    async def test_export_csv_invalid_field(self, mock_tshark, fmt, sec, tmp_path):
        """Fields with special characters rejected by export_packets_csv."""
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath=str(pcap), fields="$(whoami)")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_export_csv_valid_custom_fields(self, mock_tshark, fmt, sec, tmp_path):
        """Valid custom field names pass validation."""
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.export_fields = AsyncMock(
            return_value=[{"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"}]
        )

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath=str(pcap), fields="ip.src,ip.dst")
        assert result["isError"] is False


# ── Formatter extended tests ──────────────────────────────────────────


class TestFormatterExtended:
    """Test formatter edge cases for coverage."""

    def test_format_json_rejects_set(self, fmt):
        with pytest.raises(ValueError, match="not JSON serializable"):
            fmt.format_json({1, 2, 3})

    def test_format_json_rejects_frozenset(self, fmt):
        with pytest.raises(ValueError, match="not JSON serializable"):
            fmt.format_json(frozenset([1, 2]))

    def test_format_text_with_dict(self, fmt):
        result = fmt.format_text({"error": "fail", "message": "msg"}, title="Test")
        assert "=== Test ===" in result
        assert "error: fail" in result
        assert "message: msg" in result

    def test_format_text_with_dict_extra_keys(self, fmt):
        result = fmt.format_text({"error": "x", "custom_key": "y"})
        assert "custom_key: y" in result

    def test_format_text_with_list_of_dicts(self, fmt):
        result = fmt.format_text([{"a": 1}, {"b": 2}])
        assert '"a": 1' in result

    def test_format_text_with_list_of_strings(self, fmt):
        result = fmt.format_text(["a", "b", "c"])
        assert "- a" in result
        assert "- b" in result

    def test_format_text_with_non_standard(self, fmt):
        result = fmt.format_text(42)
        assert "42" in result

    def test_format_table_empty_headers(self, fmt):
        assert fmt.format_table([], []) == ""

    def test_format_table_with_data(self, fmt):
        rows = [{"name": "eth0", "status": "up"}, {"name": "lo", "status": "up"}]
        result = fmt.format_table(rows, ["name", "status"])
        assert "eth0" in result
        assert "lo" in result
        assert "name" in result

    def test_format_table_missing_key(self, fmt):
        rows = [{"name": "eth0"}]
        result = fmt.format_table(rows, ["name", "status"])
        assert "eth0" in result
        assert "-" in result

    def test_truncate_short_text(self, fmt):
        assert fmt.truncate("hello") == "hello"

    def test_truncate_long_text(self, fmt):
        result = fmt.truncate("a" * 1000, max_chars=100)
        assert len(result) < 200
        assert "truncated" in result

    def test_truncate_empty(self, fmt):
        assert fmt.truncate("") == ""

    def test_format_success(self, fmt):
        result = fmt.format_success({"key": "val"}, title="OK")
        assert result["isError"] is False
        assert "=== OK ===" in result["content"][0]["text"]

    def test_format_success_string(self, fmt):
        result = fmt.format_success("plain text")
        assert result["isError"] is False
        assert "plain text" in result["content"][0]["text"]

    def test_format_success_list(self, fmt):
        result = fmt.format_success([1, 2, 3])
        assert result["isError"] is False


# ── Convert format tests ──────────────────────────────────────────────


class TestConvertFormat:
    """Test convert_pcap_format tool."""

    @pytest.mark.asyncio
    async def test_convert_pcap_to_pcapng(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "convert_pcap_format", filepath=str(pcap), output_format="pcapng")
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_convert_invalid_format_rejected(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "convert_pcap_format", filepath=str(pcap), output_format="exe")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_convert_format_failure(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.convert_format = AsyncMock(
            return_value=MagicMock(returncode=1, stdout="", stderr="conversion failed")
        )

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "convert_pcap_format", filepath=str(pcap), output_format="pcapng")
        assert result["isError"] is True


# ── Protocol stats parsing ────────────────────────────────────────────


class TestProtocolStatsParsing:
    """Test robust protocol stats parsing."""

    def test_standard_format(self):
        text = (
            "===================================================================\n"
            "Protocol Hierarchy Statistics\n"
            "Filter:\n"
            "eth                                    frames:100 bytes:12000\n"
            "  ip                                   frames:90 bytes:10800\n"
            "===================================================================\n"
        )
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats
        assert stats["eth"]["frames"] == 100
        assert "ip" in stats
        assert stats["ip"]["frames"] == 90

    def test_tab_separated_format(self):
        text = "eth\t100\t12000\nip\t90\t10800"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats
        assert stats["eth"]["frames"] == 100
        assert stats["ip"]["frames"] == 90

    def test_empty_input(self):
        stats = TsharkInterface._parse_protocol_stats("")
        assert stats == {}

    def test_header_lines_skipped(self):
        text = "===\nFilter:\nProtocol Stats\neth                 frames:50 bytes:5000"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats
        assert stats["eth"]["frames"] == 50

    def test_mixed_content(self):
        text = "\n\n===\neth                 frames:10 bytes:500\n\n"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats


# ── Analysis tool branches ────────────────────────────────────────────


class TestAnalysisBranches:
    """Test analysis tool edge cases and branches."""

    @pytest.mark.asyncio
    async def test_capture_targeted_traffic_with_host(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "targeted.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            target_host="10.0.0.1",
            duration=5,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_capture_targeted_traffic_with_port(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "port.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            target_port=443,
            duration=5,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_capture_targeted_traffic_with_protocol_tcp(
        self, mock_tshark, fmt, sec, tmp_path
    ):
        pcap = tmp_path / "proto.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            protocol="tcp",
            duration=5,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_capture_targeted_traffic_http_protocol(self, mock_tshark, fmt, sec, tmp_path):
        """HTTP protocol translates to tcp port 80."""
        pcap = tmp_path / "http.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            protocol="http",
            duration=5,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_capture_targeted_traffic_https_protocol(self, mock_tshark, fmt, sec, tmp_path):
        """HTTPS protocol translates to tcp port 443."""
        pcap = tmp_path / "https.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            protocol="https",
            duration=5,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_capture_targeted_traffic_invalid_protocol(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            protocol="invalid_proto",
            duration=5,
        )
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_capture_targeted_all_filters(self, mock_tshark, fmt, sec, tmp_path):
        """Combine host + port + protocol."""
        pcap = tmp_path / "all.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "capture_targeted_traffic",
            interface="eth0",
            target_host="10.0.0.1",
            target_port=80,
            protocol="tcp",
            duration=5,
        )
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_detect_protocols_live_interface(self, mock_tshark, fmt, sec, tmp_path):
        """Detect protocols via live capture on interface."""
        pcap = tmp_path / "live.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)
        mock_tshark.protocol_stats = AsyncMock(
            return_value={
                "http": {"frames": 50, "bytes": 5000},
                "dns": {"frames": 30, "bytes": 3000},
            }
        )

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "detect_network_protocols", interface="eth0", duration=5)
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_detect_protocols_no_input(self, mock_tshark, fmt, sec):
        """Neither filepath nor interface returns error."""
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "detect_network_protocols")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_detect_protocols_with_insights(self, mock_tshark, fmt, sec, tmp_path):
        """Protocol insights include detected protocol names."""
        pcap = tmp_path / "insights.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.protocol_stats = AsyncMock(
            return_value={
                "http": {"frames": 50, "bytes": 5000},
                "tls": {"frames": 80, "bytes": 8000},
                "dns": {"frames": 30, "bytes": 3000},
            }
        )

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "detect_network_protocols", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "http" in text.lower()

    @pytest.mark.asyncio
    async def test_analyze_http_headers_with_auth_and_cookies(
        self, mock_tshark, fmt, sec, tmp_path
    ):
        """HTTP headers with Bearer auth and cookies."""
        pcap = tmp_path / "headers.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "http.request.method": "GET",
                    "http.host": "api.example.com",
                    "http.request.uri": "/users",
                    "http.response.code": "",
                    "http.authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.long.token",
                    "http.cookie": "session=abc123def; csrftoken=xyz789",
                    "http.set_cookie": "",
                    "http.user_agent": "curl/7.68.0",
                    "http.referer": "",
                    "http.x_forwarded_for": "192.168.1.100",
                    "frame.number": "5",
                },
            ]
        )

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_http_headers", filepath=str(pcap), include_cookies=True)
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Bearer" in text
        assert "session" in text
        assert "X-Forwarded-For" in text

    @pytest.mark.asyncio
    async def test_analyze_http_headers_no_cookies(self, mock_tshark, fmt, sec, tmp_path):
        """HTTP headers with include_cookies=False."""
        pcap = tmp_path / "nocookies.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "http.request.method": "POST",
                    "http.host": "example.com",
                    "http.request.uri": "/login",
                    "http.response.code": "302",
                    "http.authorization": "Basic dXNlcjpwYXNz",
                    "http.cookie": "token=shouldnotappear",
                    "http.set_cookie": "",
                    "http.user_agent": "Mozilla/5.0",
                    "http.referer": "",
                    "http.x_forwarded_for": "",
                    "frame.number": "10",
                },
            ]
        )

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_http_headers", filepath=str(pcap), include_cookies=False)
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "Basic" in text

    @pytest.mark.asyncio
    async def test_analyze_pcap_error_handling(self, mock_tshark, fmt, sec):
        """Non-existent file returns error."""
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_pcap_file", filepath="/nonexistent/file.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_get_protocol_statistics_error(self, mock_tshark, fmt, sec):
        """Error in protocol stats returns formatted error."""
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_protocol_statistics", filepath="/bad.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_get_capture_file_info_error(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "get_capture_file_info", filepath="/missing.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_analyze_http_traffic_with_data(self, mock_tshark, fmt, sec, tmp_path):
        """HTTP traffic analysis with methods, hosts, status codes."""
        pcap = tmp_path / "http_data.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {
                    "http.request.method": "GET",
                    "http.host": "example.com",
                    "http.request.uri": "/page1",
                    "http.response.code": "",
                    "http.user_agent": "Mozilla/5.0",
                },
                {
                    "http.request.method": "POST",
                    "http.host": "example.com",
                    "http.request.uri": "/api",
                    "http.response.code": "",
                    "http.user_agent": "curl/7.68.0",
                },
                {
                    "http.request.method": "",
                    "http.host": "",
                    "http.request.uri": "",
                    "http.response.code": "200",
                    "http.user_agent": "",
                },
                {
                    "http.request.method": "",
                    "http.host": "",
                    "http.request.uri": "",
                    "http.response.code": "404",
                    "http.user_agent": "",
                },
            ]
        )

        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "analyze_http_traffic", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "GET" in text
        assert "POST" in text

    @pytest.mark.asyncio
    async def test_geoip_no_ips(self, mock_tshark, fmt, sec):
        """No IPs provided returns error."""
        from netmcp.tools.analysis import register_analysis_tools

        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "geoip_lookup", ip_addresses="")
        assert result["isError"] is True


# ── Export tools extra branches ───────────────────────────────────────


class TestExportBranches:
    """Test export tools additional branches."""

    @pytest.mark.asyncio
    async def test_export_json_error(self, mock_tshark, fmt, sec):
        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_json", filepath="/nonexistent.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_export_csv_error(self, mock_tshark, fmt, sec):
        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath="/nonexistent.pcap")
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_export_csv_empty_result(self, mock_tshark, fmt, sec, tmp_path):
        """CSV export with no rows produces empty CSV."""
        pcap = tmp_path / "empty.pcap"
        pcap.write_bytes(b"fake pcap" * 100)
        mock_tshark.export_fields = AsyncMock(return_value=[])

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "export_packets_csv", filepath=str(pcap))
        assert result["isError"] is False

    @pytest.mark.asyncio
    async def test_export_json_with_filter(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "filtered.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        from netmcp.tools.export_tools import register_export_tools

        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)
        result = await call(
            mcp,
            "export_packets_json",
            filepath=str(pcap),
            display_filter="http",
            max_packets=100,
        )
        assert result["isError"] is False


# ── Stream tool error branches ────────────────────────────────────────


class TestStreamBranches:
    """Test stream tool error handling."""

    @pytest.mark.asyncio
    async def test_follow_tcp_error(self, mock_tshark, fmt, sec):
        from netmcp.tools.streams import register_stream_tools

        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "follow_tcp_stream", filepath="/bad.pcap", stream_index=0)
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_follow_udp_error(self, mock_tshark, fmt, sec):
        from netmcp.tools.streams import register_stream_tools

        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "follow_udp_stream", filepath="/bad.pcap", stream_index=0)
        assert result["isError"] is True

    @pytest.mark.asyncio
    async def test_list_tcp_streams_error(self, mock_tshark, fmt, sec):
        from netmcp.tools.streams import register_stream_tools

        mcp = FastMCP("test")
        register_stream_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "list_tcp_streams", filepath="/bad.pcap")
        assert result["isError"] is True
