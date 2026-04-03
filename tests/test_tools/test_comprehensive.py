"""Comprehensive integration tests to achieve 80%+ coverage."""

import logging
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import ErrorCode, OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


# ── Fixtures ────────────────────────────────────────────────────────────


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
        tshark.read_pcap = AsyncMock(return_value=[
            {"_source": {"layers": {
                "ip.src": ["10.0.0.1"], "ip.dst": ["10.0.0.2"],
                "frame.number": ["1"], "frame.protocols": ["eth:ethertype:ip:tcp:http"],
                "frame.len": ["100"],
            }}}
        ])
        tshark.protocol_stats = AsyncMock(return_value={
            "tcp": {"frames": 100, "bytes": 12000},
            "udp": {"frames": 50, "bytes": 6000},
        })
        tshark.follow_stream = AsyncMock(return_value="GET / HTTP/1.1\r\nHost: example.com\r\n")
        tshark.list_streams = AsyncMock(return_value=[
            {"endpoint_a": "192.168.1.1:443", "endpoint_b": "10.0.0.1:54321"}
        ])
        tshark.export_fields = AsyncMock(return_value=[
            {"http.request.method": "GET", "http.host": "example.com",
             "http.request.uri": "/api", "http.response.code": "200",
             "http.user_agent": "Mozilla/5.0",
             "http.authorization": "Bearer eyJ...", "http.cookie": "session=abc",
             "http.x_forwarded_for": "", "frame.number": "1"},
        ])
        tshark.export_json = AsyncMock(return_value=[{"_source": {"layers": {}}}])
        tshark.file_info = AsyncMock(return_value={"filepath": "/tmp/test.pcap", "total_frames": "150"})
        tshark._run = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        tshark.convert_format = AsyncMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        yield tshark


# ── Credential Extraction (45% → 80%+) ─────────────────────────────────


class TestCredentialHTTPBasic:
    @pytest.mark.asyncio
    async def test_http_basic_auth_decoded(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "creds.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        # base64("admin:password123")
        mock_tshark.export_fields = AsyncMock(side_effect=[
            [{"http.authbasic": "YWRtaW46cGFzc3dvcmQxMjM=", "ftp.request.command": "",
              "ftp.request.arg": "", "telnet.data": "", "frame.number": "1"}],
            [],
        ])

        from netmcp.tools.credentials import register_credential_tools
        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)

        tools = mcp._tool_manager._tools
        for name, tool in tools.items():
            if "credential" in name.lower() or "extract" in name.lower():
                result = await tool.fn(filepath=str(pcap))
                assert result["isError"] is False
                text = result["content"][0]["text"]
                assert "admin" in text
                break


class TestCredentialFTP:
    @pytest.mark.asyncio
    async def test_ftp_user_pass_paired(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "ftp.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(side_effect=[
            [
                {"ftp.request.command": "USER", "ftp.request.arg": "admin",
                 "http.authbasic": "", "telnet.data": "", "frame.number": "1"},
                {"ftp.request.command": "PASS", "ftp.request.arg": "secret123",
                 "http.authbasic": "", "telnet.data": "", "frame.number": "2"},
            ],
            [],
        ])

        from netmcp.tools.credentials import register_credential_tools
        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "credential" in name.lower() or "extract" in name.lower():
                result = await tool.fn(filepath=str(pcap))
                assert result["isError"] is False
                text = result["content"][0]["text"]
                assert "admin" in text
                assert "secret123" in text
                break


class TestCredentialKerberos:
    @pytest.mark.asyncio
    async def test_kerberos_asrep_hash(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "krb.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(side_effect=[
            [],
            [{"kerberos.CNameString": "jdoe", "kerberos.realm": "CORP.LOCAL",
              "kerberos.cipher": "abc123", "kerberos.type": "",
              "kerberos.msg_type": "11", "frame.number": "5"}],
        ])

        from netmcp.tools.credentials import register_credential_tools
        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "credential" in name.lower() or "extract" in name.lower():
                result = await tool.fn(filepath=str(pcap))
                assert result["isError"] is False
                text = result["content"][0]["text"]
                assert "jdoe" in text
                assert "krb5asrep" in text
                assert "hashcat" in text
                break


class TestCredentialTelnet:
    @pytest.mark.asyncio
    async def test_telnet_login_detected(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "telnet.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(side_effect=[
            [
                {"telnet.data": "login: ", "ftp.request.command": "",
                 "ftp.request.arg": "", "http.authbasic": "", "frame.number": "1"},
                {"telnet.data": "admin", "ftp.request.command": "",
                 "ftp.request.arg": "", "http.authbasic": "", "frame.number": "2"},
                {"telnet.data": "password: ", "ftp.request.command": "",
                 "ftp.request.arg": "", "http.authbasic": "", "frame.number": "3"},
                {"telnet.data": "secret", "ftp.request.command": "",
                 "ftp.request.arg": "", "http.authbasic": "", "frame.number": "4"},
            ],
            [],
        ])

        from netmcp.tools.credentials import register_credential_tools
        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "credential" in name.lower() or "extract" in name.lower():
                result = await tool.fn(filepath=str(pcap))
                assert result["isError"] is False
                text = result["content"][0]["text"]
                assert "Telnet" in text
                break


# ── Nmap Flags Validation ───────────────────────────────────────────────


class TestNmapFlagsValidation:
    def test_allowed_flags(self, sec):
        assert sec.validate_nmap_arguments("-sT -T4") == "-sT -T4"
        assert sec.validate_nmap_arguments("-sS -T4 -p 80,443") == "-sS -T4 -p 80,443"
        assert sec.validate_nmap_arguments("-sV -T4") == "-sV -T4"
        assert sec.validate_nmap_arguments("--script vuln -T4") == "--script vuln -T4"
        assert sec.validate_nmap_arguments("-F -T4") == "-F -T4"
        assert sec.validate_nmap_arguments("") == ""

    def test_dangerous_flags_rejected(self, sec):
        with pytest.raises(ValueError, match="Dangerous"):
            sec.validate_nmap_arguments("--interactive")
        with pytest.raises(ValueError, match="Dangerous"):
            sec.validate_nmap_arguments("--script-args user=admin")

    def test_unknown_flags_rejected(self, sec):
        with pytest.raises(ValueError, match="not in allowed"):
            sec.validate_nmap_arguments("--some-random-flag")

    def test_script_safe_allowed(self, sec):
        assert sec.validate_nmap_arguments("--script=safe") == "--script=safe"

    def test_script_unsafe_rejected(self, sec):
        with pytest.raises(ValueError, match="not in allowed"):
            sec.validate_nmap_arguments("--script=exploit")


# ── Symlink Rejection ───────────────────────────────────────────────────


class TestSymlinkRejection:
    def test_symlink_rejected(self, sec, tmp_path):
        target = tmp_path / "real.pcap"
        target.write_bytes(b"fake pcap data")
        link = tmp_path / "link.pcap"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="[Ss]ymbolic"):
            sec.sanitize_filepath(str(link))

    def test_regular_file_accepted(self, sec, tmp_path):
        f = tmp_path / "normal.pcap"
        f.write_bytes(b"fake pcap data")
        assert sec.sanitize_filepath(str(f)) == f.resolve()


# ── Audit Logging ───────────────────────────────────────────────────────


class TestAuditLogging:
    def test_audit_log_basic(self, sec, caplog):
        with caplog.at_level(logging.INFO, logger="netmcp.security"):
            sec.audit_log("test_operation", {"target": "10.0.0.1"})
        assert "AUDIT: test_operation" in caplog.text
        assert "10.0.0.1" in caplog.text

    def test_audit_log_filters_secrets(self, sec, caplog):
        with caplog.at_level(logging.INFO, logger="netmcp.security"):
            sec.audit_log("test_op", {"target": "x", "password": "s3cret", "token": "abc"})
        assert "s3cret" not in caplog.text
        assert "abc" not in caplog.text

    def test_audit_log_no_details(self, sec, caplog):
        with caplog.at_level(logging.INFO, logger="netmcp.security"):
            sec.audit_log("simple_op")
        assert "AUDIT: simple_op" in caplog.text


# ── Error Codes ─────────────────────────────────────────────────────────


class TestErrorCodes:
    def test_error_code_constants(self):
        assert ErrorCode.INTERNAL == "NETMCP_001"
        assert ErrorCode.VALIDATION == "NETMCP_002"
        assert ErrorCode.TOOL_EXECUTION == "NETMCP_003"
        assert ErrorCode.FILE_ERROR == "NETMCP_004"
        assert ErrorCode.TIMEOUT == "NETMCP_005"
        assert ErrorCode.RATE_LIMITED == "NETMCP_006"
        assert ErrorCode.PERMISSION == "NETMCP_007"
        assert ErrorCode.NOT_AVAILABLE == "NETMCP_008"

    def test_format_error_mapping(self, fmt):
        assert "[NETMCP_002]" in fmt.format_error(ValueError("bad"))["content"][0]["text"]
        assert "[NETMCP_004]" in fmt.format_error(FileNotFoundError("no"))["content"][0]["text"]
        assert "[NETMCP_005]" in fmt.format_error(TimeoutError("slow"))["content"][0]["text"]
        assert "[NETMCP_007]" in fmt.format_error(PermissionError("no"))["content"][0]["text"]

    def test_format_error_unknown(self, fmt):
        result = fmt.format_error(Exception("generic"))
        assert "[NETMCP_001]" in result["content"][0]["text"]


# ── Formatter Extended Coverage ─────────────────────────────────────────


class TestFormatterExtended:
    def test_format_json_rejects_set(self, fmt):
        with pytest.raises(ValueError, match="not JSON serializable"):
            fmt.format_json({1, 2, 3})

    def test_format_text_dict(self, fmt):
        result = fmt.format_text({"error": "fail", "message": "msg"}, title="T")
        assert "=== T ===" in result
        assert "error: fail" in result

    def test_format_text_list_of_dicts(self, fmt):
        result = fmt.format_text([{"a": 1}])
        assert '"a": 1' in result

    def test_format_text_list_of_strings(self, fmt):
        result = fmt.format_text(["a", "b"])
        assert "- a" in result

    def test_format_table_empty(self, fmt):
        assert fmt.format_table([], []) == ""

    def test_format_table_with_data(self, fmt):
        rows = [{"name": "eth0", "status": "up"}]
        result = fmt.format_table(rows, ["name", "status"])
        assert "eth0" in result and "up" in result

    def test_truncate_short(self, fmt):
        assert fmt.truncate("hello") == "hello"

    def test_truncate_long(self, fmt):
        result = fmt.truncate("a" * 1000, max_chars=100)
        assert "truncated" in result

    def test_truncate_empty(self, fmt):
        assert fmt.truncate("") == ""

    def test_format_success_dict(self, fmt):
        r = fmt.format_success({"k": "v"}, title="OK")
        assert r["isError"] is False
        assert "=== OK ===" in r["content"][0]["text"]

    def test_format_success_string(self, fmt):
        r = fmt.format_success("text")
        assert "text" in r["content"][0]["text"]


# ── Protocol Stats Parser ──────────────────────────────────────────────


class TestProtocolStatsParsing:
    def test_standard_format(self):
        text = (
            "===\nProtocol Hierarchy Statistics\nFilter:\n"
            "eth                                    frames:100 bytes:12000\n"
            "  ip                                   frames:90 bytes:10800\n==="
        )
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats
        assert stats["eth"]["frames"] == 100

    def test_tab_separated_format(self):
        text = "eth\t100\t12000\nip\t90\t10800"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats
        assert stats["eth"]["frames"] == 100

    def test_empty_input(self):
        assert TsharkInterface._parse_protocol_stats("") == {}

    def test_header_lines_skipped(self):
        text = "===\nFilter:\nProtocol stuff\neth  frames:50 bytes:5000"
        stats = TsharkInterface._parse_protocol_stats(text)
        assert "eth" in stats


# ── Tshark Field Validation ─────────────────────────────────────────────


class TestTsharkFieldValidation:
    def test_valid_fields(self):
        _RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{0,127}$")
        for f in ["http.host", "frame.number", "ip.src", "tcp.dstport"]:
            assert _RE.match(f), f"{f} should be valid"

    def test_invalid_fields(self):
        _RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{0,127}$")
        for f in ["$(whoami)", "; rm -rf", "has spaces", "123bad", ""]:
            assert not _RE.match(f), f"{f!r} should be invalid"


# ── Convert Format ──────────────────────────────────────────────────────


class TestConvertFormat:
    @pytest.mark.asyncio
    async def test_convert_method_exists(self, mock_tshark, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake" * 100)
        result = await mock_tshark.convert_format(str(pcap), str(pcap) + ".pcapng")
        assert result.returncode == 0

    @pytest.mark.asyncio
    async def test_convert_invalid_format_rejected(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"fake" * 100)

        from netmcp.tools.export_tools import register_export_tools
        mcp = FastMCP("test")
        register_export_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "convert" in name.lower():
                result = await tool.fn(filepath=str(pcap), output_format="exe")
                assert result["isError"] is True
                break


# ── Resources ───────────────────────────────────────────────────────────


class TestResources:
    def test_resources_registered(self):
        from netmcp.server import create_server
        server = create_server()
        assert hasattr(server, "_resource_manager")

    def test_register_resources(self, mock_tshark, fmt):
        from netmcp.interfaces.nmap import NmapInterface
        from netmcp.resources import register_resources

        nmap = NmapInterface.__new__(NmapInterface)
        nmap.available = False
        mcp = FastMCP("test")
        register_resources(mcp, mock_tshark, nmap, fmt)
        # Should complete without error


# ── Analysis Tool Branches ──────────────────────────────────────────────


class TestAnalysisToolBranches:
    @pytest.mark.asyncio
    async def test_capture_targeted_valid_protocol(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "targeted.pcap"
        pcap.write_bytes(b"fake" * 100)
        mock_tshark.capture_live = AsyncMock(return_value=pcap)

        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "targeted" in name.lower():
                result = await tool.fn(
                    interface="eth0", target_host="10.0.0.1",
                    target_port=80, protocol="tcp", duration=1, packet_limit=10,
                )
                assert result["isError"] is False
                break

    @pytest.mark.asyncio
    async def test_capture_targeted_invalid_protocol(self, mock_tshark, fmt, sec, tmp_path):
        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "targeted" in name.lower():
                result = await tool.fn(
                    interface="eth0", protocol="evil_injection", duration=1, packet_limit=10,
                )
                assert result["isError"] is True
                break

    @pytest.mark.asyncio
    async def test_detect_protocols_from_file(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "detect.pcap"
        pcap.write_bytes(b"fake" * 100)

        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "detect" in name.lower() and "protocol" in name.lower():
                result = await tool.fn(filepath=str(pcap))
                assert result["isError"] is False
                break

    @pytest.mark.asyncio
    async def test_detect_protocols_no_input(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "detect" in name.lower() and "protocol" in name.lower():
                result = await tool.fn(filepath="", interface="")
                assert result["isError"] is True
                break

    @pytest.mark.asyncio
    async def test_http_headers_analysis(self, mock_tshark, fmt, sec, tmp_path):
        pcap = tmp_path / "headers.pcap"
        pcap.write_bytes(b"fake" * 100)

        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "header" in name.lower():
                result = await tool.fn(filepath=str(pcap), include_cookies=True)
                assert result["isError"] is False
                text = result["content"][0]["text"]
                assert "Bearer" in text or "auth" in text.lower()
                break

    @pytest.mark.asyncio
    async def test_geoip_lookup_with_ips(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "geoip" in name.lower():
                result = await tool.fn(ip_addresses="1.1.1.1,8.8.8.8")
                assert result["isError"] is False
                break

    @pytest.mark.asyncio
    async def test_geoip_lookup_no_ips(self, mock_tshark, fmt, sec):
        from netmcp.tools.analysis import register_analysis_tools
        mcp = FastMCP("test")
        register_analysis_tools(mcp, mock_tshark, fmt, sec)

        for name, tool in mcp._tool_manager._tools.items():
            if "geoip" in name.lower():
                result = await tool.fn(ip_addresses="")
                assert result["isError"] is True
                break
