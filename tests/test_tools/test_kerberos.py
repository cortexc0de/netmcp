"""Tests for Kerberos credential extraction and private IP filtering."""

from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.threat_intel import ThreatIntelInterface, _is_private_ip
from netmcp.interfaces.tshark import TsharkInterface

# ── Helpers ────────────────────────────────────────────────────────────


async def call(mcp: FastMCP, name: str, **kwargs):
    """Helper to call a registered tool by name."""
    return await mcp._tool_manager.call_tool(name, kwargs)


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
        tshark.export_fields = AsyncMock(return_value=[])
        tshark._run = AsyncMock()
        return tshark


# ── Kerberos extraction tests ─────────────────────────────────────────


class TestKerberosExtraction:
    @pytest.mark.asyncio
    async def test_kerberos_extraction_success(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos AS-REQ and AS-REP hashes extracted with correct formats."""
        pcap = tmp_path / "krb_full.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],  # plaintext creds
                [
                    {
                        "kerberos.CNameString": "admin",
                        "kerberos.realm": "CORP.LOCAL",
                        "kerberos.cipher": "deadbeef",
                        "kerberos.type": "",
                        "kerberos.msg_type": "10",
                        "frame.number": "3",
                    },
                    {
                        "kerberos.CNameString": "jdoe",
                        "kerberos.realm": "CORP.LOCAL",
                        "kerberos.cipher": "abc123",
                        "kerberos.type": "",
                        "kerberos.msg_type": "11",
                        "frame.number": "5",
                    },
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        # AS-REQ format with $*$
        assert "$krb5pa$23$admin$CORP.LOCAL$*$deadbeef" in text
        assert "7500" in text
        # AS-REP format with :
        assert "$krb5asrep$23$jdoe@CORP.LOCAL:abc123" in text
        assert "18200" in text

    @pytest.mark.asyncio
    async def test_kerberos_tgs_req_service_ticket(self, mock_tshark, fmt, sec, tmp_path):
        """Kerberos TGS-REQ (msg_type 12) noted as service ticket request."""
        pcap = tmp_path / "krb_tgs12.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],
                [
                    {
                        "kerberos.CNameString": "svc_http",
                        "kerberos.realm": "DOMAIN.COM",
                        "kerberos.cipher": "cafebabe",
                        "kerberos.type": "",
                        "kerberos.msg_type": "12",
                        "frame.number": "9",
                    },
                ],
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "TGS-REQ" in text
        assert "svc_http" in text
        assert "Service ticket request" in text

    @pytest.mark.asyncio
    async def test_kerberos_no_data(self, mock_tshark, fmt, sec, tmp_path):
        """No Kerberos traffic produces zero encrypted credentials."""
        pcap = tmp_path / "no_krb.pcap"
        pcap.write_bytes(b"fake pcap" * 100)

        mock_tshark.export_fields = AsyncMock(
            side_effect=[
                [],  # plaintext creds
                [],  # kerberos creds
            ]
        )

        from netmcp.tools.credentials import register_credential_tools

        mcp = FastMCP("test")
        register_credential_tools(mcp, mock_tshark, fmt, sec)
        result = await call(mcp, "extract_credentials", filepath=str(pcap))
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert '"encrypted_count": 0' in text


# ── Private IP filtering tests ────────────────────────────────────────


class TestIsPrivateIp:
    def test_rfc1918_10(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_link_local(self):
        assert _is_private_ip("169.254.1.1") is True

    def test_multicast(self):
        assert _is_private_ip("224.0.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_another_public(self):
        assert _is_private_ip("1.1.1.1") is False

    def test_invalid_ip(self):
        assert _is_private_ip("not_an_ip") is False

    def test_empty_string(self):
        assert _is_private_ip("") is False


class TestPrivateIpFiltering:
    @pytest.mark.asyncio
    async def test_private_ips_skipped_in_scan(self):
        """Private IPs are filtered out before threat checking."""
        threat = ThreatIntelInterface(providers=["urlhaus"])

        mock_tshark = AsyncMock()
        mock_tshark.export_fields = AsyncMock(
            return_value=[
                {"ip.src": "192.168.1.1", "ip.dst": "8.8.8.8"},
                {"ip.src": "10.0.0.1", "ip.dst": "1.2.3.4"},
                {"ip.src": "127.0.0.1", "ip.dst": "172.16.0.1"},
            ]
        )

        # Mock the check_ip to avoid network calls
        threat.check_ip = AsyncMock(
            return_value={
                "ip": "mock",
                "is_threat": False,
                "threat_providers": [],
                "providers": {},
            }
        )

        result = await threat.scan_pcap("fake.pcap", mock_tshark)

        # Only 8.8.8.8 and 1.2.3.4 should be checked (public IPs)
        assert result["private_ips_skipped"] > 0
        assert result["public_ips_checked"] == 2
        assert threat.check_ip.call_count == 2

        # Verify the actual IPs checked
        checked_ips = {c.args[0] for c in threat.check_ip.call_args_list}
        assert "8.8.8.8" in checked_ips
        assert "1.2.3.4" in checked_ips
        assert "192.168.1.1" not in checked_ips
        assert "10.0.0.1" not in checked_ips
