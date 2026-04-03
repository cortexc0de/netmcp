"""Targeted tests for uncovered lines in interfaces/nmap.py."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from netmcp.interfaces.nmap import NmapInterface, NmapNotFoundError


def _make_nmap(**overrides):
    """Create NmapInterface without real nmap dependency."""
    iface = NmapInterface.__new__(NmapInterface)
    iface.available = overrides.get("available", True)
    iface._scanner = overrides.get("scanner", MagicMock())
    iface._security = overrides.get("security")
    return iface


class TestNmapRepr:
    def test_repr(self):
        """Line 49: __repr__."""
        iface = _make_nmap()
        r = repr(iface)
        assert "NmapInterface" in r
        assert "True" in r


class TestNmapNotAvailable:
    def test_get_scanner_not_available(self):
        """Line 54: NmapNotFoundError when not available."""
        iface = _make_nmap(available=False)
        with pytest.raises(NmapNotFoundError, match="nmap not found"):
            iface._get_scanner()


class TestNmapSecurityValidation:
    @pytest.mark.asyncio
    async def test_security_validates_arguments(self):
        """Line 74: security validator called."""
        mock_security = MagicMock()
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}

        iface = _make_nmap(security=mock_security, scanner=mock_scanner)
        await iface._run_scan("10.0.0.1", "-sT")
        mock_security.validate_nmap_arguments.assert_called_once_with("-sT")


class TestNmapScanErrors:
    @pytest.mark.asyncio
    async def test_port_scanner_error(self):
        """Line 85: nmap.PortScannerError → RuntimeError."""
        import nmap

        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = nmap.PortScannerError("scan failed")
        iface = _make_nmap(scanner=mock_scanner)
        with pytest.raises(RuntimeError, match="Nmap scan error"):
            await iface._run_scan("10.0.0.1", "-sT")

    @pytest.mark.asyncio
    async def test_subprocess_error(self):
        """Line 87: SubprocessError → RuntimeError."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = subprocess.SubprocessError("subprocess fail")
        iface = _make_nmap(scanner=mock_scanner)
        with pytest.raises(RuntimeError, match="Nmap subprocess error"):
            await iface._run_scan("10.0.0.1", "-sT")

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        """Line 95: TimeoutError."""
        import asyncio

        mock_scanner = MagicMock()
        iface = _make_nmap(scanner=mock_scanner)

        # Directly patch asyncio.wait_for to raise TimeoutError
        # original saved for reference

        async def mock_wait_for(coro, *, timeout=None):
            # Cancel the coroutine to avoid warnings
            coro.close() if hasattr(coro, "close") else None
            raise TimeoutError(f"Nmap scan timed out after {timeout}s for 10.0.0.1")

        with patch.object(asyncio, "wait_for", side_effect=mock_wait_for):
            with pytest.raises(TimeoutError, match="timed out"):
                await iface._run_scan("10.0.0.1", "-sT", timeout=0.01)


class TestNmapPortBranches:
    @pytest.mark.asyncio
    async def test_port_scan_no_ports(self):
        """Line 124→127: no ports specified."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.port_scan("10.0.0.1", ports="", scan_type="connect")
        args = mock_scanner.scan.call_args
        assert "-p" not in args.kwargs.get("arguments", args[1].get("arguments", ""))

    @pytest.mark.asyncio
    async def test_port_scan_with_ports(self):
        """Line 124→127: ports specified."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.port_scan("10.0.0.1", ports="80,443", scan_type="syn")
        call_kwargs = mock_scanner.scan.call_args
        arguments = call_kwargs.kwargs.get("arguments") or call_kwargs[1].get("arguments", "")
        assert "-p 80,443" in arguments

    @pytest.mark.asyncio
    async def test_service_detect_with_ports(self):
        """Line 140: ports specified in service_detect."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.service_detect("10.0.0.1", ports="22,80")
        call_kwargs = mock_scanner.scan.call_args
        arguments = call_kwargs.kwargs.get("arguments") or call_kwargs[1].get("arguments", "")
        assert "-p 22,80" in arguments

    @pytest.mark.asyncio
    async def test_vuln_scan_with_ports(self):
        """Line 165→167: ports specified in vuln_scan."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.vuln_scan("10.0.0.1", ports="443")
        call_kwargs = mock_scanner.scan.call_args
        arguments = call_kwargs.kwargs.get("arguments") or call_kwargs[1].get("arguments", "")
        assert "-p 443" in arguments


class TestNmapComprehensiveScan:
    @pytest.mark.asyncio
    async def test_comprehensive_scan(self):
        """Lines 187-188: comprehensive_scan."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {"10.0.0.1": {"tcp": {}}}}
        iface = _make_nmap(scanner=mock_scanner)
        result = await iface.comprehensive_scan("10.0.0.1")
        assert "scan" in result
        call_kwargs = mock_scanner.scan.call_args
        arguments = call_kwargs.kwargs.get("arguments") or call_kwargs[1].get("arguments", "")
        assert "-sS" in arguments
        assert "-sV" in arguments
        assert "-O" in arguments


class TestNmapScanTypeVariants:
    @pytest.mark.asyncio
    async def test_syn_scan(self):
        """syn scan type uses -sS."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.port_scan("10.0.0.1", scan_type="syn")
        arguments = mock_scanner.scan.call_args.kwargs.get("arguments") or mock_scanner.scan.call_args[1].get("arguments", "")
        assert "-sS" in arguments

    @pytest.mark.asyncio
    async def test_udp_scan(self):
        """udp scan type uses -sU."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.port_scan("10.0.0.1", scan_type="udp")
        arguments = mock_scanner.scan.call_args.kwargs.get("arguments") or mock_scanner.scan.call_args[1].get("arguments", "")
        assert "-sU" in arguments

    @pytest.mark.asyncio
    async def test_unknown_scan_defaults_to_connect(self):
        """Unknown scan_type defaults to -sT."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"scan": {}}
        iface = _make_nmap(scanner=mock_scanner)
        await iface.port_scan("10.0.0.1", scan_type="unknown")
        arguments = mock_scanner.scan.call_args.kwargs.get("arguments") or mock_scanner.scan.call_args[1].get("arguments", "")
        assert "-sT" in arguments


class TestNmapImportError:
    def test_nmap_not_importable(self):
        """Lines 18-19: ImportError when nmap module missing."""
        with patch.dict("sys.modules", {"nmap": None}):
            iface = _make_nmap(available=False)
            assert iface.available is False
