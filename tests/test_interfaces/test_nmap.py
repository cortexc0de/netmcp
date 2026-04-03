"""Tests for NmapInterface."""

from unittest.mock import MagicMock, patch

import pytest

from netmcp.interfaces.nmap import NmapInterface


class TestNmapInit:
    def test_auto_find_nmap(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            iface = NmapInterface()
            assert iface.available is True

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            iface = NmapInterface()
            assert iface.available is False


class TestPortScan:
    @pytest.mark.asyncio
    async def test_connect_scan(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "scan": {
                "127.0.0.1": {
                    "tcp": {
                        22: {"state": "open", "name": "ssh"},
                        80: {"state": "open", "name": "http"},
                    }
                }
            }
        }

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("nmap.PortScanner", return_value=mock_scanner),
        ):
            iface = NmapInterface()
            result = await iface.port_scan("127.0.0.1", ports="22,80", scan_type="connect")
            assert "scan" in result
            assert "127.0.0.1" in result["scan"]
            assert result["scan"]["127.0.0.1"]["tcp"][22]["state"] == "open"

    @pytest.mark.asyncio
    async def test_nmap_error(self):
        """Nmap should handle errors gracefully."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("nmap failed")
        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("nmap.PortScanner", return_value=mock_scanner),
        ):
            iface = NmapInterface()
            with pytest.raises(RuntimeError):
                await iface.port_scan("10.0.0.1", ports="80")


class TestServiceDetection:
    @pytest.mark.asyncio
    async def test_detects_services(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "scan": {
                "10.0.0.1": {
                    "tcp": {
                        80: {
                            "state": "open",
                            "name": "http",
                            "product": "nginx",
                            "version": "1.18.0",
                        }
                    }
                }
            }
        }

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("nmap.PortScanner", return_value=mock_scanner),
        ):
            iface = NmapInterface()
            result = await iface.service_detect("10.0.0.1")
            svc = result["scan"]["10.0.0.1"]["tcp"][80]
            assert svc["product"] == "nginx"
            assert svc["version"] == "1.18.0"


class TestOSDetect:
    @pytest.mark.asyncio
    async def test_os_detection(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "scan": {"10.0.0.1": {"osmatch": [{"name": "Linux 5.4", "accuracy": "95"}]}}
        }

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("nmap.PortScanner", return_value=mock_scanner),
        ):
            iface = NmapInterface()
            result = await iface.os_detect("10.0.0.1")
            assert "osmatch" in result["scan"]["10.0.0.1"]
            assert result["scan"]["10.0.0.1"]["osmatch"][0]["name"] == "Linux 5.4"


class TestVulnScan:
    @pytest.mark.asyncio
    async def test_vuln_scan(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "scan": {
                "10.0.0.1": {
                    "tcp": {
                        443: {"state": "open", "script": {"ssl-enum-ciphers": "TLSv1.2: secure"}}
                    }
                }
            }
        }

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("nmap.PortScanner", return_value=mock_scanner),
        ):
            iface = NmapInterface()
            result = await iface.vuln_scan("10.0.0.1", ports="443")
            assert "script" in result["scan"]["10.0.0.1"]["tcp"][443]


class TestQuickScan:
    @pytest.mark.asyncio
    async def test_quick_scan(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "scan": {
                "10.0.0.1": {
                    "tcp": {
                        80: {"state": "open", "name": "http"},
                    }
                }
            }
        }

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("nmap.PortScanner", return_value=mock_scanner),
        ):
            iface = NmapInterface()
            result = await iface.quick_scan("10.0.0.1")
            assert result["scan"]["10.0.0.1"]["tcp"][80]["state"] == "open"
