"""Tests for SecurityValidator."""

import os
import time
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from netmcp.core.security import SecurityValidator


@pytest.fixture
def validator():
    return SecurityValidator()


class TestValidateInterface:
    def test_valid_simple(self, validator):
        assert validator.validate_interface("eth0") == "eth0"
        assert validator.validate_interface("wlan0") == "wlan0"
        assert validator.validate_interface("en0") == "en0"
        assert validator.validate_interface("lo") == "lo"

    def test_valid_with_hyphen(self, validator):
        assert validator.validate_interface("Wi-Fi") == "Wi-Fi"
        assert validator.validate_interface("eth-0") == "eth-0"

    def test_valid_alias(self, validator):
        assert validator.validate_interface("eth0:0") == "eth0:0"

    def test_valid_docker_interface(self, validator):
        assert validator.validate_interface("docker0") == "docker0"
        assert validator.validate_interface("br-abc123") == "br-abc123"

    def test_reject_empty(self, validator):
        with pytest.raises(ValueError, match="Interface name cannot be empty"):
            validator.validate_interface("")

    def test_reject_shell_chars(self, validator):
        for bad in ["eth0; rm -rf /", "eth0 | cat", "eth0 &", "eth0$", "eth0`whoami`"]:
            with pytest.raises(ValueError, match="shell metacharacters"):
                validator.validate_interface(bad)

    def test_reject_too_long(self, validator):
        with pytest.raises(ValueError, match="too long"):
            validator.validate_interface("a" * 257)

    def test_reject_spaces(self, validator):
        with pytest.raises(ValueError, match="spaces"):
            validator.validate_interface("eth 0")


class TestValidateTarget:
    def test_valid_ipv4(self, validator):
        assert validator.validate_target("192.168.1.1") == "192.168.1.1"
        assert validator.validate_target("10.0.0.1") == "10.0.0.1"
        assert validator.validate_target("127.0.0.1") == "127.0.0.1"

    def test_valid_cidr(self, validator):
        assert validator.validate_target("192.168.0.0/24") == "192.168.0.0/24"
        assert validator.validate_target("10.0.0.0/8") == "10.0.0.0/8"
        assert validator.validate_target("0.0.0.0/0") == "0.0.0.0/0"

    def test_valid_ipv6(self, validator):
        assert validator.validate_target("::1") == "::1"
        assert validator.validate_target("2001:db8::1") == "2001:db8::1"
        assert validator.validate_target("fe80::1") == "fe80::1"

    def test_valid_ipv6_cidr(self, validator):
        assert validator.validate_target("2001:db8::/32") == "2001:db8::/32"

    def test_valid_hostname(self, validator):
        assert validator.validate_target("example.com") == "example.com"
        assert validator.validate_target("scanme.nmap.org") == "scanme.nmap.org"
        assert validator.validate_target("my-host.local") == "my-host.local"

    def test_reject_shell_injection(self, validator):
        for bad in [
            "; rm -rf /",
            "$(whoami)",
            "| cat /etc/passwd",
            "`echo pwned`",
            "192.168.1.1; cat /etc/shadow",
        ]:
            with pytest.raises(ValueError, match="dangerous characters"):
                validator.validate_target(bad)

    def test_reject_empty(self, validator):
        with pytest.raises(ValueError, match="Target cannot be empty"):
            validator.validate_target("")


class TestValidatePortRange:
    def test_valid_single_port(self, validator):
        assert validator.validate_port_range("80") == "80"
        assert validator.validate_port_range("443") == "443"
        assert validator.validate_port_range("8080") == "8080"

    def test_valid_range(self, validator):
        assert validator.validate_port_range("1-1024") == "1-1024"
        assert validator.validate_port_range("8000-9000") == "8000-9000"

    def test_valid_multiple(self, validator):
        assert validator.validate_port_range("80,443,8080") == "80,443,8080"
        assert validator.validate_port_range("1-1024,8080,8443") == "1-1024,8080,8443"

    def test_reject_zero_port(self, validator):
        with pytest.raises(ValueError, match="Invalid port"):
            validator.validate_port_range("0")

    def test_reject_too_high(self, validator):
        with pytest.raises(ValueError, match="Invalid port"):
            validator.validate_port_range("65536")

    def test_reject_negative(self, validator):
        with pytest.raises(ValueError, match="Invalid port"):
            validator.validate_port_range("-1")

    def test_reject_non_numeric(self, validator):
        with pytest.raises(ValueError, match="Invalid port"):
            validator.validate_port_range("abc")

    def test_reject_bad_range(self, validator):
        with pytest.raises(ValueError, match="Invalid port"):
            validator.validate_port_range("80-abc")
        with pytest.raises(ValueError, match="Invalid port"):
            validator.validate_port_range("100-50")

    def test_reject_empty(self, validator):
        with pytest.raises(ValueError, match="Port specification cannot be empty"):
            validator.validate_port_range("")


class TestValidateCaptureFilter:
    def test_valid_bpf(self, validator):
        assert validator.validate_capture_filter("tcp port 80") == "tcp port 80"
        assert validator.validate_capture_filter("host 192.168.1.1") == "host 192.168.1.1"
        assert validator.validate_capture_filter("tcp and port 443") == "tcp and port 443"
        assert validator.validate_capture_filter("") == ""
        assert validator.validate_capture_filter("udp") == "udp"
        assert validator.validate_capture_filter("icmp") == "icmp"

    def test_reject_shell_chars(self, validator):
        for bad in [
            "tcp; rm -rf /",
            "port 80 | cat",
            "host $(whoami)",
            "tcp `echo evil`",
            "port 80 &",
        ]:
            with pytest.raises(ValueError, match="shell metacharacters"):
                validator.validate_capture_filter(bad)

    def test_reject_parens(self, validator):
        with pytest.raises(ValueError, match="shell metacharacters"):
            validator.validate_capture_filter("tcp and (port 80 or port 443)")

    def test_reject_too_long(self, validator):
        with pytest.raises(ValueError, match="too long"):
            validator.validate_capture_filter("a" * 257)


class TestValidateDisplayFilter:
    def test_valid_filters(self, validator):
        assert validator.validate_display_filter("http") == "http"
        assert validator.validate_display_filter("ip.addr == 192.168.1.1") == "ip.addr == 192.168.1.1"
        assert validator.validate_display_filter("tcp.port == 80") == "tcp.port == 80"
        assert validator.validate_display_filter("") == ""

    def test_reject_shell_chars(self, validator):
        for bad in ["http; evil", "tcp | cat", "$(whoami)"]:
            with pytest.raises(ValueError, match="shell metacharacters"):
                validator.validate_display_filter(bad)

    def test_reject_too_long(self, validator):
        with pytest.raises(ValueError, match="too long"):
            validator.validate_display_filter("a" * 513)


class TestSanitizeFilepath:
    def test_valid_absolute(self, validator, tmp_path):
        pcap = tmp_path / "capture.pcap"
        pcap.write_bytes(b"fake pcap data")
        result = validator.sanitize_filepath(str(pcap))
        assert result == pcap.resolve()

    def test_valid_pcapng(self, validator, tmp_path):
        f = tmp_path / "capture.pcapng"
        f.write_bytes(b"fake pcapng data")
        result = validator.sanitize_filepath(str(f))
        assert result == f.resolve()

    def test_valid_cap(self, validator, tmp_path):
        f = tmp_path / "capture.cap"
        f.write_bytes(b"fake cap data")
        result = validator.sanitize_filepath(str(f))
        assert result == f.resolve()

    def test_valid_relative(self, validator, tmp_path, monkeypatch):
        # Create file in tmp_path and monkeypatch cwd
        f = tmp_path / "test.pcap"
        f.write_bytes(b"fake")
        monkeypatch.chdir(tmp_path)
        result = validator.sanitize_filepath("test.pcap")
        assert result == f.resolve()

    def test_reject_path_traversal(self, validator):
        with pytest.raises(ValueError, match="Path traversal"):
            validator.sanitize_filepath("../../../etc/passwd")

    def test_reject_wrong_extension(self, validator, tmp_path):
        f = tmp_path / "file.txt"
        f.write_bytes(b"fake")
        with pytest.raises(ValueError, match="Invalid file extension"):
            validator.sanitize_filepath(str(f))

    def test_reject_no_extension(self, validator, tmp_path):
        f = tmp_path / "capture"
        f.write_bytes(b"fake")
        with pytest.raises(ValueError, match="Invalid file extension"):
            validator.sanitize_filepath(str(f))

    def test_reject_file_not_found(self, validator):
        with pytest.raises(ValueError, match="File does not exist"):
            validator.sanitize_filepath("/nonexistent/file.pcap")

    def test_reject_file_too_large(self, validator, tmp_path):
        f = tmp_path / "large.pcap"
        f.write_bytes(b"x" * (100 * 1024 * 1024 + 1))  # > 100MB
        with pytest.raises(ValueError, match="too large"):
            validator.sanitize_filepath(str(f))


class TestCheckRateLimit:
    def test_allows_within_limit(self, validator):
        for i in range(10):
            assert validator.check_rate_limit("nmap_scan") is True

    def test_blocks_over_limit(self, validator):
        for i in range(10):
            validator.check_rate_limit("nmap_scan")
        assert validator.check_rate_limit("nmap_scan") is False

    def test_different_operations_independent(self, validator):
        for i in range(10):
            validator.check_rate_limit("scan_a")
        # scan_b should still be allowed
        assert validator.check_rate_limit("scan_b") is True

    def test_sliding_window(self, validator):
        # Fill up limit
        for i in range(10):
            validator.check_rate_limit("test_op")
        # Should be blocked
        assert validator.check_rate_limit("test_op") is False

        # Manually expire old entries by clearing
        validator._rate_limit_history.clear()
        # Should be allowed again
        assert validator.check_rate_limit("test_op") is True

    def test_custom_limit(self, validator):
        for i in range(3):
            assert validator.check_rate_limit("limited", max_ops=3, window_seconds=60) is True
        assert validator.check_rate_limit("limited", max_ops=3, window_seconds=60) is False


class TestIsPrivileged:
    @patch("os.getuid", return_value=0)
    def test_root_is_privileged(self, mock_uid, validator):
        assert validator.is_privileged() is True

    @patch("os.getuid", return_value=1000)
    def test_non_root_is_not_privileged(self, mock_uid, validator):
        assert validator.is_privileged() is False
