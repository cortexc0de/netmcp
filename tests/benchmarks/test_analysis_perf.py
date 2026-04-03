"""Performance benchmarks for analysis operations."""

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator


class TestSecurityValidationPerf:
    """Benchmark security validation operations."""

    def test_validate_target_ip(self, benchmark):
        sec = SecurityValidator()
        benchmark(sec.validate_target, "192.168.1.1")

    def test_validate_target_cidr(self, benchmark):
        sec = SecurityValidator()
        benchmark(sec.validate_target, "10.0.0.0/24")

    def test_sanitize_filepath(self, benchmark, tmp_path):
        sec = SecurityValidator()
        p = tmp_path / "test.pcap"
        p.write_bytes(b"fake")
        benchmark(sec.sanitize_filepath, str(p))

    def test_validate_display_filter(self, benchmark):
        sec = SecurityValidator()
        benchmark(sec.validate_display_filter, "tcp.port == 80 and ip.addr == 10.0.0.1")

    def test_validate_nmap_arguments(self, benchmark):
        sec = SecurityValidator()
        benchmark(sec.validate_nmap_arguments, "-sT -T4 -p 80,443,8080")

    def test_check_rate_limit(self, benchmark):
        sec = SecurityValidator()

        def rate_check():
            sec._rate_limit_history.clear()
            return sec.check_rate_limit("bench_test", max_ops=1000)

        benchmark(rate_check)


class TestFormatterPerf:
    """Benchmark output formatting."""

    def test_format_success_small(self, benchmark):
        fmt = OutputFormatter()
        data = {"key": "value", "count": 42}
        benchmark(fmt.format_success, data, title="Test")

    def test_format_success_large(self, benchmark):
        fmt = OutputFormatter()
        data = {
            "packets": [
                {"id": i, "src": f"10.0.0.{i % 256}", "dst": "8.8.8.8"} for i in range(1000)
            ],
            "stats": {"total": 1000, "protocols": {"tcp": 500, "udp": 300, "icmp": 200}},
        }
        benchmark(fmt.format_success, data, title="Large")

    def test_format_error(self, benchmark):
        fmt = OutputFormatter()
        err = ValueError("test error")
        benchmark(fmt.format_error, err, "TEST_001")
