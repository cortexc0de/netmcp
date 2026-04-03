"""Performance benchmarks for network operations."""

from netmcp.interfaces.threat_intel import ThreatIntelInterface
from netmcp.interfaces.tshark import TsharkInterface


class TestThreatIntelCachePerf:
    """Benchmark threat intel caching."""

    def test_cache_write(self, benchmark):
        ti = ThreatIntelInterface()
        counter = [0]

        def cache_write():
            counter[0] += 1
            ti._set_cache(f"key_{counter[0]}", {"result": "safe"})

        benchmark(cache_write)

    def test_cache_read_hit(self, benchmark):
        ti = ThreatIntelInterface()
        ti._set_cache("bench_key", {"result": "cached"})
        benchmark(ti._get_cache, "bench_key")

    def test_cache_read_miss(self, benchmark):
        ti = ThreatIntelInterface()
        benchmark(ti._get_cache, "nonexistent_key")


class TestProtocolStatsParserPerf:
    """Benchmark protocol stats parsing."""

    def test_parse_small_output(self, benchmark):
        output = "\n".join([
            "===================================================================",
            "Protocol Hierarchy Statistics",
            "Filter:",
            "",
            "eth                                      frames:1000 bytes:500000",
            "  ip                                     frames:950 bytes:475000",
            "    tcp                                  frames:800 bytes:400000",
            "      http                               frames:200 bytes:100000",
            "    udp                                  frames:150 bytes:75000",
            "      dns                                frames:100 bytes:50000",
            "===================================================================",
        ])
        benchmark(TsharkInterface._parse_protocol_stats, output)

    def test_parse_large_output(self, benchmark):
        lines = [
            "===================================================================",
            "Protocol Hierarchy Statistics",
            "Filter:",
            "",
        ]
        for i in range(200):
            indent = "  " * (i % 5)
            lines.append(f"{indent}proto_{i:<30}  frames:{1000 - i} bytes:{50000 - i * 100}")
        lines.append("===================================================================")
        output = "\n".join(lines)
        benchmark(TsharkInterface._parse_protocol_stats, output)
