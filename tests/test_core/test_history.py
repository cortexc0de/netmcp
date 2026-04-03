"""Tests for CaptureHistory."""

import threading

from netmcp.core.history import CaptureHistory


class TestAddEntry:
    def test_add_entry(self):
        h = CaptureHistory()
        h.add("analyze_pcap", "/tmp/test.pcap", "Found 100 packets")
        assert len(h) == 1
        entries = h.get_recent(1)
        assert entries[0].tool_name == "analyze_pcap"
        assert entries[0].file_path == "/tmp/test.pcap"
        assert entries[0].summary == "Found 100 packets"
        assert entries[0].duration == 0.0
        assert entries[0].timestamp > 0

    def test_add_with_duration(self):
        h = CaptureHistory()
        h.add("scan_network", "192.168.1.0/24", "Scan complete", duration=5.3)
        entries = h.get_recent(1)
        assert entries[0].duration == 5.3


class TestMaxEntriesEviction:
    def test_max_entries_eviction(self):
        h = CaptureHistory()
        for i in range(150):
            h.add("tool", f"/path/{i}.pcap", f"summary {i}")
        assert len(h) == 100
        recent = h.get_recent(100)
        assert recent[0].file_path == "/path/50.pcap"
        assert recent[-1].file_path == "/path/149.pcap"


class TestGetRecent:
    def test_get_recent_fewer_than_count(self):
        h = CaptureHistory()
        h.add("t1", "f1", "s1")
        h.add("t2", "f2", "s2")
        entries = h.get_recent(10)
        assert len(entries) == 2

    def test_get_recent_exact(self):
        h = CaptureHistory()
        for i in range(5):
            h.add("tool", f"f{i}", f"s{i}")
        entries = h.get_recent(3)
        assert len(entries) == 3
        assert entries[0].file_path == "f2"
        assert entries[-1].file_path == "f4"

    def test_get_recent_empty(self):
        h = CaptureHistory()
        assert h.get_recent(10) == []


class TestClear:
    def test_clear(self):
        h = CaptureHistory()
        h.add("t", "f", "s")
        h.add("t", "f", "s")
        assert len(h) == 2
        h.clear()
        assert len(h) == 0
        assert h.get_recent(10) == []


class TestLen:
    def test_len_empty(self):
        h = CaptureHistory()
        assert len(h) == 0

    def test_len_after_adds(self):
        h = CaptureHistory()
        h.add("t", "f", "s")
        h.add("t", "f", "s")
        h.add("t", "f", "s")
        assert len(h) == 3


class TestThreadSafety:
    def test_thread_safety(self):
        h = CaptureHistory()
        errors: list[Exception] = []

        def add_entries(start: int, count: int):
            try:
                for i in range(count):
                    h.add("tool", f"f{start + i}", f"s{start + i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_entries, args=(i * 20, 20)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(h) == 100
