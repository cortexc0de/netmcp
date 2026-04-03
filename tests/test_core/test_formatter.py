"""Tests for OutputFormatter."""

import json
import subprocess
from unittest.mock import patch

import pytest

from netmcp.core.formatter import OutputFormatter


@pytest.fixture
def fmt():
    return OutputFormatter()


class TestFormatJson:
    def test_dict(self, fmt):
        data = {"key": "value", "num": 42}
        result = fmt.format_json(data)
        parsed = json.loads(result)
        assert parsed == data

    def test_list(self, fmt):
        data = [1, 2, 3]
        result = fmt.format_json(data)
        assert json.loads(result) == data

    def test_none(self, fmt):
        result = fmt.format_json(None)
        assert json.loads(result) is None

    def test_nested(self, fmt):
        data = {"a": {"b": {"c": [1, 2, {"d": "deep"}]}}}
        result = fmt.format_json(data)
        assert json.loads(result) == data

    def test_empty_containers(self, fmt):
        assert json.loads(fmt.format_json({})) == {}
        assert json.loads(fmt.format_json([])) == []

    def test_non_serializable_raises(self, fmt):
        with pytest.raises(ValueError, match="not JSON serializable"):
            fmt.format_json(set([1, 2, 3]))


class TestFormatText:
    def test_string(self, fmt):
        assert fmt.format_text("hello") == "hello"

    def test_string_with_title(self, fmt):
        result = fmt.format_text("body", "Title")
        assert "Title" in result
        assert "body" in result

    def test_dict_extraction(self, fmt):
        data = {"message": "Success", "status": "ok", "extra": "ignored"}
        result = fmt.format_text(data)
        assert "Success" in result
        assert "ok" in result

    def test_list_formatting(self, fmt):
        data = ["item1", "item2", "item3"]
        result = fmt.format_text(data)
        assert "item1" in result
        assert "item2" in result

    def test_dict_list_formatting(self, fmt):
        data = [
            {"name": "Alice", "role": "admin"},
            {"name": "Bob", "role": "user"},
        ]
        result = fmt.format_text(data)
        assert "Alice" in result
        assert "Bob" in result

    def test_unknown_type(self, fmt):
        result = fmt.format_text(42)
        assert "42" in result


class TestFormatError:
    def test_value_error(self, fmt):
        err = ValueError("bad input")
        result = fmt.format_error(err, "NETMCP_002")
        assert result["isError"] is True
        assert "[NETMCP_002]" in result["content"][0]["text"]
        assert "bad input" in result["content"][0]["text"]

    def test_file_not_found(self, fmt):
        err = FileNotFoundError("no file")
        result = fmt.format_error(err)
        assert "NETMCP_004" in result["content"][0]["text"]

    def test_timeout(self, fmt):
        err = TimeoutError("took too long")
        result = fmt.format_error(err)
        assert "NETMCP_005" in result["content"][0]["text"]

    def test_permission(self, fmt):
        err = PermissionError("access denied")
        result = fmt.format_error(err)
        assert "NETMCP_007" in result["content"][0]["text"]

    def test_called_process_error(self, fmt):
        err = subprocess.CalledProcessError(1, "tshark", "output", "stderr")
        result = fmt.format_error(err)
        assert "NETMCP_003" in result["content"][0]["text"]

    def test_generic_error(self, fmt):
        err = RuntimeError("something broke")
        result = fmt.format_error(err)
        assert result["isError"] is True
        assert "something broke" in result["content"][0]["text"]

    def test_default_code(self, fmt):
        err = Exception("oops")
        result = fmt.format_error(err)
        assert "NETMCP_001" in result["content"][0]["text"]


class TestFormatTable:
    def test_basic_table(self, fmt):
        rows = [
            {"Protocol": "TCP", "Packets": 1500, "Bytes": 204800},
            {"Protocol": "UDP", "Packets": 300, "Bytes": 45000},
        ]
        headers = ["Protocol", "Packets", "Bytes"]
        result = fmt.format_table(rows, headers)
        assert "Protocol" in result
        assert "TCP" in result
        assert "1500" in result
        assert "UDP" in result
        assert "--------" in result  # separator

    def test_empty_rows(self, fmt):
        result = fmt.format_table([], ["Col1", "Col2"])
        assert "Col1" in result
        assert "Col2" in result

    def test_missing_keys(self, fmt):
        rows = [{"A": 1}, {"B": 2}]
        result = fmt.format_table(rows, ["A", "B"])
        assert "-" in result

    def test_single_row(self, fmt):
        rows = [{"X": "val"}]
        result = fmt.format_table(rows, ["X"])
        assert "val" in result


class TestTruncate:
    def test_short_text(self, fmt):
        text = "hello world"
        assert fmt.truncate(text) == text

    def test_long_text(self, fmt):
        text = "x" * 1000
        result = fmt.truncate(text, max_chars=100)
        assert len(result) <= 150  # 100 + truncation suffix
        assert "[truncated" in result.lower() or "truncated" in result

    def test_empty_string(self, fmt):
        assert fmt.truncate("") == ""

    def test_none(self, fmt):
        assert fmt.truncate(None) == ""

    def test_exact_length(self, fmt):
        text = "a" * 10
        result = fmt.truncate(text, max_chars=10)
        assert result == text


class TestFormatSuccess:
    def test_string_result(self, fmt):
        result = fmt.format_success("all good")
        assert result["isError"] is False
        assert "all good" in result["content"][0]["text"]

    def test_dict_result(self, fmt):
        result = fmt.format_success({"status": "ok"})
        assert result["isError"] is False
        assert "status" in result["content"][0]["text"]

    def test_with_title(self, fmt):
        result = fmt.format_success("data", title="Report")
        assert "Report" in result["content"][0]["text"]
