"""Benchmark fixtures for netmcp performance tests."""

import pytest

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator


@pytest.fixture
def security_validator():
    return SecurityValidator()


@pytest.fixture
def formatter():
    return OutputFormatter()
