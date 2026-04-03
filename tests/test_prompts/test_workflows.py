"""Tests for workflow prompts — covers lines 21, 46, 69, 96, 122 in workflows.py."""

import pytest
from mcp.server.fastmcp import FastMCP

from netmcp.prompts.workflows import register_prompts


def _get_text(messages) -> str:
    """Extract text from render_prompt result (list of message objects)."""
    parts = []
    for m in messages:
        content = m.content
        if hasattr(content, "text"):
            parts.append(content.text)
        elif isinstance(content, str):
            parts.append(content)
    return "\n".join(parts)


@pytest.fixture
def mcp_with_prompts():
    mcp = FastMCP("test")
    register_prompts(mcp)
    return mcp


class TestWorkflowPrompts:
    @pytest.mark.asyncio
    async def test_security_audit_prompt(self, mcp_with_prompts):
        """Line 21: security_audit return."""
        assert "security_audit" in mcp_with_prompts._prompt_manager._prompts
        result = await mcp_with_prompts._prompt_manager.render_prompt(
            "security_audit", {"filepath": "/test.pcap"}
        )
        text = _get_text(result)
        assert "security audit" in text.lower()

    @pytest.mark.asyncio
    async def test_network_troubleshooting_prompt(self, mcp_with_prompts):
        """Line 46: network_troubleshooting return."""
        result = await mcp_with_prompts._prompt_manager.render_prompt(
            "network_troubleshooting", {"interface": "eth0", "duration": "10"}
        )
        assert "eth0" in _get_text(result)

    @pytest.mark.asyncio
    async def test_incident_response_prompt(self, mcp_with_prompts):
        """Line 69: incident_response return."""
        result = await mcp_with_prompts._prompt_manager.render_prompt(
            "incident_response", {"target": "10.0.0.1"}
        )
        assert "10.0.0.1" in _get_text(result)

    @pytest.mark.asyncio
    async def test_traffic_analysis_prompt(self, mcp_with_prompts):
        """Line 96: traffic_analysis return."""
        result = await mcp_with_prompts._prompt_manager.render_prompt(
            "traffic_analysis", {"filepath": "/data.pcap"}
        )
        assert "/data.pcap" in _get_text(result)

    @pytest.mark.asyncio
    async def test_network_baseline_prompt(self, mcp_with_prompts):
        """Line 122: network_baseline return."""
        result = await mcp_with_prompts._prompt_manager.render_prompt(
            "network_baseline", {"interface": "wlan0", "duration": "30"}
        )
        assert "wlan0" in _get_text(result)
