"""Tests for workflow prompts — covers register_prompts in workflows.py."""

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
        """security_audit returns Russian workflow text."""
        assert "security_audit" in mcp_with_prompts._prompt_manager._prompts
        result = await mcp_with_prompts._prompt_manager.render_prompt("security_audit", {})
        text = _get_text(result)
        assert "analyze_pcap" in text
        assert "extract_credentials" in text

    @pytest.mark.asyncio
    async def test_network_troubleshooting_prompt(self, mcp_with_prompts):
        """network_troubleshooting returns workflow text."""
        result = await mcp_with_prompts._prompt_manager.render_prompt("network_troubleshooting", {})
        text = _get_text(result)
        assert "quick_capture" in text

    @pytest.mark.asyncio
    async def test_incident_response_prompt(self, mcp_with_prompts):
        """incident_response returns workflow text."""
        result = await mcp_with_prompts._prompt_manager.render_prompt("incident_response", {})
        text = _get_text(result)
        assert "check_threat_intelligence" in text

    @pytest.mark.asyncio
    async def test_traffic_analysis_prompt(self, mcp_with_prompts):
        """traffic_analysis returns workflow text."""
        result = await mcp_with_prompts._prompt_manager.render_prompt("traffic_analysis", {})
        text = _get_text(result)
        assert "analyze_pcap" in text

    @pytest.mark.asyncio
    async def test_network_baseline_prompt(self, mcp_with_prompts):
        """network_baseline still accepts params."""
        result = await mcp_with_prompts._prompt_manager.render_prompt(
            "network_baseline", {"interface": "wlan0", "duration": "30"}
        )
        assert "wlan0" in _get_text(result)
