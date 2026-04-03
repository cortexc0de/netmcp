"""Extended tests for workflow prompts added in Gap 1."""

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


class TestSecurityAuditPrompt:
    @pytest.mark.asyncio
    async def test_prompt_exists(self, mcp_with_prompts):
        assert "security_audit" in mcp_with_prompts._prompt_manager._prompts

    @pytest.mark.asyncio
    async def test_returns_string(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("security_audit", {})
        text = _get_text(result)
        assert isinstance(text, str) and len(text) > 0

    @pytest.mark.asyncio
    async def test_contains_keywords(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("security_audit", {})
        text = _get_text(result)
        assert "analyze_pcap" in text
        assert "extract_credentials" in text
        assert "analyze_tls_handshake" in text
        assert "analyze_dns_traffic" in text
        assert "check_threat_intelligence" in text
        assert "generate_report" in text


class TestNetworkTroubleshootingPrompt:
    @pytest.mark.asyncio
    async def test_prompt_exists(self, mcp_with_prompts):
        assert "network_troubleshooting" in mcp_with_prompts._prompt_manager._prompts

    @pytest.mark.asyncio
    async def test_returns_string(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("network_troubleshooting", {})
        text = _get_text(result)
        assert isinstance(text, str) and len(text) > 0

    @pytest.mark.asyncio
    async def test_contains_keywords(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("network_troubleshooting", {})
        text = _get_text(result)
        assert "quick_capture" in text
        assert "get_protocol_hierarchy" in text
        assert "visualize_network_flows" in text
        assert "analyze_dns_traffic" in text
        assert "analyze_http_traffic" in text
        assert "get_conversation_stats" in text


class TestIncidentResponsePrompt:
    @pytest.mark.asyncio
    async def test_prompt_exists(self, mcp_with_prompts):
        assert "incident_response" in mcp_with_prompts._prompt_manager._prompts

    @pytest.mark.asyncio
    async def test_returns_string(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("incident_response", {})
        text = _get_text(result)
        assert isinstance(text, str) and len(text) > 0

    @pytest.mark.asyncio
    async def test_contains_keywords(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("incident_response", {})
        text = _get_text(result)
        assert "get_capture_info" in text
        assert "check_threat_intelligence" in text
        assert "deep_packet_analysis" in text
        assert "follow_tcp_stream" in text
        assert "extract_objects" in text
        assert "generate_report" in text


class TestTrafficAnalysisPrompt:
    @pytest.mark.asyncio
    async def test_prompt_exists(self, mcp_with_prompts):
        assert "traffic_analysis" in mcp_with_prompts._prompt_manager._prompts

    @pytest.mark.asyncio
    async def test_returns_string(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("traffic_analysis", {})
        text = _get_text(result)
        assert isinstance(text, str) and len(text) > 0

    @pytest.mark.asyncio
    async def test_contains_keywords(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("traffic_analysis", {})
        text = _get_text(result)
        assert "analyze_pcap" in text
        assert "get_protocol_hierarchy" in text
        assert "get_io_statistics" in text
        assert "visualize_network_flows" in text
        assert "check_threat_intelligence" in text


class TestCredentialAnalysisPrompt:
    @pytest.mark.asyncio
    async def test_prompt_exists(self, mcp_with_prompts):
        assert "credential_analysis" in mcp_with_prompts._prompt_manager._prompts

    @pytest.mark.asyncio
    async def test_returns_string(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("credential_analysis", {})
        text = _get_text(result)
        assert isinstance(text, str) and len(text) > 0

    @pytest.mark.asyncio
    async def test_contains_keywords(self, mcp_with_prompts):
        result = await mcp_with_prompts._prompt_manager.render_prompt("credential_analysis", {})
        text = _get_text(result)
        assert "extract_credentials" in text
        assert "analyze_tls_handshake" in text
        assert "analyze_http_traffic" in text
        assert "check_threat_intelligence" in text
