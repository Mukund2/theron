"""Tests for the action classifier."""

import pytest

from theron.config import TheronConfig
from theron.security.classifier import ActionClassifier, RiskTier


@pytest.fixture
def classifier():
    """Create a classifier with default config."""
    config = TheronConfig()
    return ActionClassifier(config)


class TestToolClassification:
    """Test tool risk classification."""

    def test_safe_tools(self, classifier):
        """Test classification of safe tools."""
        safe_tools = ["get_weather", "get_time", "read_file", "search_web"]
        for tool in safe_tools:
            result = classifier.classify_tool(tool)
            assert result.risk_tier == RiskTier.SAFE, f"{tool} should be SAFE"

    def test_moderate_tools(self, classifier):
        """Test classification of moderate tools."""
        moderate_tools = ["send_email", "write_file", "post_to_slack"]
        for tool in moderate_tools:
            result = classifier.classify_tool(tool)
            assert result.risk_tier == RiskTier.MODERATE, f"{tool} should be MODERATE"

    def test_sensitive_tools(self, classifier):
        """Test classification of sensitive tools."""
        sensitive_tools = ["execute_shell", "run_script", "delete_file", "bash"]
        for tool in sensitive_tools:
            result = classifier.classify_tool(tool)
            assert result.risk_tier == RiskTier.SENSITIVE, f"{tool} should be SENSITIVE"

    def test_critical_tools(self, classifier):
        """Test classification of critical tools."""
        critical_tools = ["sudo_execute", "transfer_funds", "admin_command"]
        for tool in critical_tools:
            result = classifier.classify_tool(tool)
            assert result.risk_tier == RiskTier.CRITICAL, f"{tool} should be CRITICAL"

    def test_unknown_tools(self, classifier):
        """Test classification of unknown tools."""
        result = classifier.classify_tool("my_custom_unknown_tool")
        # Should default to tier 3 (sensitive) for unknown tools
        assert result.risk_tier == RiskTier.SENSITIVE
        assert result.matched_by == "default"

    def test_pattern_matching(self, classifier):
        """Test pattern-based classification."""
        # Tools starting with get_ should be safe
        result = classifier.classify_tool("get_user_profile")
        assert result.risk_tier == RiskTier.SAFE

        # Tools starting with execute should be sensitive
        result = classifier.classify_tool("execute_query")
        assert result.risk_tier == RiskTier.SENSITIVE


class TestConfigOverrides:
    """Test configuration-based overrides."""

    def test_whitelist(self):
        """Test that whitelisted tools are classified as safe."""
        config = TheronConfig()
        config.gating.whitelist = ["my_dangerous_tool"]
        classifier = ActionClassifier(config)

        result = classifier.classify_tool("my_dangerous_tool")
        assert result.risk_tier == RiskTier.SAFE
        assert result.matched_by == "whitelist"

    def test_blacklist(self):
        """Test that blacklisted tools are classified as critical."""
        config = TheronConfig()
        config.gating.blacklist = ["my_safe_tool"]
        classifier = ActionClassifier(config)

        result = classifier.classify_tool("my_safe_tool")
        assert result.risk_tier == RiskTier.CRITICAL
        assert result.matched_by == "blacklist"

    def test_tool_overrides(self):
        """Test explicit tool tier overrides."""
        config = TheronConfig()
        config.classification.tool_overrides = {"custom_tool": 1}
        classifier = ActionClassifier(config)

        result = classifier.classify_tool("custom_tool")
        assert result.risk_tier == RiskTier.SAFE
        assert result.matched_by == "config_override"


class TestResponseParsing:
    """Test parsing of LLM responses."""

    def test_parse_anthropic_tool_calls(self, classifier):
        """Test parsing Anthropic-style tool calls."""
        response = {
            "content": [
                {"type": "text", "text": "I'll help you with that."},
                {
                    "type": "tool_use",
                    "id": "tool_123",
                    "name": "execute_shell",
                    "input": {"command": "ls -la"},
                },
            ]
        }

        tool_calls = classifier.parse_tool_calls_anthropic(response)
        assert len(tool_calls) == 1
        assert tool_calls[0].name == "execute_shell"
        assert tool_calls[0].arguments == {"command": "ls -la"}
        assert tool_calls[0].call_id == "tool_123"

    def test_parse_openai_tool_calls(self, classifier):
        """Test parsing OpenAI-style tool calls."""
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "send_email",
                                    "arguments": '{"to": "user@example.com"}',
                                },
                            }
                        ]
                    }
                }
            ]
        }

        tool_calls = classifier.parse_tool_calls_openai(response)
        assert len(tool_calls) == 1
        assert tool_calls[0].name == "send_email"
        assert tool_calls[0].arguments == {"to": "user@example.com"}

    def test_parse_empty_response(self, classifier):
        """Test parsing response with no tool calls."""
        response = {"content": [{"type": "text", "text": "Just a text response."}]}
        tool_calls = classifier.parse_tool_calls_anthropic(response)
        assert len(tool_calls) == 0

    def test_classify_response(self, classifier):
        """Test full response classification."""
        response = {
            "content": [
                {"type": "tool_use", "id": "1", "name": "get_weather", "input": {}},
                {"type": "tool_use", "id": "2", "name": "execute_shell", "input": {}},
            ]
        }

        results = classifier.classify_response(response, "anthropic")
        assert len(results) == 2

        # Check classifications
        tiers = [r[1].risk_tier for r in results]
        assert RiskTier.SAFE in tiers
        assert RiskTier.SENSITIVE in tiers
