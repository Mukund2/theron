"""Tests for the action gating."""

import pytest

from theron.config import TheronConfig
from theron.security.classifier import RiskTier, ToolCall, ToolClassification
from theron.security.gating import ActionGate, GateAction
from theron.security.tagger import SourceTag


@pytest.fixture
def gate():
    """Create a gate with default config."""
    config = TheronConfig()
    return ActionGate(config)


def make_tool_call(name: str = "test_tool", args: dict = None) -> ToolCall:
    """Helper to create a tool call."""
    return ToolCall(name=name, arguments=args or {}, call_id="test_id")


def make_classification(
    name: str = "test_tool", tier: RiskTier = RiskTier.SAFE
) -> ToolClassification:
    """Helper to create a classification."""
    return ToolClassification(
        tool_name=name,
        risk_tier=tier,
        confidence=0.9,
        matched_by="test",
        description="Test classification",
    )


class TestPolicyMatrix:
    """Test the policy matrix enforcement."""

    def test_user_direct_allows_safe(self, gate):
        """Test USER_DIRECT allows safe actions."""
        decision = gate.evaluate(
            make_tool_call(),
            make_classification(tier=RiskTier.SAFE),
            SourceTag.USER_DIRECT,
        )
        assert decision.action == GateAction.ALLOW

    def test_user_direct_allows_sensitive(self, gate):
        """Test USER_DIRECT allows sensitive actions."""
        decision = gate.evaluate(
            make_tool_call(),
            make_classification(tier=RiskTier.SENSITIVE),
            SourceTag.USER_DIRECT,
        )
        assert decision.action == GateAction.ALLOW

    def test_user_direct_logs_critical(self, gate):
        """Test USER_DIRECT logs critical actions."""
        decision = gate.evaluate(
            make_tool_call(),
            make_classification(tier=RiskTier.CRITICAL),
            SourceTag.USER_DIRECT,
        )
        assert decision.action == GateAction.LOG

    def test_content_read_sandboxes_sensitive(self, gate):
        """Test CONTENT_READ sandboxes sensitive actions."""
        decision = gate.evaluate(
            make_tool_call("execute_shell"),
            make_classification("execute_shell", RiskTier.SENSITIVE),
            SourceTag.CONTENT_READ,
        )
        assert decision.action == GateAction.SANDBOX
        assert decision.block_message is not None
        assert decision.sandbox_id is not None

    def test_content_read_sandboxes_critical(self, gate):
        """Test CONTENT_READ sandboxes critical actions."""
        decision = gate.evaluate(
            make_tool_call("sudo_execute"),
            make_classification("sudo_execute", RiskTier.CRITICAL),
            SourceTag.CONTENT_READ,
        )
        assert decision.action == GateAction.SANDBOX
        assert decision.sandbox_id is not None

    def test_content_read_allows_safe(self, gate):
        """Test CONTENT_READ allows safe actions."""
        decision = gate.evaluate(
            make_tool_call("get_weather"),
            make_classification("get_weather", RiskTier.SAFE),
            SourceTag.CONTENT_READ,
        )
        assert decision.action == GateAction.ALLOW

    def test_content_read_logs_moderate(self, gate):
        """Test CONTENT_READ logs moderate actions."""
        decision = gate.evaluate(
            make_tool_call("send_email"),
            make_classification("send_email", RiskTier.MODERATE),
            SourceTag.CONTENT_READ,
        )
        assert decision.action == GateAction.LOG

    def test_tool_result_sandboxes_sensitive(self, gate):
        """Test TOOL_RESULT sandboxes sensitive actions."""
        decision = gate.evaluate(
            make_tool_call("run_script"),
            make_classification("run_script", RiskTier.SENSITIVE),
            SourceTag.TOOL_RESULT,
        )
        assert decision.action == GateAction.SANDBOX
        assert decision.sandbox_id is not None


class TestThreatScoreGating:
    """Test threat score based gating."""

    def test_high_threat_score_blocks(self, gate):
        """Test that high threat score causes blocking."""
        decision = gate.evaluate(
            make_tool_call("send_email"),
            make_classification("send_email", RiskTier.MODERATE),
            SourceTag.USER_DIRECT,
            threat_score=85,  # Above threshold
        )
        assert decision.action == GateAction.BLOCK
        assert "threat score" in decision.reason.lower()

    def test_low_threat_score_allows(self, gate):
        """Test that low threat score doesn't affect decision."""
        decision = gate.evaluate(
            make_tool_call("send_email"),
            make_classification("send_email", RiskTier.MODERATE),
            SourceTag.USER_DIRECT,
            threat_score=20,  # Below threshold
        )
        assert decision.action == GateAction.ALLOW


class TestConfigOverrides:
    """Test configuration-based overrides."""

    def test_whitelist_override(self):
        """Test that whitelisted tools are always allowed."""
        config = TheronConfig()
        config.gating.whitelist = ["dangerous_tool"]
        gate = ActionGate(config)

        decision = gate.evaluate(
            make_tool_call("dangerous_tool"),
            make_classification("dangerous_tool", RiskTier.CRITICAL),
            SourceTag.CONTENT_READ,
        )
        assert decision.action == GateAction.ALLOW
        assert "whitelist" in decision.reason.lower()

    def test_blacklist_override(self):
        """Test that blacklisted tools are always blocked."""
        config = TheronConfig()
        config.gating.blacklist = ["safe_tool"]
        gate = ActionGate(config)

        decision = gate.evaluate(
            make_tool_call("safe_tool"),
            make_classification("safe_tool", RiskTier.SAFE),
            SourceTag.USER_DIRECT,
        )
        assert decision.action == GateAction.BLOCK
        assert "blacklist" in decision.reason.lower()

    def test_source_tool_override(self):
        """Test source:tool combination override."""
        config = TheronConfig()
        config.gating.overrides = {"USER_DIRECT:send_email": "block"}
        gate = ActionGate(config)

        decision = gate.evaluate(
            make_tool_call("send_email"),
            make_classification("send_email", RiskTier.MODERATE),
            SourceTag.USER_DIRECT,
        )
        assert decision.action == GateAction.BLOCK
        assert "override" in decision.reason.lower()


class TestResponseFiltering:
    """Test response modification when blocking/sandboxing."""

    def test_filter_anthropic_response_sandbox(self, gate):
        """Test filtering sandboxed tool calls from Anthropic response."""
        response = {
            "content": [
                {"type": "text", "text": "I'll help you."},
                {
                    "type": "tool_use",
                    "id": "sandboxed_id",
                    "name": "execute_shell",
                    "input": {"command": "rm -rf /"},
                },
            ],
            "stop_reason": "tool_use",
        }

        decision = gate.evaluate(
            ToolCall(name="execute_shell", arguments={}, call_id="sandboxed_id"),
            make_classification("execute_shell", RiskTier.SENSITIVE),
            SourceTag.CONTENT_READ,
        )

        # Should be SANDBOX action
        assert decision.action == GateAction.SANDBOX

        filtered = gate.filter_response_anthropic(response, [decision])

        # Tool call should be replaced with sandbox message
        assert len(filtered["content"]) == 2
        assert filtered["content"][1]["type"] == "text"
        assert "Theron Security" in filtered["content"][1]["text"]
        assert "sandbox" in filtered["content"][1]["text"].lower()
        assert filtered["stop_reason"] == "end_turn"

    def test_filter_anthropic_response_block(self, gate):
        """Test filtering blocked tool calls from Anthropic response."""
        # Use blacklist to force a BLOCK instead of SANDBOX
        gate.config.gating.blacklist = ["execute_shell"]

        response = {
            "content": [
                {"type": "text", "text": "I'll help you."},
                {
                    "type": "tool_use",
                    "id": "blocked_id",
                    "name": "execute_shell",
                    "input": {"command": "rm -rf /"},
                },
            ],
            "stop_reason": "tool_use",
        }

        decision = gate.evaluate(
            ToolCall(name="execute_shell", arguments={}, call_id="blocked_id"),
            make_classification("execute_shell", RiskTier.SENSITIVE),
            SourceTag.CONTENT_READ,
        )

        # Should be BLOCK action due to blacklist
        assert decision.action == GateAction.BLOCK

        filtered = gate.filter_response_anthropic(response, [decision])

        # Tool call should be replaced with block message
        assert len(filtered["content"]) == 2
        assert filtered["content"][1]["type"] == "text"
        assert "Theron Security" in filtered["content"][1]["text"]
        assert filtered["stop_reason"] == "end_turn"

    def test_filter_preserves_allowed_tools(self, gate):
        """Test that allowed tool calls are preserved."""
        response = {
            "content": [
                {"type": "tool_use", "id": "1", "name": "get_weather", "input": {}},
                {"type": "tool_use", "id": "2", "name": "execute_shell", "input": {}},
            ],
            "stop_reason": "tool_use",
        }

        decisions = [
            gate.evaluate(
                ToolCall(name="get_weather", arguments={}, call_id="1"),
                make_classification("get_weather", RiskTier.SAFE),
                SourceTag.CONTENT_READ,
            ),
            gate.evaluate(
                ToolCall(name="execute_shell", arguments={}, call_id="2"),
                make_classification("execute_shell", RiskTier.SENSITIVE),
                SourceTag.CONTENT_READ,
            ),
        ]

        filtered = gate.filter_response_anthropic(response, decisions)

        # First tool should still be there, second should be sandboxed
        tool_uses = [c for c in filtered["content"] if c.get("type") == "tool_use"]
        assert len(tool_uses) == 1
        assert tool_uses[0]["name"] == "get_weather"


class TestSandboxAction:
    """Test sandbox action behavior."""

    def test_sandbox_generates_id(self, gate):
        """Test that SANDBOX action generates a unique ID."""
        decision = gate.evaluate(
            make_tool_call("execute_shell"),
            make_classification("execute_shell", RiskTier.SENSITIVE),
            SourceTag.CONTENT_READ,
        )

        assert decision.action == GateAction.SANDBOX
        assert decision.sandbox_id is not None
        assert len(decision.sandbox_id) > 0

    def test_sandbox_message_includes_id(self, gate):
        """Test that sandbox message includes the sandbox ID."""
        decision = gate.evaluate(
            make_tool_call("execute_shell"),
            make_classification("execute_shell", RiskTier.SENSITIVE),
            SourceTag.CONTENT_READ,
        )

        assert decision.sandbox_id in decision.block_message

    def test_user_indirect_critical_sandboxes(self, gate):
        """Test USER_INDIRECT with critical action gets sandboxed."""
        decision = gate.evaluate(
            make_tool_call("sudo_rm"),
            make_classification("sudo_rm", RiskTier.CRITICAL),
            SourceTag.USER_INDIRECT,
        )

        assert decision.action == GateAction.SANDBOX
