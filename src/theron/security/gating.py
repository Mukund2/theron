"""Source-based action gating for Theron.

Applies security policy based on (action risk x source trust).
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ..config import TheronConfig, get_config
from .classifier import RiskTier, ToolCall, ToolClassification
from .tagger import SourceTag


class GateAction(str, Enum):
    """Actions the gate can take."""

    ALLOW = "allow"
    LOG = "log"
    BLOCK = "block"


@dataclass
class GateDecision:
    """Result of a gating decision."""

    action: GateAction
    tool_call: ToolCall
    classification: ToolClassification
    source_tag: SourceTag
    reason: str
    block_message: Optional[str] = None


# Default policy matrix: source_tag -> {risk_tier -> action}
DEFAULT_POLICY: dict[SourceTag, dict[RiskTier, GateAction]] = {
    SourceTag.USER_DIRECT: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.ALLOW,
        RiskTier.SENSITIVE: GateAction.ALLOW,
        RiskTier.CRITICAL: GateAction.LOG,
    },
    SourceTag.USER_INDIRECT: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.ALLOW,
        RiskTier.SENSITIVE: GateAction.LOG,
        RiskTier.CRITICAL: GateAction.BLOCK,
    },
    SourceTag.CONTENT_READ: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.LOG,
        RiskTier.SENSITIVE: GateAction.BLOCK,
        RiskTier.CRITICAL: GateAction.BLOCK,
    },
    SourceTag.TOOL_RESULT: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.LOG,
        RiskTier.SENSITIVE: GateAction.BLOCK,
        RiskTier.CRITICAL: GateAction.BLOCK,
    },
    SourceTag.SYSTEM: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.ALLOW,
        RiskTier.SENSITIVE: GateAction.ALLOW,
        RiskTier.CRITICAL: GateAction.ALLOW,
    },
}


class ActionGate:
    """Applies security policy to tool calls based on source trust."""

    def __init__(self, config: Optional[TheronConfig] = None):
        """Initialize the gate.

        Args:
            config: Optional TheronConfig. If not provided, loads from file.
        """
        self.config = config or get_config()
        self._policy = DEFAULT_POLICY.copy()

    def evaluate(
        self,
        tool_call: ToolCall,
        classification: ToolClassification,
        source_tag: SourceTag,
        threat_score: int = 0,
    ) -> GateDecision:
        """Evaluate whether a tool call should be allowed.

        Args:
            tool_call: The tool call to evaluate
            classification: The risk classification of the tool
            source_tag: The trust level of the source
            threat_score: Optional threat score from injection detection

        Returns:
            GateDecision with the action to take
        """
        # Check for override in config
        override_key = f"{source_tag.value}:{tool_call.name}"
        if override_key in self.config.gating.overrides:
            override_action = self.config.gating.overrides[override_key]
            return GateDecision(
                action=GateAction(override_action),
                tool_call=tool_call,
                classification=classification,
                source_tag=source_tag,
                reason=f"Config override: {override_key} -> {override_action}",
            )

        # Check whitelist
        if tool_call.name in self.config.gating.whitelist:
            return GateDecision(
                action=GateAction.ALLOW,
                tool_call=tool_call,
                classification=classification,
                source_tag=source_tag,
                reason="Tool is whitelisted",
            )

        # Check blacklist
        if tool_call.name in self.config.gating.blacklist:
            return GateDecision(
                action=GateAction.BLOCK,
                tool_call=tool_call,
                classification=classification,
                source_tag=source_tag,
                reason="Tool is blacklisted",
                block_message=self._generate_block_message(
                    tool_call, classification, source_tag, "Tool is blacklisted"
                ),
            )

        # If high threat score, be more restrictive
        if threat_score >= self.config.detection.injection_threshold:
            if classification.risk_tier >= RiskTier.MODERATE:
                return GateDecision(
                    action=GateAction.BLOCK,
                    tool_call=tool_call,
                    classification=classification,
                    source_tag=source_tag,
                    reason=f"High threat score ({threat_score}) detected in conversation",
                    block_message=self._generate_block_message(
                        tool_call,
                        classification,
                        source_tag,
                        f"Prompt injection detected (threat score: {threat_score})",
                    ),
                )

        # Apply policy matrix
        source_policy = self._policy.get(source_tag, self._policy[SourceTag.CONTENT_READ])
        action = source_policy.get(classification.risk_tier, GateAction.BLOCK)

        decision = GateDecision(
            action=action,
            tool_call=tool_call,
            classification=classification,
            source_tag=source_tag,
            reason=f"Policy: {source_tag.value} + Tier {classification.risk_tier.value} -> {action.value}",
        )

        if action == GateAction.BLOCK:
            decision.block_message = self._generate_block_message(
                tool_call, classification, source_tag, decision.reason
            )

        return decision

    def _generate_block_message(
        self,
        tool_call: ToolCall,
        classification: ToolClassification,
        source_tag: SourceTag,
        reason: str,
    ) -> str:
        """Generate a human-readable block message."""
        # Truncate arguments for display
        args_str = str(tool_call.arguments)
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."

        return f"""[Theron Security] Blocked action: {tool_call.name}

Reason: {reason}

Details:
- Tool: {tool_call.name}
- Risk Level: Tier {classification.risk_tier.value} ({classification.risk_tier.name})
- Source Trust: {source_tag.value}
- Arguments: {args_str}

The AI attempted to execute a {classification.risk_tier.name.lower()}-risk action based on content
that may not be directly from you. This could be a prompt injection attack.

If this was intentional, you can:
1. Run the command directly as a user message
2. Whitelist this specific action in Theron config (~/.theron/config.yaml)
3. Add an override for this source:tool combination"""

    def filter_response_anthropic(
        self,
        response: dict[str, Any],
        decisions: list[GateDecision],
    ) -> dict[str, Any]:
        """Filter an Anthropic response, removing blocked tool calls.

        Args:
            response: The original API response
            decisions: Gate decisions for each tool call

        Returns:
            Modified response with blocked calls removed/replaced
        """
        blocked_decisions = [d for d in decisions if d.action == GateAction.BLOCK]
        if not blocked_decisions:
            return response

        # Build set of blocked tool call IDs
        blocked_ids = {d.tool_call.call_id for d in blocked_decisions if d.tool_call.call_id}

        # Filter content blocks
        new_content = []
        for block in response.get("content", []):
            if isinstance(block, dict):
                if block.get("type") == "tool_use":
                    if block.get("id") in blocked_ids:
                        # Replace with text explaining the block
                        decision = next(
                            d for d in blocked_decisions if d.tool_call.call_id == block.get("id")
                        )
                        new_content.append({
                            "type": "text",
                            "text": decision.block_message,
                        })
                        continue
                new_content.append(block)
            else:
                new_content.append(block)

        # If all content was blocked, add explanation
        if not new_content:
            new_content.append({
                "type": "text",
                "text": blocked_decisions[0].block_message,
            })

        modified = response.copy()
        modified["content"] = new_content

        # Update stop_reason if we blocked tool use
        if blocked_ids and modified.get("stop_reason") == "tool_use":
            modified["stop_reason"] = "end_turn"

        return modified

    def filter_response_openai(
        self,
        response: dict[str, Any],
        decisions: list[GateDecision],
    ) -> dict[str, Any]:
        """Filter an OpenAI response, removing blocked tool calls.

        Args:
            response: The original API response
            decisions: Gate decisions for each tool call

        Returns:
            Modified response with blocked calls removed/replaced
        """
        blocked_decisions = [d for d in decisions if d.action == GateAction.BLOCK]
        if not blocked_decisions:
            return response

        modified = response.copy()
        choices = modified.get("choices", [])
        if not choices:
            return modified

        choice = choices[0].copy()
        message = choice.get("message", {}).copy()

        # Handle function_call
        if message.get("function_call"):
            func_name = message["function_call"].get("name")
            for d in blocked_decisions:
                if d.tool_call.name == func_name:
                    # Replace function_call with content
                    message.pop("function_call", None)
                    message["content"] = d.block_message
                    choice["finish_reason"] = "stop"
                    break

        # Handle tool_calls
        if message.get("tool_calls"):
            blocked_ids = {d.tool_call.call_id for d in blocked_decisions if d.tool_call.call_id}
            new_tool_calls = []
            blocked_messages = []

            for tc in message["tool_calls"]:
                if tc.get("id") in blocked_ids:
                    decision = next(d for d in blocked_decisions if d.tool_call.call_id == tc.get("id"))
                    blocked_messages.append(decision.block_message)
                else:
                    new_tool_calls.append(tc)

            message["tool_calls"] = new_tool_calls if new_tool_calls else None

            # Add blocked messages to content
            if blocked_messages:
                existing_content = message.get("content") or ""
                message["content"] = existing_content + "\n\n" + "\n\n".join(blocked_messages)

            if not new_tool_calls:
                choice["finish_reason"] = "stop"

        choice["message"] = message
        modified["choices"] = [choice]
        return modified
