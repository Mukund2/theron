"""Action risk classification for Theron.

Categorizes every tool/function call by potential harm.
"""

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional

from ..config import TheronConfig, get_config
from ..patterns import TOOL_TIERS, get_tier_for_tool


class RiskTier(IntEnum):
    """Risk tier levels."""

    SAFE = 1  # get_weather, get_time, read_calendar, search_web
    MODERATE = 2  # send_email, post_message, create_event, write_file
    SENSITIVE = 3  # execute_shell, run_script, delete_file, access_credentials
    CRITICAL = 4  # sudo_*, admin_*, bulk_delete, transfer_funds


@dataclass
class ToolClassification:
    """Classification result for a tool."""

    tool_name: str
    risk_tier: RiskTier
    confidence: float  # 0.0 to 1.0
    matched_by: str  # "exact", "pattern", "default"
    description: str


@dataclass
class ToolCall:
    """Parsed tool call from LLM response."""

    name: str
    arguments: dict[str, Any]
    call_id: Optional[str] = None


class ActionClassifier:
    """Classifies actions/tools by risk level."""

    def __init__(self, config: Optional[TheronConfig] = None):
        """Initialize the classifier.

        Args:
            config: Optional TheronConfig. If not provided, loads from file.
        """
        self.config = config or get_config()
        self._tool_patterns = self._build_tool_patterns()

    def _build_tool_patterns(self) -> dict[int, list[re.Pattern]]:
        """Build regex patterns for tool classification."""
        patterns: dict[int, list[re.Pattern]] = {1: [], 2: [], 3: [], 4: []}

        # Add patterns based on common tool naming conventions
        tier_patterns = {
            1: [r"^get_", r"^read_(?!credential)", r"^list_", r"^search_", r"^fetch_(?!secret)"],
            2: [r"^send_", r"^post_", r"^create_(?!user)", r"^write_", r"^update_"],
            3: [r"^execute", r"^run_", r"^delete_", r"^shell", r"^bash", r"^terminal"],
            4: [r"^sudo", r"^admin", r"^bulk_", r"^transfer_", r"^modify_system"],
        }

        for tier, pats in tier_patterns.items():
            for pat in pats:
                try:
                    patterns[tier].append(re.compile(pat, re.IGNORECASE))
                except re.error:
                    pass

        return patterns

    def classify_tool(self, tool_name: str) -> ToolClassification:
        """Classify a single tool by name.

        Args:
            tool_name: The name of the tool

        Returns:
            ToolClassification with risk tier and details
        """
        normalized = tool_name.lower().replace("-", "_").replace(" ", "_")

        # Check config overrides first
        overrides = self.config.classification.tool_overrides
        if tool_name in overrides or normalized in overrides:
            tier = overrides.get(tool_name) or overrides.get(normalized)
            return ToolClassification(
                tool_name=tool_name,
                risk_tier=RiskTier(tier),
                confidence=1.0,
                matched_by="config_override",
                description=f"Overridden to tier {tier} in config",
            )

        # Check whitelist/blacklist
        if tool_name in self.config.gating.whitelist or normalized in self.config.gating.whitelist:
            return ToolClassification(
                tool_name=tool_name,
                risk_tier=RiskTier.SAFE,
                confidence=1.0,
                matched_by="whitelist",
                description="Whitelisted tool",
            )

        if tool_name in self.config.gating.blacklist or normalized in self.config.gating.blacklist:
            return ToolClassification(
                tool_name=tool_name,
                risk_tier=RiskTier.CRITICAL,
                confidence=1.0,
                matched_by="blacklist",
                description="Blacklisted tool",
            )

        # Check exact matches in TOOL_TIERS
        for tier_name, tools in TOOL_TIERS.items():
            tier_num = int(tier_name.split("_")[1])
            if normalized in tools:
                return ToolClassification(
                    tool_name=tool_name,
                    risk_tier=RiskTier(tier_num),
                    confidence=0.95,
                    matched_by="exact",
                    description=self._get_tier_description(RiskTier(tier_num)),
                )

        # Check pattern matches
        for tier, patterns in self._tool_patterns.items():
            for pattern in patterns:
                if pattern.search(normalized):
                    return ToolClassification(
                        tool_name=tool_name,
                        risk_tier=RiskTier(tier),
                        confidence=0.8,
                        matched_by="pattern",
                        description=self._get_tier_description(RiskTier(tier)),
                    )

        # Check partial matches in TOOL_TIERS
        for tier_name, tools in TOOL_TIERS.items():
            tier_num = int(tier_name.split("_")[1])
            for tool in tools:
                if tool in normalized or normalized in tool:
                    return ToolClassification(
                        tool_name=tool_name,
                        risk_tier=RiskTier(tier_num),
                        confidence=0.7,
                        matched_by="partial",
                        description=self._get_tier_description(RiskTier(tier_num)),
                    )

        # Default to configured unknown tool tier
        default_tier = self.config.classification.unknown_tool_tier
        return ToolClassification(
            tool_name=tool_name,
            risk_tier=RiskTier(default_tier),
            confidence=0.5,
            matched_by="default",
            description=f"Unknown tool, defaulting to tier {default_tier}",
        )

    def _get_tier_description(self, tier: RiskTier) -> str:
        """Get a human-readable description of a risk tier."""
        descriptions = {
            RiskTier.SAFE: "Safe - read-only operations with no side effects",
            RiskTier.MODERATE: "Moderate - creates content or sends communications",
            RiskTier.SENSITIVE: "Sensitive - executes code, modifies files, or accesses credentials",
            RiskTier.CRITICAL: "Critical - system-level operations or financial transactions",
        }
        return descriptions.get(tier, "Unknown risk level")

    def parse_tool_calls_anthropic(self, response: dict[str, Any]) -> list[ToolCall]:
        """Parse tool calls from an Anthropic API response.

        Args:
            response: The API response dict

        Returns:
            List of ToolCall objects
        """
        tool_calls: list[ToolCall] = []

        content = response.get("content", [])
        if not isinstance(content, list):
            return tool_calls

        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        name=block.get("name", "unknown"),
                        arguments=block.get("input", {}),
                        call_id=block.get("id"),
                    )
                )

        return tool_calls

    def parse_tool_calls_openai(self, response: dict[str, Any]) -> list[ToolCall]:
        """Parse tool calls from an OpenAI API response.

        Args:
            response: The API response dict

        Returns:
            List of ToolCall objects
        """
        import json

        tool_calls: list[ToolCall] = []

        choices = response.get("choices", [])
        if not choices:
            return tool_calls

        message = choices[0].get("message", {})

        # Handle function_call (legacy format)
        function_call = message.get("function_call")
        if function_call:
            try:
                args = json.loads(function_call.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(
                ToolCall(
                    name=function_call.get("name", "unknown"),
                    arguments=args,
                )
            )

        # Handle tool_calls (new format)
        calls = message.get("tool_calls", [])
        for call in calls:
            if call.get("type") == "function":
                func = call.get("function", {})
                try:
                    args = json.loads(func.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(
                    ToolCall(
                        name=func.get("name", "unknown"),
                        arguments=args,
                        call_id=call.get("id"),
                    )
                )

        return tool_calls

    def classify_response(
        self, response: dict[str, Any], provider: str
    ) -> list[tuple[ToolCall, ToolClassification]]:
        """Classify all tool calls in an LLM response.

        Args:
            response: The API response dict
            provider: "anthropic" or "openai"

        Returns:
            List of (ToolCall, ToolClassification) tuples
        """
        if provider == "anthropic":
            tool_calls = self.parse_tool_calls_anthropic(response)
        elif provider == "openai":
            tool_calls = self.parse_tool_calls_openai(response)
        else:
            return []

        return [(call, self.classify_tool(call.name)) for call in tool_calls]
