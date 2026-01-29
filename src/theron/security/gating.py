"""Source-based action gating for Theron.

Applies security policy based on (action risk x source trust).
Includes composite risk scoring from multiple intelligence signals.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from ..config import TheronConfig, get_config
from .classifier import RiskTier, ToolCall, ToolClassification
from .tagger import SourceTag


class GateAction(str, Enum):
    """Actions the gate can take."""

    ALLOW = "allow"
    LOG = "log"
    SANDBOX = "sandbox"  # Run in isolated container, await user approval
    BLOCK = "block"


@dataclass
class RiskFactors:
    """Breakdown of risk factors contributing to decision."""

    base_tier: int = 1
    threat_score: float = 0.0
    chain_risk: float = 0.0
    anomaly_score: float = 0.0
    hijack_drift: float = 0.0
    taint_influence: int = 0
    exfiltration_risk: bool = False
    honeypot_triggered: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "base_tier": self.base_tier,
            "threat_score": self.threat_score,
            "chain_risk": round(self.chain_risk, 3),
            "anomaly_score": round(self.anomaly_score, 3),
            "hijack_drift": round(self.hijack_drift, 3),
            "taint_influence": self.taint_influence,
            "exfiltration_risk": self.exfiltration_risk,
            "honeypot_triggered": self.honeypot_triggered,
        }


@dataclass
class GateDecision:
    """Result of a gating decision."""

    action: GateAction
    tool_call: ToolCall
    classification: ToolClassification
    source_tag: SourceTag
    reason: str
    block_message: Optional[str] = None
    sandbox_id: Optional[str] = None  # ID for sandbox execution tracking
    risk_factors: Optional[RiskFactors] = None
    alerts: list[str] = field(default_factory=list)  # Alert IDs triggered


# Default policy matrix: source_tag -> {risk_tier -> action}
# SANDBOX is used for sensitive/critical actions from untrusted sources
# This allows running in an isolated environment before user approval
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
        RiskTier.CRITICAL: GateAction.SANDBOX,  # Sandbox instead of block
    },
    SourceTag.CONTENT_READ: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.LOG,
        RiskTier.SENSITIVE: GateAction.SANDBOX,  # Sandbox instead of block
        RiskTier.CRITICAL: GateAction.SANDBOX,   # Sandbox instead of block
    },
    SourceTag.TOOL_RESULT: {
        RiskTier.SAFE: GateAction.ALLOW,
        RiskTier.MODERATE: GateAction.LOG,
        RiskTier.SENSITIVE: GateAction.SANDBOX,  # Sandbox instead of block
        RiskTier.CRITICAL: GateAction.SANDBOX,   # Sandbox instead of block
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
        elif action == GateAction.SANDBOX:
            import uuid
            decision.sandbox_id = str(uuid.uuid4())
            decision.block_message = self._generate_sandbox_message(
                tool_call, classification, source_tag, decision.reason, decision.sandbox_id
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

    def _generate_sandbox_message(
        self,
        tool_call: ToolCall,
        classification: ToolClassification,
        source_tag: SourceTag,
        reason: str,
        sandbox_id: str,
    ) -> str:
        """Generate a message for sandboxed actions."""
        args_str = str(tool_call.arguments)
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."

        return f"""[Theron Security] Action sent to sandbox: {tool_call.name}

Reason: {reason}

Details:
- Tool: {tool_call.name}
- Risk Level: Tier {classification.risk_tier.value} ({classification.risk_tier.name})
- Source Trust: {source_tag.value}
- Arguments: {args_str}
- Sandbox ID: {sandbox_id}

The AI attempted to execute a {classification.risk_tier.name.lower()}-risk action based on content
that may not be directly from you. The action will be run in an isolated sandbox.

To approve or reject this action, visit the Theron dashboard at http://localhost:8080
and review the sandbox results in the "Pending Approvals" tab."""

    def filter_response_anthropic(
        self,
        response: dict[str, Any],
        decisions: list[GateDecision],
    ) -> dict[str, Any]:
        """Filter an Anthropic response, removing blocked/sandboxed tool calls.

        Args:
            response: The original API response
            decisions: Gate decisions for each tool call

        Returns:
            Modified response with blocked/sandboxed calls removed/replaced
        """
        # Both BLOCK and SANDBOX actions need to be filtered from response
        filtered_decisions = [
            d for d in decisions if d.action in (GateAction.BLOCK, GateAction.SANDBOX)
        ]
        if not filtered_decisions:
            return response

        # Build set of filtered tool call IDs
        filtered_ids = {d.tool_call.call_id for d in filtered_decisions if d.tool_call.call_id}

        # Filter content blocks
        new_content = []
        for block in response.get("content", []):
            if isinstance(block, dict):
                if block.get("type") == "tool_use":
                    if block.get("id") in filtered_ids:
                        # Replace with text explaining the block/sandbox
                        decision = next(
                            d for d in filtered_decisions if d.tool_call.call_id == block.get("id")
                        )
                        new_content.append({
                            "type": "text",
                            "text": decision.block_message,
                        })
                        continue
                new_content.append(block)
            else:
                new_content.append(block)

        # If all content was filtered, add explanation
        if not new_content:
            new_content.append({
                "type": "text",
                "text": filtered_decisions[0].block_message,
            })

        modified = response.copy()
        modified["content"] = new_content

        # Update stop_reason if we blocked/sandboxed tool use
        if filtered_ids and modified.get("stop_reason") == "tool_use":
            modified["stop_reason"] = "end_turn"

        return modified

    def filter_response_openai(
        self,
        response: dict[str, Any],
        decisions: list[GateDecision],
    ) -> dict[str, Any]:
        """Filter an OpenAI response, removing blocked/sandboxed tool calls.

        Args:
            response: The original API response
            decisions: Gate decisions for each tool call

        Returns:
            Modified response with blocked/sandboxed calls removed/replaced
        """
        # Both BLOCK and SANDBOX actions need to be filtered from response
        filtered_decisions = [
            d for d in decisions if d.action in (GateAction.BLOCK, GateAction.SANDBOX)
        ]
        if not filtered_decisions:
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
            for d in filtered_decisions:
                if d.tool_call.name == func_name:
                    # Replace function_call with content
                    message.pop("function_call", None)
                    message["content"] = d.block_message
                    choice["finish_reason"] = "stop"
                    break

        # Handle tool_calls
        if message.get("tool_calls"):
            filtered_ids = {d.tool_call.call_id for d in filtered_decisions if d.tool_call.call_id}
            new_tool_calls = []
            filtered_messages = []

            for tc in message["tool_calls"]:
                if tc.get("id") in filtered_ids:
                    decision = next(d for d in filtered_decisions if d.tool_call.call_id == tc.get("id"))
                    filtered_messages.append(decision.block_message)
                else:
                    new_tool_calls.append(tc)

            message["tool_calls"] = new_tool_calls if new_tool_calls else None

            # Add filtered messages to content
            if filtered_messages:
                existing_content = message.get("content") or ""
                message["content"] = existing_content + "\n\n" + "\n\n".join(filtered_messages)

            if not new_tool_calls:
                choice["finish_reason"] = "stop"

        choice["message"] = message
        modified["choices"] = [choice]
        return modified


class EnhancedActionGate(ActionGate):
    """Enhanced action gate with composite risk scoring from intelligence modules."""

    def __init__(
        self,
        config: Optional[TheronConfig] = None,
        causal_tracker=None,
        exfil_detector=None,
        hijack_detector=None,
        anomaly_scorer=None,
        honeypot_mgr=None,
        taint_tracker=None,
    ):
        """Initialize enhanced gate with intelligence modules.

        Args:
            config: Optional TheronConfig
            causal_tracker: CausalTracker instance
            exfil_detector: ExfiltrationDetector instance
            hijack_detector: HijackDetector instance
            anomaly_scorer: AnomalyScorer instance
            honeypot_mgr: HoneypotManager instance
            taint_tracker: TaintTracker instance
        """
        super().__init__(config)
        self.causal_tracker = causal_tracker
        self.exfil_detector = exfil_detector
        self.hijack_detector = hijack_detector
        self.anomaly_scorer = anomaly_scorer
        self.honeypot_mgr = honeypot_mgr
        self.taint_tracker = taint_tracker

    def evaluate_enhanced(
        self,
        tool_call: ToolCall,
        classification: ToolClassification,
        source_tag: SourceTag,
        threat_score: int = 0,
        request_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> GateDecision:
        """Evaluate with composite risk scoring from all intelligence signals.

        Args:
            tool_call: The tool call to evaluate
            classification: The risk classification of the tool
            source_tag: The trust level of the source
            threat_score: Threat score from injection detection
            request_id: Request identifier for intelligence lookups
            agent_id: Agent identifier for behavioral analysis

        Returns:
            GateDecision with comprehensive risk analysis
        """
        import uuid

        alerts: list[str] = []
        risk_factors = RiskFactors(
            base_tier=classification.risk_tier.value,
            threat_score=float(threat_score),
        )

        # 1. Check honeypot use (immediate block if triggered)
        if self.honeypot_mgr:
            honeypot_alert = self.honeypot_mgr.check_for_honeypot_use(
                tool_call.name, tool_call.arguments
            )
            if honeypot_alert:
                risk_factors.honeypot_triggered = True
                alerts.append(honeypot_alert.alert_id)
                return GateDecision(
                    action=GateAction.BLOCK,
                    tool_call=tool_call,
                    classification=classification,
                    source_tag=source_tag,
                    reason="HONEYPOT_TRIGGERED: Agent attempted to use canary credential",
                    block_message=self._generate_honeypot_block_message(
                        tool_call, honeypot_alert
                    ),
                    risk_factors=risk_factors,
                    alerts=alerts,
                )

        # 2. Check exfiltration (immediate block if detected)
        if self.exfil_detector and request_id:
            exfil_alert = self.exfil_detector.check_outbound_action(
                request_id, tool_call.name, tool_call.arguments
            )
            if exfil_alert:
                risk_factors.exfiltration_risk = True
                alerts.append(exfil_alert.alert_id)
                return GateDecision(
                    action=GateAction.BLOCK,
                    tool_call=tool_call,
                    classification=classification,
                    source_tag=source_tag,
                    reason=f"EXFILTRATION_DETECTED: Sensitive data ({exfil_alert.sensitive_type}) flowing to {tool_call.name}",
                    block_message=self._generate_exfil_block_message(
                        tool_call, exfil_alert
                    ),
                    risk_factors=risk_factors,
                    alerts=alerts,
                )

        # 3. Get causal chain context
        if self.causal_tracker and request_id:
            chain = self.causal_tracker.get_chain(request_id)
            if chain:
                risk_factors.chain_risk = self.causal_tracker.calculate_chain_risk(
                    self.causal_tracker._current_chains.get(request_id, [])
                )

        # 4. Check intent drift / hijack
        if self.hijack_detector and request_id:
            hijack_alert = self.hijack_detector.check_tool_alignment(
                request_id, tool_call.name, tool_call.arguments
            )
            if hijack_alert:
                risk_factors.hijack_drift = hijack_alert.drift_score
                alerts.append(hijack_alert.alert_id)

        # 5. Get anomaly score
        if self.anomaly_scorer and agent_id:
            from datetime import datetime
            anomaly = self.anomaly_scorer.score_action(
                agent_id,
                tool_call.name,
                classification.risk_tier.value,
                datetime.utcnow().hour,
                threat_score,
                source_tag.value,
            )
            risk_factors.anomaly_score = anomaly.score

        # 6. Check taint influence
        if self.taint_tracker and request_id:
            propagations = self.taint_tracker.check_taint_influence(
                request_id, tool_call.name, tool_call.arguments
            )
            risk_factors.taint_influence = len(propagations)

        # 7. Calculate composite risk score
        composite_risk = self._calculate_composite_risk(risk_factors, threat_score)

        # 8. Determine action based on composite risk
        action = self._determine_action(
            source_tag, classification.risk_tier, composite_risk, risk_factors
        )

        # Build decision
        reason = self._build_reason(action, risk_factors, composite_risk)

        decision = GateDecision(
            action=action,
            tool_call=tool_call,
            classification=classification,
            source_tag=source_tag,
            reason=reason,
            risk_factors=risk_factors,
            alerts=alerts,
        )

        if action == GateAction.BLOCK:
            decision.block_message = self._generate_enhanced_block_message(
                tool_call, classification, source_tag, reason, risk_factors
            )
        elif action == GateAction.SANDBOX:
            decision.sandbox_id = str(uuid.uuid4())
            decision.block_message = self._generate_enhanced_sandbox_message(
                tool_call, classification, source_tag, reason,
                decision.sandbox_id, risk_factors
            )

        return decision

    def _calculate_composite_risk(
        self,
        factors: RiskFactors,
        threat_score: int,
    ) -> float:
        """Calculate composite risk score from all factors.

        Args:
            factors: RiskFactors breakdown
            threat_score: Raw threat score

        Returns:
            Composite risk score (0.0 to 1.0)
        """
        # Weights for each factor
        weights = {
            "base_tier": 0.25,
            "threat_score": 0.20,
            "chain_risk": 0.15,
            "anomaly_score": 0.15,
            "hijack_drift": 0.15,
            "taint_influence": 0.10,
        }

        # Normalize factors to 0-1 range
        normalized = {
            "base_tier": (factors.base_tier - 1) / 3.0,  # Tier 1-4 -> 0-1
            "threat_score": min(threat_score / 100.0, 1.0),
            "chain_risk": factors.chain_risk,
            "anomaly_score": factors.anomaly_score,
            "hijack_drift": factors.hijack_drift,
            "taint_influence": min(factors.taint_influence / 5.0, 1.0),
        }

        # Calculate weighted sum
        composite = sum(
            normalized[key] * weights[key]
            for key in weights
        )

        return min(composite, 1.0)

    def _determine_action(
        self,
        source_tag: SourceTag,
        risk_tier: RiskTier,
        composite_risk: float,
        factors: RiskFactors,
    ) -> GateAction:
        """Determine action based on composite risk.

        Args:
            source_tag: Source trust level
            risk_tier: Base risk tier
            composite_risk: Calculated composite risk
            factors: Risk factors breakdown

        Returns:
            GateAction to take
        """
        # Critical immediate blocks
        if factors.honeypot_triggered or factors.exfiltration_risk:
            return GateAction.BLOCK

        # High composite risk with significant hijack drift
        if composite_risk >= 0.7 and factors.hijack_drift >= 0.6:
            return GateAction.BLOCK

        # Very high composite risk
        if composite_risk >= 0.8:
            return GateAction.SANDBOX

        # High risk with taint influence
        if composite_risk >= 0.6 and factors.taint_influence >= 2:
            return GateAction.SANDBOX

        # Fall back to base policy matrix
        source_policy = self._policy.get(source_tag, self._policy[SourceTag.CONTENT_READ])
        base_action = source_policy.get(risk_tier, GateAction.BLOCK)

        # Escalate if composite risk is significantly higher than base tier would suggest
        if composite_risk >= 0.5 and base_action == GateAction.ALLOW:
            return GateAction.LOG
        if composite_risk >= 0.6 and base_action == GateAction.LOG:
            return GateAction.SANDBOX

        return base_action

    def _build_reason(
        self,
        action: GateAction,
        factors: RiskFactors,
        composite_risk: float,
    ) -> str:
        """Build explanation for the decision.

        Args:
            action: Action being taken
            factors: Risk factors
            composite_risk: Composite risk score

        Returns:
            Human-readable reason
        """
        parts = [f"Composite risk: {composite_risk:.2f}"]

        if factors.honeypot_triggered:
            parts.append("HONEYPOT TRIGGERED")
        if factors.exfiltration_risk:
            parts.append("EXFILTRATION DETECTED")
        if factors.hijack_drift >= 0.5:
            parts.append(f"Intent drift: {factors.hijack_drift:.2f}")
        if factors.anomaly_score >= 0.5:
            parts.append(f"Anomaly: {factors.anomaly_score:.2f}")
        if factors.taint_influence >= 2:
            parts.append(f"Taint influence: {factors.taint_influence}")
        if factors.chain_risk >= 0.5:
            parts.append(f"Chain risk: {factors.chain_risk:.2f}")

        return " | ".join(parts)

    def _generate_honeypot_block_message(self, tool_call: ToolCall, alert) -> str:
        """Generate block message for honeypot trigger."""
        return f"""[Theron Security] CRITICAL: Honeypot Triggered

The AI agent attempted to use a canary credential that was injected as a security trap.
This indicates the agent may be compromised or manipulated.

Tool: {tool_call.name}
Honeypot Type: {alert.honeypot_type}
Alert ID: {alert.alert_id}

This action has been BLOCKED. Review the agent's recent activity in the Theron dashboard."""

    def _generate_exfil_block_message(self, tool_call: ToolCall, alert) -> str:
        """Generate block message for exfiltration detection."""
        return f"""[Theron Security] CRITICAL: Data Exfiltration Detected

The AI agent attempted to send sensitive data to an external destination.

Tool: {tool_call.name}
Sensitive Data Type: {alert.sensitive_type}
Data Source: {alert.source}
Severity: {alert.severity}

This action has been BLOCKED to prevent data leakage."""

    def _generate_enhanced_block_message(
        self,
        tool_call: ToolCall,
        classification: ToolClassification,
        source_tag: SourceTag,
        reason: str,
        factors: RiskFactors,
    ) -> str:
        """Generate enhanced block message with risk factors."""
        args_str = str(tool_call.arguments)
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."

        risk_breakdown = []
        if factors.chain_risk > 0:
            risk_breakdown.append(f"  - Causal chain risk: {factors.chain_risk:.2f}")
        if factors.anomaly_score > 0:
            risk_breakdown.append(f"  - Anomaly score: {factors.anomaly_score:.2f}")
        if factors.hijack_drift > 0:
            risk_breakdown.append(f"  - Intent drift: {factors.hijack_drift:.2f}")
        if factors.taint_influence > 0:
            risk_breakdown.append(f"  - Taint influence: {factors.taint_influence} propagations")

        risk_section = "\n".join(risk_breakdown) if risk_breakdown else "  - Base policy violation"

        return f"""[Theron Security] Blocked action: {tool_call.name}

Reason: {reason}

Risk Analysis:
{risk_section}

Details:
- Tool: {tool_call.name}
- Risk Level: Tier {classification.risk_tier.value} ({classification.risk_tier.name})
- Source Trust: {source_tag.value}
- Arguments: {args_str}

This action was blocked based on composite risk analysis from multiple intelligence signals."""

    def _generate_enhanced_sandbox_message(
        self,
        tool_call: ToolCall,
        classification: ToolClassification,
        source_tag: SourceTag,
        reason: str,
        sandbox_id: str,
        factors: RiskFactors,
    ) -> str:
        """Generate enhanced sandbox message with risk factors."""
        args_str = str(tool_call.arguments)
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."

        return f"""[Theron Security] Action sent to sandbox: {tool_call.name}

Reason: {reason}

Details:
- Tool: {tool_call.name}
- Risk Level: Tier {classification.risk_tier.value} ({classification.risk_tier.name})
- Source Trust: {source_tag.value}
- Arguments: {args_str}
- Sandbox ID: {sandbox_id}

Risk Factors:
- Base tier: {factors.base_tier}
- Chain risk: {factors.chain_risk:.2f}
- Anomaly score: {factors.anomaly_score:.2f}
- Taint influence: {factors.taint_influence}

The action will be run in an isolated sandbox. Review at http://localhost:8080"""
