"""Anomaly detection and scoring for Theron.

Scores how anomalous an action is compared to the agent's behavioral baseline.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .baseline import BaselineManager, AgentProfile


@dataclass
class AnomalyFactor:
    """A single factor contributing to anomaly score."""

    name: str
    score: float  # 0.0 to 1.0
    description: str
    weight: float = 1.0


@dataclass
class AnomalyScore:
    """Result of anomaly scoring."""

    score: float  # 0.0 to 1.0
    has_baseline: bool
    factors: list[AnomalyFactor] = field(default_factory=list)
    is_anomalous: bool = False
    anomaly_threshold: float = 0.5

    @property
    def severity(self) -> str:
        """Get severity level based on score."""
        if self.score >= 0.8:
            return "critical"
        elif self.score >= 0.6:
            return "high"
        elif self.score >= 0.4:
            return "medium"
        elif self.score >= 0.2:
            return "low"
        else:
            return "none"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "score": round(self.score, 3),
            "has_baseline": self.has_baseline,
            "is_anomalous": self.is_anomalous,
            "severity": self.severity,
            "factors": [
                {
                    "name": f.name,
                    "score": round(f.score, 3),
                    "description": f.description,
                    "weight": f.weight,
                }
                for f in self.factors
            ],
        }


class AnomalyScorer:
    """Scores actions for anomalies based on behavioral baselines."""

    def __init__(
        self,
        baseline_mgr: BaselineManager,
        anomaly_threshold: float = 0.5,
    ):
        """Initialize the anomaly scorer.

        Args:
            baseline_mgr: BaselineManager instance for profile access.
            anomaly_threshold: Score threshold for considering something anomalous.
        """
        self.baseline_mgr = baseline_mgr
        self.anomaly_threshold = anomaly_threshold

    def score_action(
        self,
        agent_id: str,
        tool_name: Optional[str] = None,
        risk_tier: int = 1,
        hour: Optional[int] = None,
        threat_score: float = 0.0,
        source_tag: Optional[str] = None,
    ) -> AnomalyScore:
        """Score how anomalous an action is for an agent.

        Args:
            agent_id: Agent identifier
            tool_name: Name of tool being used
            risk_tier: Risk tier of the tool (1-4)
            hour: Hour of day (0-23), defaults to current
            threat_score: Threat score from detection
            source_tag: Source tag of the request

        Returns:
            AnomalyScore with detailed breakdown
        """
        if hour is None:
            hour = datetime.utcnow().hour

        baseline = self.baseline_mgr.get_baseline(agent_id)

        if not baseline:
            # No baseline yet - can't score anomalies
            return AnomalyScore(
                score=0.0,
                has_baseline=False,
                is_anomalous=False,
                anomaly_threshold=self.anomaly_threshold,
            )

        factors = []

        # Factor 1: Tool frequency anomaly
        if tool_name:
            tool_factor = self._score_tool_frequency(baseline, tool_name)
            factors.append(tool_factor)

        # Factor 2: Time of day anomaly
        time_factor = self._score_time_of_day(baseline, hour)
        factors.append(time_factor)

        # Factor 3: Risk tier anomaly
        tier_factor = self._score_risk_tier(baseline, risk_tier)
        factors.append(tier_factor)

        # Factor 4: Threat score anomaly
        if threat_score > 0:
            threat_factor = self._score_threat_score(baseline, threat_score)
            factors.append(threat_factor)

        # Factor 5: Source tag anomaly
        if source_tag:
            source_factor = self._score_source_tag(baseline, source_tag)
            factors.append(source_factor)

        # Factor 6: Approval history (if tool was previously rejected)
        if tool_name:
            approval_factor = self._score_approval_history(baseline, tool_name)
            if approval_factor.score > 0:
                factors.append(approval_factor)

        # Combine factors with weighted average
        total_weight = sum(f.weight for f in factors)
        if total_weight > 0:
            combined_score = sum(f.score * f.weight for f in factors) / total_weight
        else:
            combined_score = 0.0

        return AnomalyScore(
            score=combined_score,
            has_baseline=True,
            factors=factors,
            is_anomalous=combined_score >= self.anomaly_threshold,
            anomaly_threshold=self.anomaly_threshold,
        )

    def _score_tool_frequency(
        self,
        baseline: AgentProfile,
        tool_name: str,
    ) -> AnomalyFactor:
        """Score tool usage frequency anomaly.

        Args:
            baseline: Agent's baseline profile
            tool_name: Tool being used

        Returns:
            AnomalyFactor for tool frequency
        """
        tool_freq = baseline.tool_frequencies.get(tool_name, 0)
        total_tools = sum(baseline.tool_frequencies.values())

        if tool_freq == 0:
            # Never used this tool before
            return AnomalyFactor(
                name="never_used_tool",
                score=0.8,
                description=f"Tool '{tool_name}' has never been used by this agent",
                weight=1.5,  # Higher weight - this is significant
            )

        # Calculate percentage of usage
        usage_pct = tool_freq / total_tools if total_tools > 0 else 0

        if usage_pct < 0.01:
            # Rarely used (less than 1%)
            return AnomalyFactor(
                name="rarely_used_tool",
                score=0.5,
                description=f"Tool '{tool_name}' is rarely used ({usage_pct:.1%} of actions)",
                weight=1.2,
            )
        elif usage_pct < 0.05:
            # Uncommon (less than 5%)
            return AnomalyFactor(
                name="uncommon_tool",
                score=0.3,
                description=f"Tool '{tool_name}' is uncommon ({usage_pct:.1%} of actions)",
                weight=1.0,
            )
        else:
            # Normal usage
            return AnomalyFactor(
                name="normal_tool",
                score=0.0,
                description=f"Tool '{tool_name}' is commonly used ({usage_pct:.1%} of actions)",
                weight=1.0,
            )

    def _score_time_of_day(
        self,
        baseline: AgentProfile,
        hour: int,
    ) -> AnomalyFactor:
        """Score time of day anomaly.

        Args:
            baseline: Agent's baseline profile
            hour: Current hour (0-23)

        Returns:
            AnomalyFactor for time of day
        """
        hour_freq = baseline.tool_hourly_distribution.get(hour, 0)
        total_activity = sum(baseline.tool_hourly_distribution.values())

        if hour_freq == 0:
            # Never active at this hour
            return AnomalyFactor(
                name="unusual_hour",
                score=0.4,
                description=f"Agent has never been active at hour {hour:02d}:00",
                weight=0.8,
            )

        # Calculate percentage
        hour_pct = hour_freq / total_activity if total_activity > 0 else 0

        if hour_pct < 0.02:
            # Very unusual hour
            return AnomalyFactor(
                name="rare_hour",
                score=0.3,
                description=f"Hour {hour:02d}:00 has very little activity ({hour_pct:.1%})",
                weight=0.7,
            )
        else:
            return AnomalyFactor(
                name="normal_hour",
                score=0.0,
                description=f"Hour {hour:02d}:00 is within normal activity pattern",
                weight=0.5,
            )

    def _score_risk_tier(
        self,
        baseline: AgentProfile,
        risk_tier: int,
    ) -> AnomalyFactor:
        """Score risk tier anomaly.

        Args:
            baseline: Agent's baseline profile
            risk_tier: Current risk tier (1-4)

        Returns:
            AnomalyFactor for risk tier
        """
        # Get typical risk tier
        typical_tier = self.baseline_mgr.get_typical_risk_tier(baseline.agent_id)

        tier_diff = risk_tier - typical_tier

        if tier_diff >= 2:
            # Much higher risk than usual
            return AnomalyFactor(
                name="much_higher_risk",
                score=0.7,
                description=f"Risk tier {risk_tier} is much higher than typical ({typical_tier})",
                weight=1.3,
            )
        elif tier_diff == 1:
            # Slightly higher risk
            return AnomalyFactor(
                name="higher_risk",
                score=0.4,
                description=f"Risk tier {risk_tier} is higher than typical ({typical_tier})",
                weight=1.0,
            )
        elif tier_diff == 0:
            # Normal risk
            return AnomalyFactor(
                name="normal_risk",
                score=0.0,
                description=f"Risk tier {risk_tier} matches typical pattern",
                weight=0.8,
            )
        else:
            # Lower risk than usual (not anomalous)
            return AnomalyFactor(
                name="lower_risk",
                score=0.0,
                description=f"Risk tier {risk_tier} is lower than typical ({typical_tier})",
                weight=0.5,
            )

    def _score_threat_score(
        self,
        baseline: AgentProfile,
        threat_score: float,
    ) -> AnomalyFactor:
        """Score threat score anomaly.

        Args:
            baseline: Agent's baseline profile
            threat_score: Current threat score

        Returns:
            AnomalyFactor for threat score
        """
        avg_threat = baseline.avg_threat_score

        if avg_threat == 0:
            # No baseline for threat scores
            if threat_score > 50:
                return AnomalyFactor(
                    name="high_threat_no_baseline",
                    score=0.6,
                    description=f"Threat score {threat_score:.0f} with no prior threat history",
                    weight=1.2,
                )
            return AnomalyFactor(
                name="normal_threat",
                score=0.0,
                description="Threat score is within expected range",
                weight=0.8,
            )

        # Calculate deviation from average
        deviation = threat_score - avg_threat

        if deviation > 30:
            return AnomalyFactor(
                name="high_threat_deviation",
                score=0.7,
                description=f"Threat score {threat_score:.0f} is much higher than average ({avg_threat:.0f})",
                weight=1.3,
            )
        elif deviation > 15:
            return AnomalyFactor(
                name="elevated_threat",
                score=0.4,
                description=f"Threat score {threat_score:.0f} is elevated from average ({avg_threat:.0f})",
                weight=1.0,
            )
        else:
            return AnomalyFactor(
                name="normal_threat",
                score=0.0,
                description=f"Threat score {threat_score:.0f} is within normal range",
                weight=0.8,
            )

    def _score_source_tag(
        self,
        baseline: AgentProfile,
        source_tag: str,
    ) -> AnomalyFactor:
        """Score source tag anomaly.

        Args:
            baseline: Agent's baseline profile
            source_tag: Current source tag

        Returns:
            AnomalyFactor for source tag
        """
        tag_freq = baseline.source_tag_distribution.get(source_tag, 0)
        total_tags = sum(baseline.source_tag_distribution.values())

        if tag_freq == 0:
            # Never seen this source tag
            return AnomalyFactor(
                name="new_source_type",
                score=0.4,
                description=f"Source tag '{source_tag}' is new for this agent",
                weight=0.9,
            )

        tag_pct = tag_freq / total_tags if total_tags > 0 else 0

        if tag_pct < 0.05:
            return AnomalyFactor(
                name="rare_source",
                score=0.3,
                description=f"Source tag '{source_tag}' is rare ({tag_pct:.1%})",
                weight=0.7,
            )
        else:
            return AnomalyFactor(
                name="normal_source",
                score=0.0,
                description=f"Source tag '{source_tag}' is common",
                weight=0.5,
            )

    def _score_approval_history(
        self,
        baseline: AgentProfile,
        tool_name: str,
    ) -> AnomalyFactor:
        """Score based on approval/rejection history for this tool.

        Args:
            baseline: Agent's baseline profile
            tool_name: Tool being used

        Returns:
            AnomalyFactor for approval history
        """
        rejected_count = baseline.commonly_rejected_tools.get(tool_name, 0)
        approved_count = baseline.commonly_approved_tools.get(tool_name, 0)

        if rejected_count > 0 and rejected_count > approved_count:
            # This tool has been rejected more than approved
            return AnomalyFactor(
                name="previously_rejected",
                score=0.6,
                description=f"Tool '{tool_name}' has been rejected {rejected_count} times previously",
                weight=1.4,
            )
        elif rejected_count > 0:
            # Some rejections but more approvals
            return AnomalyFactor(
                name="mixed_history",
                score=0.2,
                description=f"Tool '{tool_name}' has mixed approval history",
                weight=0.8,
            )
        else:
            return AnomalyFactor(
                name="no_rejection_history",
                score=0.0,
                description="No rejection history for this tool",
                weight=0.5,
            )

    def get_anomaly_summary(self, score: AnomalyScore) -> str:
        """Generate a human-readable summary of anomaly score.

        Args:
            score: AnomalyScore to summarize

        Returns:
            Summary string
        """
        if not score.has_baseline:
            return "No baseline available for anomaly detection"

        if not score.is_anomalous:
            return f"Action appears normal (score: {score.score:.2f})"

        # Get top contributing factors
        top_factors = sorted(
            score.factors,
            key=lambda f: f.score * f.weight,
            reverse=True,
        )[:3]

        factor_descriptions = [f.description for f in top_factors if f.score > 0]

        if factor_descriptions:
            return (
                f"Anomaly detected (score: {score.score:.2f}, {score.severity}). "
                f"Factors: {'; '.join(factor_descriptions)}"
            )
        else:
            return f"Anomaly detected (score: {score.score:.2f}, {score.severity})"
