"""Behavioral baseline learning for Theron.

Learns what's "normal" for each agent over time to enable zero-config anomaly detection.
"""

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ..storage.models import AgentProfileCreate


@dataclass
class AgentProfile:
    """Behavioral profile for an agent."""

    agent_id: str
    created_at: datetime
    last_updated: datetime
    total_requests: int = 0

    # Tool usage statistics
    tool_frequencies: dict[str, int] = field(default_factory=dict)
    tool_hourly_distribution: dict[int, int] = field(default_factory=dict)
    avg_tools_per_request: float = 0.0

    # Risk patterns
    avg_threat_score: float = 0.0
    threat_score_sum: float = 0.0
    risk_tier_distribution: dict[int, int] = field(default_factory=dict)

    # Content patterns
    source_tag_distribution: dict[str, int] = field(default_factory=dict)
    avg_content_length: float = 0.0
    content_length_sum: int = 0

    # Approval patterns (learning from user feedback)
    sandbox_approval_count: int = 0
    sandbox_rejection_count: int = 0
    commonly_approved_tools: dict[str, int] = field(default_factory=dict)
    commonly_rejected_tools: dict[str, int] = field(default_factory=dict)

    # Recent activity window (last N requests)
    recent_tools: list[str] = field(default_factory=list)
    recent_hours: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert profile to dictionary for storage."""
        return {
            "agent_id": self.agent_id,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "last_updated": self.last_updated.isoformat() if isinstance(self.last_updated, datetime) else self.last_updated,
            "total_requests": self.total_requests,
            "tool_frequencies": self.tool_frequencies,
            "tool_hourly_distribution": {str(k): v for k, v in self.tool_hourly_distribution.items()},
            "avg_tools_per_request": self.avg_tools_per_request,
            "avg_threat_score": self.avg_threat_score,
            "threat_score_sum": self.threat_score_sum,
            "risk_tier_distribution": {str(k): v for k, v in self.risk_tier_distribution.items()},
            "source_tag_distribution": self.source_tag_distribution,
            "avg_content_length": self.avg_content_length,
            "content_length_sum": self.content_length_sum,
            "sandbox_approval_count": self.sandbox_approval_count,
            "sandbox_rejection_count": self.sandbox_rejection_count,
            "commonly_approved_tools": self.commonly_approved_tools,
            "commonly_rejected_tools": self.commonly_rejected_tools,
            "recent_tools": self.recent_tools[-100:],  # Keep last 100
            "recent_hours": self.recent_hours[-100:],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AgentProfile":
        """Create profile from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif not isinstance(created_at, datetime):
            created_at = datetime.utcnow()

        last_updated = data.get("last_updated")
        if isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated)
        elif not isinstance(last_updated, datetime):
            last_updated = datetime.utcnow()

        return cls(
            agent_id=data.get("agent_id", "unknown"),
            created_at=created_at,
            last_updated=last_updated,
            total_requests=data.get("total_requests", 0),
            tool_frequencies=data.get("tool_frequencies", {}),
            tool_hourly_distribution={int(k): v for k, v in data.get("tool_hourly_distribution", {}).items()},
            avg_tools_per_request=data.get("avg_tools_per_request", 0.0),
            avg_threat_score=data.get("avg_threat_score", 0.0),
            threat_score_sum=data.get("threat_score_sum", 0.0),
            risk_tier_distribution={int(k): v for k, v in data.get("risk_tier_distribution", {}).items()},
            source_tag_distribution=data.get("source_tag_distribution", {}),
            avg_content_length=data.get("avg_content_length", 0.0),
            content_length_sum=data.get("content_length_sum", 0),
            sandbox_approval_count=data.get("sandbox_approval_count", 0),
            sandbox_rejection_count=data.get("sandbox_rejection_count", 0),
            commonly_approved_tools=data.get("commonly_approved_tools", {}),
            commonly_rejected_tools=data.get("commonly_rejected_tools", {}),
            recent_tools=data.get("recent_tools", []),
            recent_hours=data.get("recent_hours", []),
        )

    @property
    def sandbox_approval_rate(self) -> float:
        """Calculate sandbox approval rate."""
        total = self.sandbox_approval_count + self.sandbox_rejection_count
        if total == 0:
            return 0.5  # Default to neutral
        return self.sandbox_approval_count / total


class BaselineManager:
    """Manages behavioral baselines for agents."""

    def __init__(self, db=None, min_requests_for_baseline: int = 25):
        """Initialize the baseline manager.

        Args:
            db: Optional database instance for persistence.
            min_requests_for_baseline: Minimum requests before baseline is considered reliable.
        """
        self.db = db
        self._min_requests_for_baseline = min_requests_for_baseline
        # In-memory cache of profiles
        self._profiles: dict[str, AgentProfile] = {}

    def _get_or_create_profile(self, agent_id: str) -> AgentProfile:
        """Get or create a profile for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            AgentProfile for the agent
        """
        if agent_id not in self._profiles:
            self._profiles[agent_id] = AgentProfile(
                agent_id=agent_id,
                created_at=datetime.utcnow(),
                last_updated=datetime.utcnow(),
            )
        return self._profiles[agent_id]

    def update_profile(
        self,
        agent_id: str,
        tool_name: Optional[str] = None,
        risk_tier: Optional[int] = None,
        threat_score: float = 0.0,
        source_tag: Optional[str] = None,
        content_length: int = 0,
    ) -> AgentProfile:
        """Update profile with new event data.

        Args:
            agent_id: Agent identifier
            tool_name: Name of tool used (if any)
            risk_tier: Risk tier of the tool (1-4)
            threat_score: Threat score from detection
            source_tag: Source tag of the request
            content_length: Length of content processed

        Returns:
            Updated AgentProfile
        """
        profile = self._get_or_create_profile(agent_id)
        profile.total_requests += 1
        profile.last_updated = datetime.utcnow()

        current_hour = datetime.utcnow().hour

        # Update tool frequencies
        if tool_name:
            profile.tool_frequencies[tool_name] = (
                profile.tool_frequencies.get(tool_name, 0) + 1
            )
            profile.recent_tools.append(tool_name)
            if len(profile.recent_tools) > 100:
                profile.recent_tools = profile.recent_tools[-100:]

        # Update hourly distribution
        profile.tool_hourly_distribution[current_hour] = (
            profile.tool_hourly_distribution.get(current_hour, 0) + 1
        )
        profile.recent_hours.append(current_hour)
        if len(profile.recent_hours) > 100:
            profile.recent_hours = profile.recent_hours[-100:]

        # Update threat score average
        profile.threat_score_sum += threat_score
        profile.avg_threat_score = profile.threat_score_sum / profile.total_requests

        # Update risk tier distribution
        if risk_tier is not None:
            profile.risk_tier_distribution[risk_tier] = (
                profile.risk_tier_distribution.get(risk_tier, 0) + 1
            )

        # Update source tag distribution
        if source_tag:
            profile.source_tag_distribution[source_tag] = (
                profile.source_tag_distribution.get(source_tag, 0) + 1
            )

        # Update content length average
        if content_length > 0:
            profile.content_length_sum += content_length
            profile.avg_content_length = profile.content_length_sum / profile.total_requests

        return profile

    def get_baseline(self, agent_id: str) -> Optional[AgentProfile]:
        """Get baseline if we have enough data.

        Args:
            agent_id: Agent identifier

        Returns:
            AgentProfile if enough data, None otherwise
        """
        profile = self._profiles.get(agent_id)
        if profile and profile.total_requests >= self._min_requests_for_baseline:
            return profile
        return None

    def has_baseline(self, agent_id: str) -> bool:
        """Check if an agent has a reliable baseline.

        Args:
            agent_id: Agent identifier

        Returns:
            True if baseline exists and is reliable
        """
        return self.get_baseline(agent_id) is not None

    def learn_from_approval(
        self,
        agent_id: str,
        tool_name: str,
        approved: bool,
    ) -> None:
        """Update profile based on user approval/rejection of sandbox.

        Args:
            agent_id: Agent identifier
            tool_name: Name of the tool that was sandboxed
            approved: Whether user approved the action
        """
        profile = self._get_or_create_profile(agent_id)

        if approved:
            profile.sandbox_approval_count += 1
            profile.commonly_approved_tools[tool_name] = (
                profile.commonly_approved_tools.get(tool_name, 0) + 1
            )
        else:
            profile.sandbox_rejection_count += 1
            profile.commonly_rejected_tools[tool_name] = (
                profile.commonly_rejected_tools.get(tool_name, 0) + 1
            )

    def get_typical_tools(self, agent_id: str, top_n: int = 10) -> list[tuple[str, int]]:
        """Get the most commonly used tools for an agent.

        Args:
            agent_id: Agent identifier
            top_n: Number of tools to return

        Returns:
            List of (tool_name, count) tuples
        """
        profile = self._profiles.get(agent_id)
        if not profile:
            return []

        sorted_tools = sorted(
            profile.tool_frequencies.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return sorted_tools[:top_n]

    def get_typical_hours(self, agent_id: str) -> list[int]:
        """Get typical hours of activity for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            List of hours (0-23) with activity
        """
        profile = self._profiles.get(agent_id)
        if not profile:
            return list(range(24))  # All hours if no baseline

        # Hours with activity
        active_hours = [h for h, c in profile.tool_hourly_distribution.items() if c > 0]
        return sorted(active_hours) if active_hours else list(range(24))

    def get_typical_risk_tier(self, agent_id: str) -> int:
        """Get the typical risk tier for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Most common risk tier (1-4), defaults to 2
        """
        profile = self._profiles.get(agent_id)
        if not profile or not profile.risk_tier_distribution:
            return 2  # Default to moderate

        return max(
            profile.risk_tier_distribution.keys(),
            key=lambda k: profile.risk_tier_distribution[k],
        )

    def get_profile_summary(self, agent_id: str) -> dict:
        """Get a summary of an agent's profile.

        Args:
            agent_id: Agent identifier

        Returns:
            Summary dictionary
        """
        profile = self._profiles.get(agent_id)
        if not profile:
            return {
                "exists": False,
                "has_baseline": False,
            }

        return {
            "exists": True,
            "has_baseline": profile.total_requests >= self._min_requests_for_baseline,
            "total_requests": profile.total_requests,
            "unique_tools": len(profile.tool_frequencies),
            "avg_threat_score": round(profile.avg_threat_score, 2),
            "typical_risk_tier": self.get_typical_risk_tier(agent_id),
            "sandbox_approval_rate": round(profile.sandbox_approval_rate, 2),
            "active_hours": len(self.get_typical_hours(agent_id)),
            "created_at": profile.created_at.isoformat() if isinstance(profile.created_at, datetime) else profile.created_at,
            "last_updated": profile.last_updated.isoformat() if isinstance(profile.last_updated, datetime) else profile.last_updated,
        }

    async def save_profile(self, agent_id: str) -> None:
        """Save profile to database.

        Args:
            agent_id: Agent to save
        """
        if not self.db:
            return

        profile = self._profiles.get(agent_id)
        if not profile:
            return

        profile_create = AgentProfileCreate(
            agent_id=agent_id,
            profile_data=profile.to_dict(),
        )

        await self.db.create_or_update_profile(profile_create)

    async def load_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Load profile from database.

        Args:
            agent_id: Agent to load

        Returns:
            AgentProfile if found
        """
        if not self.db:
            return None

        profile_db = await self.db.get_agent_profile(agent_id)
        if not profile_db:
            return None

        profile_data = json.loads(profile_db.profile_data)
        profile = AgentProfile.from_dict(profile_data)
        self._profiles[agent_id] = profile

        return profile

    async def create_snapshot(self, agent_id: str) -> Optional[str]:
        """Create a snapshot of current profile.

        Args:
            agent_id: Agent to snapshot

        Returns:
            Snapshot ID if created
        """
        if not self.db:
            return None

        profile = self._profiles.get(agent_id)
        if not profile:
            return None

        snapshot_id = str(uuid4())
        await self.db.create_profile_snapshot(
            snapshot_id=snapshot_id,
            agent_id=agent_id,
            profile_data=profile.to_dict(),
        )

        return snapshot_id

    def get_all_profiles(self) -> list[AgentProfile]:
        """Get all loaded profiles.

        Returns:
            List of all profiles
        """
        return list(self._profiles.values())
