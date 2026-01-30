"""Adaptive filtering strictness for Theron proxy.

Automatically adjusts how strictly Theron filters requests when security events
are detected. All levels auto-recover - no manual intervention ever required.

Key principles:
1. Theron is a proxy - it can't control agents, only filter their requests
2. Per-action blocking is the primary defense (in gating.py)
3. This module adds *extra* scrutiny after suspicious activity
4. User should never need to do anything - everything auto-recovers
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Optional
from uuid import uuid4


class DegradationLevel(IntEnum):
    """Filtering strictness levels.

    Note: These control how strict Theron's filtering is, not the agent's autonomy.
    Theron is a proxy - it can't control agents, only filter their requests.
    All levels auto-recover over time. No manual intervention required.
    """

    NORMAL = 0        # Standard policy matrix applies
    CAUTIOUS = 1      # Extra logging, lower thresholds for sandboxing
    RESTRICTED = 2    # Sandbox all Tier 3-4 tools regardless of source


@dataclass
class DegradationEvent:
    """An event that triggered degradation."""

    event_id: str
    event_type: str  # anomaly, violation, honeypot, exfiltration, hijack
    severity: str    # low, medium, high, critical
    description: str
    timestamp: datetime
    impact_score: float  # How much this event affects degradation (0-1)


@dataclass
class DegradationState:
    """Current degradation state for an agent or request."""

    state_id: str
    agent_id: Optional[str]
    request_id: Optional[str]

    # Current level
    level: DegradationLevel
    level_changed_at: datetime

    # Events that led to current state
    triggering_events: list[DegradationEvent] = field(default_factory=list)

    # Accumulated risk that determines level
    accumulated_risk: float = 0.0

    # Auto-recovery tracking
    last_escalation: Optional[datetime] = None
    last_recovery: Optional[datetime] = None
    recovery_blocked_until: Optional[datetime] = None


# Level thresholds based on accumulated risk
LEVEL_THRESHOLDS = {
    DegradationLevel.NORMAL: 0.0,
    DegradationLevel.CAUTIOUS: 0.3,
    DegradationLevel.RESTRICTED: 0.6,
}

# Tool restrictions per level
LEVEL_RESTRICTIONS = {
    DegradationLevel.NORMAL: {
        "allowed_tiers": [1, 2, 3, 4],
        "shadow_required": False,
        "logging_level": "normal",
    },
    DegradationLevel.CAUTIOUS: {
        "allowed_tiers": [1, 2, 3, 4],
        "shadow_required": False,
        "logging_level": "verbose",
        "sandbox_threshold_reduction": 0.2,  # Lower threshold for sandboxing
    },
    DegradationLevel.RESTRICTED: {
        "allowed_tiers": [1, 2, 3, 4],
        "shadow_required_tiers": [3, 4],
        "logging_level": "verbose",
        "sandbox_all_tier_3_4": True,  # Sandbox all high-risk tools
    },
}

# Impact scores for different event types
EVENT_IMPACT = {
    # Critical events - immediate escalation
    "honeypot_triggered": 0.9,
    "exfiltration_detected": 0.8,
    "backdoor_detected": 0.9,

    # High severity events
    "hijack_detected": 0.5,
    "permission_violation": 0.4,
    "shadow_discarded": 0.3,

    # Medium events - accumulate over time
    "anomaly_high": 0.3,
    "unusual_tool": 0.15,
    "permission_warning": 0.1,

    # Low events - minor impact
    "anomaly_medium": 0.1,
    "anomaly_low": 0.05,
}

# Recovery rates (risk reduction per minute without incidents)
# All levels auto-recover - no manual intervention ever required
RECOVERY_RATES = {
    DegradationLevel.CAUTIOUS: 0.03,     # ~10 min to recover to NORMAL
    DegradationLevel.RESTRICTED: 0.02,   # ~20 min to recover to CAUTIOUS
}


class DegradationManager:
    """Manages graceful degradation for autonomous agents."""

    def __init__(
        self,
        db=None,
        enable_auto_recovery: bool = True,
        recovery_cooldown_minutes: int = 5,
    ):
        """Initialize the degradation manager.

        Args:
            db: Optional database for persistence
            enable_auto_recovery: Whether to automatically recover from degradation
            recovery_cooldown_minutes: Minutes to wait before attempting recovery
        """
        self.db = db
        self.enable_auto_recovery = enable_auto_recovery
        self.recovery_cooldown = timedelta(minutes=recovery_cooldown_minutes)

        # State per agent/request
        self._states: dict[str, DegradationState] = {}

        # Global state (affects all agents)
        self._global_level: DegradationLevel = DegradationLevel.NORMAL
        self._global_events: list[DegradationEvent] = []

    def get_state(self, agent_id: Optional[str] = None, request_id: Optional[str] = None) -> DegradationState:
        """Get or create degradation state for an agent or request."""
        key = agent_id or request_id or "global"

        if key not in self._states:
            self._states[key] = DegradationState(
                state_id=str(uuid4()),
                agent_id=agent_id,
                request_id=request_id,
                level=DegradationLevel.NORMAL,
                level_changed_at=datetime.utcnow(),
            )

        return self._states[key]

    def record_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> DegradationEvent:
        """Record a security event and update degradation level.

        Args:
            event_type: Type of event (from EVENT_IMPACT keys)
            severity: Severity level
            description: Human-readable description
            agent_id: Agent that triggered the event
            request_id: Request that triggered the event

        Returns:
            Created DegradationEvent
        """
        # Calculate impact score
        base_impact = EVENT_IMPACT.get(event_type, 0.2)

        # Adjust by severity
        severity_multipliers = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.7,
        }
        impact = base_impact * severity_multipliers.get(severity, 1.0)

        event = DegradationEvent(
            event_id=str(uuid4()),
            event_type=event_type,
            severity=severity,
            description=description,
            timestamp=datetime.utcnow(),
            impact_score=impact,
        )

        # Update state
        state = self.get_state(agent_id, request_id)
        state.triggering_events.append(event)
        state.accumulated_risk = min(1.0, state.accumulated_risk + impact)

        # Recalculate level
        self._update_level(state)

        return event

    def _update_level(self, state: DegradationState) -> None:
        """Update degradation level based on accumulated risk."""
        old_level = state.level

        # Find appropriate level
        new_level = DegradationLevel.NORMAL
        for level in sorted(LEVEL_THRESHOLDS.keys(), key=lambda x: LEVEL_THRESHOLDS[x], reverse=True):
            if state.accumulated_risk >= LEVEL_THRESHOLDS[level]:
                new_level = level
                break

        if new_level != old_level:
            state.level = new_level
            state.level_changed_at = datetime.utcnow()

            if new_level > old_level:
                state.last_escalation = datetime.utcnow()
                # Block recovery for cooldown period after escalation
                state.recovery_blocked_until = datetime.utcnow() + self.recovery_cooldown
            else:
                state.last_recovery = datetime.utcnow()

    def attempt_recovery(
        self,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> bool:
        """Attempt to recover (reduce) degradation level.

        Should be called periodically when agent is operating normally.

        Args:
            agent_id: Agent identifier
            request_id: Request identifier

        Returns:
            True if level was reduced
        """
        if not self.enable_auto_recovery:
            return False

        state = self.get_state(agent_id, request_id)

        # Check if recovery is blocked
        if state.recovery_blocked_until and datetime.utcnow() < state.recovery_blocked_until:
            return False

        # Already at NORMAL - nothing to recover
        if state.level == DegradationLevel.NORMAL:
            return False

        # Apply recovery rate - all levels auto-recover
        recovery_rate = RECOVERY_RATES.get(state.level, 0.02)
        state.accumulated_risk = max(0.0, state.accumulated_risk - recovery_rate)
        old_level = state.level
        self._update_level(state)
        return state.level < old_level

    def get_restrictions(
        self,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> dict:
        """Get current restrictions based on degradation level.

        Args:
            agent_id: Agent identifier
            request_id: Request identifier

        Returns:
            Restriction dictionary for the current level
        """
        state = self.get_state(agent_id, request_id)

        # Combine agent/request state with global state
        effective_level = max(state.level, self._global_level)

        return LEVEL_RESTRICTIONS.get(effective_level, LEVEL_RESTRICTIONS[DegradationLevel.NORMAL])

    def is_tool_allowed(
        self,
        tool_name: str,
        risk_tier: int,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Check if a tool is allowed under current filtering level.

        Note: All tools are always allowed. This method now only returns
        whether additional scrutiny (sandboxing) is recommended.

        Args:
            tool_name: Tool being called
            risk_tier: Risk tier of the tool
            agent_id: Agent identifier
            request_id: Request identifier

        Returns:
            Tuple of (is_allowed, reason) - always (True, ...) now
        """
        # All tools are always allowed - we never fully block
        # The per-action blocking in gating.py handles dangerous actions
        return True, "Tool allowed"

    def requires_shadow_execution(
        self,
        risk_tier: int,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> bool:
        """Check if shadow execution is required for this tool.

        Args:
            risk_tier: Risk tier of the tool
            agent_id: Agent identifier
            request_id: Request identifier

        Returns:
            True if shadow execution required
        """
        restrictions = self.get_restrictions(agent_id, request_id)

        # Global shadow requirement
        if restrictions.get("shadow_required"):
            return True

        # Tier-specific shadow requirement
        shadow_tiers = restrictions.get("shadow_required_tiers", [])
        if risk_tier in shadow_tiers:
            return True

        return False

    def force_level(
        self,
        level: DegradationLevel,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
        reason: str = "Manual override",
    ) -> None:
        """Force a specific degradation level.

        Args:
            level: Level to force
            agent_id: Agent identifier
            request_id: Request identifier
            reason: Reason for forcing
        """
        state = self.get_state(agent_id, request_id)

        # Set accumulated risk to match the level
        state.accumulated_risk = LEVEL_THRESHOLDS[level]
        state.level = level
        state.level_changed_at = datetime.utcnow()

        # Add event for audit
        state.triggering_events.append(DegradationEvent(
            event_id=str(uuid4()),
            event_type="manual_override",
            severity="medium",
            description=f"Level forced to {level.name}: {reason}",
            timestamp=datetime.utcnow(),
            impact_score=0.0,
        ))

    def get_status_summary(
        self,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> dict:
        """Get summary of current degradation status.

        Args:
            agent_id: Agent identifier
            request_id: Request identifier

        Returns:
            Status summary dictionary
        """
        state = self.get_state(agent_id, request_id)
        restrictions = self.get_restrictions(agent_id, request_id)

        return {
            "level": state.level.name,
            "level_value": state.level.value,
            "accumulated_risk": round(state.accumulated_risk, 3),
            "event_count": len(state.triggering_events),
            "level_changed_at": state.level_changed_at.isoformat(),
            "recovery_blocked": (
                state.recovery_blocked_until is not None and
                datetime.utcnow() < state.recovery_blocked_until
            ),
            "restrictions": {
                "allowed_tiers": restrictions.get("allowed_tiers", [1, 2, 3, 4]),
                "shadow_required": restrictions.get("shadow_required", False),
                "sandbox_tier_3_4": restrictions.get("sandbox_all_tier_3_4", False),
            },
            "recent_events": [
                {
                    "type": e.event_type,
                    "severity": e.severity,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in state.triggering_events[-5:]
            ],
        }

    def get_all_degraded_agents(self) -> list[dict]:
        """Get list of all agents with degraded autonomy."""
        degraded = []

        for key, state in self._states.items():
            if state.level > DegradationLevel.NORMAL:
                degraded.append({
                    "agent_id": state.agent_id,
                    "request_id": state.request_id,
                    "level": state.level.name,
                    "accumulated_risk": state.accumulated_risk,
                    "event_count": len(state.triggering_events),
                })

        return degraded

    def clear_request(self, request_id: str) -> None:
        """Clear state for a completed request."""
        if request_id in self._states:
            del self._states[request_id]


# Global degradation manager instance
_degradation_manager: Optional[DegradationManager] = None


def get_degradation_manager(db=None) -> DegradationManager:
    """Get the global degradation manager instance."""
    global _degradation_manager
    if _degradation_manager is None:
        _degradation_manager = DegradationManager(db)
    return _degradation_manager


def reset_degradation_manager() -> None:
    """Reset the global degradation manager."""
    global _degradation_manager
    _degradation_manager = None
