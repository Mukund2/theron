"""Graceful degradation for autonomous agents.

Automatically reduces agent autonomy levels when security events are detected.
This implements the AWS recommendation for agentic AI security without requiring
human intervention.

Key insight: When things look suspicious, automatically restrict what the agent
can do until the situation clarifies - better to be overly cautious than compromised.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Optional
from uuid import uuid4


class DegradationLevel(IntEnum):
    """Autonomy levels from full to minimal."""

    FULL = 0          # Normal operation - all tools available
    CAUTIOUS = 1      # Elevated logging, soft warnings
    RESTRICTED = 2    # Tier 3-4 tools require shadow execution
    MINIMAL = 3       # Only read operations allowed
    SUSPENDED = 4     # No tool execution - agent effectively paused


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
    DegradationLevel.FULL: 0.0,
    DegradationLevel.CAUTIOUS: 0.2,
    DegradationLevel.RESTRICTED: 0.4,
    DegradationLevel.MINIMAL: 0.7,
    DegradationLevel.SUSPENDED: 0.9,
}

# Tool restrictions per level
LEVEL_RESTRICTIONS = {
    DegradationLevel.FULL: {
        "allowed_tiers": [1, 2, 3, 4],
        "shadow_required": False,
        "logging_level": "normal",
    },
    DegradationLevel.CAUTIOUS: {
        "allowed_tiers": [1, 2, 3, 4],
        "shadow_required": False,
        "logging_level": "verbose",
        "warn_on_tier": 3,
    },
    DegradationLevel.RESTRICTED: {
        "allowed_tiers": [1, 2, 3, 4],
        "shadow_required_tiers": [3, 4],
        "logging_level": "verbose",
    },
    DegradationLevel.MINIMAL: {
        "allowed_tiers": [1, 2],
        "shadow_required": True,
        "logging_level": "verbose",
        "read_only": True,
    },
    DegradationLevel.SUSPENDED: {
        "allowed_tiers": [],
        "shadow_required": True,
        "logging_level": "verbose",
        "read_only": True,
        "all_blocked": True,
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
RECOVERY_RATES = {
    DegradationLevel.CAUTIOUS: 0.02,     # ~10 min to recover from CAUTIOUS
    DegradationLevel.RESTRICTED: 0.01,   # ~40 min to recover from RESTRICTED
    DegradationLevel.MINIMAL: 0.005,     # ~80 min to recover from MINIMAL
    DegradationLevel.SUSPENDED: 0.0,     # No auto-recovery from SUSPENDED
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
        self._global_level: DegradationLevel = DegradationLevel.FULL
        self._global_events: list[DegradationEvent] = []

    def get_state(self, agent_id: Optional[str] = None, request_id: Optional[str] = None) -> DegradationState:
        """Get or create degradation state for an agent or request."""
        key = agent_id or request_id or "global"

        if key not in self._states:
            self._states[key] = DegradationState(
                state_id=str(uuid4()),
                agent_id=agent_id,
                request_id=request_id,
                level=DegradationLevel.FULL,
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
        new_level = DegradationLevel.FULL
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

        # Can't recover from SUSPENDED automatically
        if state.level == DegradationLevel.SUSPENDED:
            return False

        # Can't recover if already at FULL
        if state.level == DegradationLevel.FULL:
            return False

        # Apply recovery rate
        recovery_rate = RECOVERY_RATES.get(state.level, 0.0)
        if recovery_rate > 0:
            state.accumulated_risk = max(0.0, state.accumulated_risk - recovery_rate)
            old_level = state.level
            self._update_level(state)
            return state.level < old_level

        return False

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

        return LEVEL_RESTRICTIONS.get(effective_level, LEVEL_RESTRICTIONS[DegradationLevel.FULL])

    def is_tool_allowed(
        self,
        tool_name: str,
        risk_tier: int,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Check if a tool is allowed under current degradation level.

        Args:
            tool_name: Tool being called
            risk_tier: Risk tier of the tool
            agent_id: Agent identifier
            request_id: Request identifier

        Returns:
            Tuple of (is_allowed, reason)
        """
        restrictions = self.get_restrictions(agent_id, request_id)

        # Check if all blocked
        if restrictions.get("all_blocked"):
            return False, "Agent is suspended - all tool execution blocked"

        # Check allowed tiers
        allowed_tiers = restrictions.get("allowed_tiers", [1, 2, 3, 4])
        if risk_tier not in allowed_tiers:
            return False, f"Tier {risk_tier} tools not allowed at current degradation level"

        # Check read-only mode
        if restrictions.get("read_only"):
            write_tools = ["write", "create", "delete", "remove", "modify", "update", "insert", "drop"]
            if any(w in tool_name.lower() for w in write_tools):
                return False, "Write operations blocked in minimal autonomy mode"

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

    def resume_from_suspended(
        self,
        agent_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Resume an agent from SUSPENDED state.

        This is the only way to recover from SUSPENDED.

        Args:
            agent_id: Agent identifier
            request_id: Request identifier
        """
        state = self.get_state(agent_id, request_id)

        if state.level == DegradationLevel.SUSPENDED:
            # Reset to RESTRICTED (still cautious after suspension)
            state.level = DegradationLevel.RESTRICTED
            state.accumulated_risk = LEVEL_THRESHOLDS[DegradationLevel.RESTRICTED]
            state.level_changed_at = datetime.utcnow()
            state.recovery_blocked_until = datetime.utcnow() + timedelta(minutes=30)

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
                "allowed_tiers": restrictions.get("allowed_tiers", []),
                "shadow_required": restrictions.get("shadow_required", False),
                "read_only": restrictions.get("read_only", False),
                "all_blocked": restrictions.get("all_blocked", False),
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
            if state.level > DegradationLevel.FULL:
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
