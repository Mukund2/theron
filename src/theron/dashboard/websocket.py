"""WebSocket utilities for Theron dashboard."""

import asyncio
import json
from typing import Any, Callable, Optional

from fastapi import WebSocket

from .api import manager


class EventBroadcaster:
    """Utility class for broadcasting events to WebSocket clients."""

    _instance: Optional["EventBroadcaster"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def broadcast_new_event(self, event: dict[str, Any]) -> None:
        """Broadcast a new event to all connected clients."""
        message = {
            "type": "new_event",
            "data": self._serialize_event(event),
        }
        await manager.broadcast(message)

    async def broadcast_stats_update(self, stats: dict[str, Any]) -> None:
        """Broadcast updated statistics to all connected clients."""
        message = {
            "type": "stats_update",
            "data": stats,
        }
        await manager.broadcast(message)

    async def broadcast_alert(
        self, level: str, message: str, details: Optional[dict] = None
    ) -> None:
        """Broadcast an alert to all connected clients."""
        alert = {
            "type": "alert",
            "data": {
                "level": level,  # "info", "warning", "error", "critical"
                "message": message,
                "details": details or {},
            },
        }
        await manager.broadcast(alert)

    def _serialize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Serialize an event for JSON transmission."""
        serialized = {}
        for key, value in event.items():
            if hasattr(value, "isoformat"):
                serialized[key] = value.isoformat()
            elif hasattr(value, "value"):  # Enum
                serialized[key] = value.value
            else:
                serialized[key] = value
        return serialized


# Global broadcaster instance
broadcaster = EventBroadcaster()


async def notify_blocked_action(
    tool_name: str,
    risk_tier: int,
    source_tag: str,
    reason: str,
) -> None:
    """Send a notification when an action is blocked."""
    await broadcaster.broadcast_alert(
        level="warning",
        message=f"Blocked action: {tool_name}",
        details={
            "tool_name": tool_name,
            "risk_tier": risk_tier,
            "source_tag": source_tag,
            "reason": reason,
        },
    )


async def notify_injection_detected(
    threat_score: int,
    patterns: list[str],
    source_tag: str,
) -> None:
    """Send a notification when a prompt injection is detected."""
    await broadcaster.broadcast_alert(
        level="error" if threat_score >= 80 else "warning",
        message=f"Prompt injection detected (score: {threat_score})",
        details={
            "threat_score": threat_score,
            "patterns": patterns,
            "source_tag": source_tag,
        },
    )
